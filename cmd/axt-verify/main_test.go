// Copyright 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/anthropics/axt-verify/internal/testlog"
	"github.com/anthropics/axt-verify/leaf"
)

const (
	orgUUID = "25f6429a-3293-49bf-afed-cb312911554b"
	origin  = "axt.anthropic.com/" + orgUUID
)

func served(i int, index *uint64) []byte {
	raw, _ := json.Marshal(map[string]any{
		"id": "activity_" + string(rune('a'+i)), "type": "anthropic_access",
		"created_at": "2026-08-01T00:00:00Z", "organization_id": "org_015gtSHLz269eTwgrH8NX5yk",
		"organization_uuid": "25f6429a-3293-49bf-afed-cb312911554b", "reason_code": "safety_review",
		"actor": map[string]any{"type": "anthropic_actor"}, leaf.IndexKey: index,
	})
	return raw
}

type fixture struct {
	dir    string
	srv    *testlog.Server
	events [][]byte
	// logKey is the fake log's verifier string, passed as --log-key.
	logKey string
}

func setup(t *testing.T) *fixture { return setupAt(t, origin) }

// setupAt builds the fixture against a log whose origin is whatever is asked
// for, so a test can tell "the key's name decides the origin" apart from "the
// fixture happens to use the default origin".
func setupAt(t *testing.T, logOrigin string) *fixture {
	t.Helper()
	l := testlog.New(logOrigin)
	srv := testlog.NewServer(l)
	t.Cleanup(srv.Close)
	httpClient = srv.Client()
	t.Cleanup(func() { httpClient = nil })
	f := &fixture{dir: t.TempDir(), srv: srv}
	for i := range 3 {
		idx := uint64(i)
		raw := served(i, &idx)
		ev, err := leaf.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		l.Append(ev.Entry)
		srv.Events = append(srv.Events, raw)
		f.events = append(f.events, raw)
	}
	srv.Publish()
	f.logKey = l.Key.VKey
	t.Setenv(apiKeyEnv, testlog.APIKey)
	// The API host is a constant in a release build. Tests reach the fake
	// through the same seam our own acceptance builds use — the package var
	// the internal build tag fills in — rather than an environment variable
	// a customer's binary would have to honour.
	pointAt(t, srv.HTTP.URL)
	return f
}

// pointAt aims this process's axt-verify at a URL for the duration of a test.
func pointAt(t *testing.T, url string) {
	t.Helper()
	prev := internalBaseURL
	internalBaseURL = url
	t.Cleanup(func() { internalBaseURL = prev })
}

func (f *fixture) run(t *testing.T, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = run(append([]string{
		"--org", orgUUID, "--log-key", f.logKey,
		"--state", filepath.Join(f.dir, "axt-verify.state"),
	}, args...), strings.NewReader(stdin), &out, &errb)
	t.Logf("axt-verify %s → exit %d\nstdout:\n%sstderr:\n%s", strings.Join(args, " "), code, out.String(), errb.String())
	return code, out.String(), errb.String()
}

func TestCLI_RunWritesStateAndExitCodes(t *testing.T) {
	f := setup(t)

	code, stdout, _ := f.run(t, "", "run")
	if code != exitOK || !strings.Contains(stdout, "3 verified") || !strings.Contains(stdout, "becomes the baseline") {
		t.Fatalf("first run: exit %d\n%s", code, stdout)
	}
	if _, err := os.Stat(filepath.Join(f.dir, "axt-verify.state")); err != nil {
		t.Fatalf("state file: %v", err)
	}
	code, stdout, _ = f.run(t, "", "run")
	if code != exitOK || !strings.Contains(stdout, "append-only: verified from tree size 3") {
		t.Fatalf("second run: exit %d\n%s", code, stdout)
	}

	code, stdout, _ = f.run(t, "", "--json", "checkpoint")
	var rep struct {
		OK         bool
		Checkpoint struct{ Size uint64 }
	}
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil || code != exitOK || !rep.OK || rep.Checkpoint.Size != 3 {
		t.Fatalf("--json checkpoint: exit %d rep=%+v err=%v\n%s", code, rep, err, stdout)
	}

	// Tampered feed → exit 1, and the failure names the event.
	f.srv.Events[1] = []byte(strings.Replace(string(f.events[1]), "safety_review", "incident_response", 1))
	_ = os.Remove(filepath.Join(f.dir, "axt-verify.state"))
	code, stdout, stderr := f.run(t, "", "run")
	if code != exitFailed || !strings.Contains(stdout, "FAILED activity_b (leaf index 1)") || !strings.Contains(stderr, "VERIFICATION FAILED") {
		t.Fatalf("tampered: exit %d", code)
	}

	// Rollback → exit 1 via the pass error.
	f.srv.Events[1] = f.events[1]
	f.run(t, "", "run")
	f.srv.Published = 2
	if code, _, stderr = f.run(t, "", "checkpoint"); code != exitFailed || !strings.Contains(stderr, "shrank") {
		t.Fatalf("rollback: exit %d", code)
	}
	f.srv.Publish()

	// A pass that verified nothing leaves no state behind: a mistaken
	// invocation (wrong --org → 404) must not pin its origin to disk.
	fresh := filepath.Join(t.TempDir(), "fresh.state")
	f.srv.FailNext = map[string][]int{"checkpoint": {404}}
	if code, _, _ = f.run(t, "", "--state", fresh, "checkpoint"); code != exitTransient {
		t.Fatalf("404 before anything verified: exit %d", code)
	}
	if _, err := os.Stat(fresh); !os.IsNotExist(err) {
		t.Fatal("a pass that verified nothing wrote a state file")
	}

	// Transport exhaustion → exit 3 (429s: the fake sends retry-after: 0).
	f.srv.FailNext = map[string][]int{"checkpoint": {429, 429, 429, 429, 429}}
	if code, _, _ = f.run(t, "", "checkpoint"); code != exitTransient {
		t.Fatalf("429s: exit %d", code)
	}

	// Usage/config → exit 2.
	t.Setenv(apiKeyEnv, "")
	if code, _, stderr = f.run(t, "", "run"); code != exitUsage || !strings.Contains(stderr, "no API key") {
		t.Fatalf("no key: exit %d", code)
	}
	t.Setenv(apiKeyEnv, testlog.APIKey)
	if code, _, _ = f.run(t, "", "bogus"); code != exitUsage {
		t.Fatalf("bogus command: exit %d", code)
	}
	// A misspelt flag fails loudly rather than being ignored.
	var errb bytes.Buffer
	if code := run([]string{"--org", orgUUID, "--mispelt", "1", "run"}, nil, &bytes.Buffer{}, &errb); code != exitUsage {
		t.Fatalf("unknown flag: exit %d: %s", code, errb.String())
	}
}

func TestCLI_EventsFromStdin(t *testing.T) {
	f := setup(t)
	shapes := map[string]string{
		"object": string(f.events[0]),
		"array":  "[" + string(f.events[0]) + "," + string(f.events[1]) + "]",
		"page":   `{"data":[` + string(f.events[2]) + `],"has_more":false}`,
		"jsonl":  string(f.events[0]) + "\n\n" + string(f.events[1]) + "\n" + string(f.events[2]) + "\n",
	}
	want := map[string]string{"object": "1 verified", "array": "2 verified", "page": "1 verified", "jsonl": "3 verified"}
	for name, in := range shapes {
		code, stdout, _ := f.run(t, in, "events", "-")
		if code != exitOK || !strings.Contains(stdout, want[name]) {
			t.Fatalf("%s: exit %d\n%s", name, code, stdout)
		}
	}
	// An event served without a leaf index is reported, not failed.
	if code, stdout, _ := f.run(t, string(served(9, nil)), "events", "-"); code != exitOK || !strings.Contains(stdout, "1 served without a leaf") {
		t.Fatalf("null index: exit %d\n%s", code, stdout)
	}
	// events never touches the state file.
	if _, err := os.Stat(filepath.Join(f.dir, "axt-verify.state")); !os.IsNotExist(err) {
		t.Fatalf("events wrote state: %v", err)
	}
}

// The FAILED lines are the tamper evidence; a served id must not be able to
// rewrite the terminal they are printed on.
func TestPrintable_EscapesServedControlCharacters(t *testing.T) {
	in := "activity_1\x1b[2K\x1b[Aoverwritten\x7f\u0085"
	got := printable(in)
	want := `activity_1\u001b[2K\u001b[Aoverwritten\u007f\u0085`
	if got != want {
		t.Fatalf("printable(%q) = %q, want %q", in, got, want)
	}
	if plain := "activity_1 (leaf index 3)"; printable(plain) != plain {
		t.Fatalf("printable rewrote an ordinary string: %q", printable(plain))
	}
	// A bidi override can reorder the FAILED line it sits on, and a raw
	// byte that is not UTF-8 must not print as an ordinary U+FFFD.
	if got, want := printable("a\u202eb"), `a\u202eb`; got != want {
		t.Fatalf("bidi override: printable = %q, want %q", got, want)
	}
	if got, want := printable("a\xffb"), `a\xffb`; got != want {
		t.Fatalf("invalid byte: printable = %q, want %q", got, want)
	}
	if s := "café 😀"; printable(s) != s {
		t.Fatalf("ordinary non-ASCII was escaped: %q", printable(s))
	}
}

// A served event may carry any key; one that also looks like a feed page
// must not be read as one, or its own content is never verified.
func TestCLI_AmbiguousEventInputRefused(t *testing.T) {
	f := setup(t)
	for _, in := range []string{
		`{"type":"anthropic_access","id":"activity_a","data":[]}`,
		`{"type":null,"id":"activity_a","data":[]}`,
		// No type at all, but still event-shaped: a page carries none of
		// these names.
		`{"id":"activity_a","organization_uuid":"25f6429a-3293-49bf-afed-cb312911554b","data":[]}`,
		// Names the leaf projects but the earlier guard did not list, and a
		// case variant leaf.Parse would refuse outright.
		`{"accessor_department":"T&S","data":[]}`,
		`{"Reason_Code":"csae_report","data":[]}`,
	} {
		code, _, stderr := f.run(t, in, "events", "-")
		if code != exitUsage || !strings.Contains(stderr, "neither clearly a feed page nor one event") {
			t.Fatalf("%s: exit %d\n%s", in, code, stderr)
		}
	}
	// A real page still reads as one.
	if code, _, _ := f.run(t, `{"data":[],"has_more":false,"last_id":null}`, "events", "-"); code == exitUsage {
		t.Fatal("a feed page was refused")
	}
}

// The same tampered bytes must get the same verdict however they are framed:
// a smuggled duplicate member is the verifier's refusal, not a usage error.
func TestCLI_TamperedEventExitsTheSameWhateverTheFraming(t *testing.T) {
	f := setup(t)
	// The tampered event also carries a field valued "data", which a byte
	// scan would mistake for a feed page.
	one := strings.Replace(string(f.events[0]), `"reason_code"`, `"accessor_department":"data","reason_code":"smuggled","reason_code"`, 1)
	for name, in := range map[string]string{
		"object": one,
		"array":  "[" + one + "]",
		"jsonl":  one + "\n",
	} {
		code, _, _ := f.run(t, in, "events", "-")
		if code != exitFailed {
			t.Fatalf("%s: exit %d, want %d", name, code, exitFailed)
		}
	}
}

func TestCLI_Version(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"version"}, nil, &out, &bytes.Buffer{}); code != 0 || !strings.HasPrefix(out.String(), "axt-verify ") {
		t.Fatalf("exit %d: %q", code, out.String())
	}
}

func TestResolveVersion(t *testing.T) {
	withMain := func(v string) *debug.BuildInfo {
		return &debug.BuildInfo{Main: debug.Module{Version: v}}
	}
	cases := map[string]struct {
		stamped string
		info    *debug.BuildInfo
		want    string
	}{
		"ldflags win":               {"v1.2.3", withMain("v9.9.9"), "v1.2.3"},
		"go install records module": {"dev", withMain("v1.2.3"), "v1.2.3"},
		"plain checkout is (devel)": {"dev", withMain("(devel)"), "dev"},
		"empty module version":      {"dev", withMain(""), "dev"},
		"no build info":             {"dev", nil, "dev"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := resolveVersion(c.stamped, c.info); got != c.want {
				t.Fatalf("resolveVersion(%q, …) = %q, want %q", c.stamped, got, c.want)
			}
		})
	}
}
