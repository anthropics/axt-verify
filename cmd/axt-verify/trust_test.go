// Copyright 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/anthropics/axt-verify"
	"github.com/anthropics/axt-verify/checkpoint"
	"github.com/anthropics/axt-verify/compliance"
)

// bare runs the command with only the arguments given: no --log-key, so the
// shipped key decides. The fixture's fake log signs with its own key, so such
// a run cannot verify — these tests check what the tool decided to trust, not
// what verified.
func (f *fixture) bare(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb strings.Builder
	// An explicit state path: the default is the working directory, which a
	// test must not write into.
	code := run(append([]string{"--state", filepath.Join(f.dir, "trust.state")}, args...),
		strings.NewReader(""), &out, &errb)
	t.Logf("axt-verify %s → exit %d\nstdout:\n%sstderr:\n%s", strings.Join(args, " "), code, out.String(), errb.String())
	return code, out.String(), errb.String()
}

// The common case asks nobody what to trust: the key ships with the release,
// and nothing is read from disk to decide it.
func TestCLI_BuiltinKeyDecidesTrust(t *testing.T) {
	f := setup(t)
	code, _, stderr := f.bare(t, "--org", orgUUID, "checkpoint")
	if code != exitFailed {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "using built-in log key") {
		t.Fatalf("the run did not say what it trusted:\n%s", stderr)
	}
	if !strings.Contains(stderr, "built-in key for "+axtverify.OriginPrefix) {
		t.Fatalf("the signature failure did not point at the shipped key:\n%s", stderr)
	}
}

// --log-key is the one override, and it must name this organization's log.
func TestCLI_LogKeyOverride(t *testing.T) {
	f := setup(t)
	if code, _, stderr := f.bare(t, "--org", orgUUID, "--log-key", f.logKey, "checkpoint"); code != exitOK {
		t.Fatalf("the fake log's own key was refused: exit %d\n%s", code, stderr)
	}
	// A key named for another origin would verify signatures from somewhere
	// else entirely.
	elsewhere := strings.Replace(f.logKey, origin, "axt.anthropic.com/00000000-0000-0000-0000-000000000000", 1)
	code, _, stderr := f.bare(t, "--org", orgUUID, "--log-key", elsewhere, "checkpoint")
	if code != exitUsage || !strings.Contains(stderr, "log-key") {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
}

// The override is readable from the environment, for a cron line that sets it
// once; an explicit flag still wins.
func TestCLI_LogKeyFromEnvironment(t *testing.T) {
	f := setup(t)
	t.Setenv(logKeyEnv, f.logKey)
	if code, _, stderr := f.bare(t, "--org", orgUUID, "checkpoint"); code != exitOK {
		t.Fatalf("the environment's key was not used: exit %d\n%s", code, stderr)
	}
	elsewhere := strings.Replace(f.logKey, origin, "axt.anthropic.com/00000000-0000-0000-0000-000000000000", 1)
	if code, _, _ := f.bare(t, "--org", orgUUID, "--log-key", elsewhere, "checkpoint"); code != exitUsage {
		t.Fatalf("the flag did not win over the environment: exit %d", code)
	}
}

// The tagged id is the one a customer has to hand; say which value to use.
func TestCLI_TaggedOrgIdIsRejectedWithAHint(t *testing.T) {
	f := setup(t)
	code, _, stderr := f.bare(t, "--org", "org_015gtSHLz269eTwgrH8NX5yk", "checkpoint")
	if code != exitUsage || !strings.Contains(stderr, "organization_uuid") {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
}

func TestCLI_OrgIsRequired(t *testing.T) {
	f := setup(t)
	if code, _, stderr := f.bare(t, "checkpoint"); code != exitUsage || !strings.Contains(stderr, "--org") {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
}

// The API base URL, wherever it comes from, must be a bare https origin:
// userinfo would carry the API key to another host, a path would double under
// every endpoint.
func TestCLI_APIBaseURLIsValidated(t *testing.T) {
	f := setup(t)
	for _, base := range []string{
		"http://insecure.example",
		"https://api.anthropic.com@elsewhere.example",
		"https://api.anthropic.com/v1",
		"https://api.anthropic.com?region=eu",
	} {
		pointAt(t, base)
		code, _, stderr := f.bare(t, "--org", orgUUID, "--log-key", f.logKey, "checkpoint")
		if code != exitUsage || !strings.Contains(stderr, "API base URL") {
			t.Fatalf("%s: exit %d\n%s", base, code, stderr)
		}
	}
}

// There is no --base-url flag to find.
func TestCLI_NoBaseURLFlag(t *testing.T) {
	f := setup(t)
	code, _, stderr := f.bare(t, "--org", orgUUID, "--base-url", "https://elsewhere.example", "checkpoint")
	if code != exitUsage || !strings.Contains(stderr, "not defined") {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
}

// A release build has one host. The environment variable our own acceptance
// builds read does not exist here: setting it changes nothing, and the
// resolved client still points at production.
func TestCLI_ReleaseBuildIgnoresTheHostEnvironmentVariable(t *testing.T) {
	f := setup(t)
	t.Setenv("AXT_VERIFY_API_BASE_URL", f.srv.HTTP.URL)
	pointAt(t, "") // what a release binary carries

	before := f.srv.Requests["checkpoint"]
	o := trustOptions{org: orgUUID, baseURL: internalBaseURL, logKey: f.logKey,
		stderr: io.Discard, logf: func(string, ...any) {}}
	_, client, _, err := o.resolve("sk-ant-test")
	if err != nil {
		t.Fatal(err)
	}
	if client.BaseURL != compliance.DefaultBaseURL {
		t.Fatalf("base URL %q, want %q", client.BaseURL, compliance.DefaultBaseURL)
	}
	if got := f.srv.Requests["checkpoint"] - before; got != 0 {
		t.Fatalf("%d requests reached the fake the environment variable named", got)
	}
}

// A supplied log key is announced on stderr even under --quiet: it can arrive
// from the environment, so a swapped key would otherwise change what a run
// trusts without leaving a trace in the log that run writes.
func TestCLI_SuppliedLogKeyIsAlwaysAnnounced(t *testing.T) {
	f := setup(t)
	_, _, stderr := f.bare(t, "--org", orgUUID, "--log-key", f.logKey, "--quiet", "checkpoint")
	if !strings.Contains(stderr, "verifying with a supplied log key") {
		t.Fatalf("--quiet hid which key was trusted:\n%s", stderr)
	}
	// The key hash is meaningful for every encoding, so it is always named.
	hash, ok := axtverify.KeyHash(f.logKey)
	if !ok || !strings.Contains(stderr, hash) {
		t.Fatalf("the announcement omits the key hash %q:\n%s", hash, stderr)
	}
	// The fake signs with the ECDSA encoding this log uses, whose payload is
	// the SPKI — so the published fingerprint is derivable and is printed.
	fp, derivable := axtverify.FingerprintOfVerifierKey(f.logKey)
	if !derivable || !strings.Contains(stderr, fp) {
		t.Fatalf("the announcement omits the fingerprint %q:\n%s", fp, stderr)
	}
}

// A filename that looks like a flag must not be able to replace the trust
// anchor this release ships: everything after "--" is positional.
// Go's flag package stops at the first "--" it meets, but this parser runs it
// once per positional, so without an explicit split a flag-shaped argument in
// the SECOND position after the terminator would be parsed as a flag on a
// later round. That is the case a glob produces, and the one this covers.
func TestParseCommandArgs_TerminatorHoldsForEveryArgument(t *testing.T) {
	var errb strings.Builder
	fs := newFlagSet(&errb)
	quiet := fs.Bool("quiet", false, "")
	logKey := fs.String("log-key", "", "")

	cmd, rest, code := parseCommandArgs(fs, []string{"events", "--", "a.json", "--quiet", "--log-key=elsewhere"})
	if code != exitOK || cmd != "events" {
		t.Fatalf("cmd=%q code=%d", cmd, code)
	}
	want := []string{"a.json", "--quiet", "--log-key=elsewhere"}
	if len(rest) != len(want) {
		t.Fatalf("positionals %q, want %q", rest, want)
	}
	for i := range want {
		if rest[i] != want[i] {
			t.Fatalf("positionals %q, want %q", rest, want)
		}
	}
	if *quiet || *logKey != "" {
		t.Fatalf("a flag after the terminator took effect: quiet=%v log-key=%q", *quiet, *logKey)
	}
}

func TestCLI_TerminatorProtectsFlagShapedFilenames(t *testing.T) {
	f := setup(t)
	var out, errb strings.Builder
	// A filename that spells a flag, arriving from a glob or a wrapper.
	const flagShaped = "--log-key=elsewhere.example/x+00000000+AAAA"
	code := run([]string{"--org", orgUUID, "--log-key", f.logKey,
		"--state", filepath.Join(f.dir, "t.state"), "events", "--", flagShaped},
		strings.NewReader(""), &out, &errb)
	if code != exitUsage {
		t.Fatalf("exit %d\n%s", code, errb.String())
	}
	// It has to fail as a file this tool could not read — not as a flag it
	// parsed. If the terminator stopped working, the argument would reach the
	// flag set and the message would be about the key's name instead.
	if !strings.Contains(errb.String(), flagShaped) || !strings.Contains(errb.String(), "no such file") {
		t.Fatalf("the argument was not read as a filename:\n%s", errb.String())
	}
	if strings.Contains(errb.String(), "must be named") {
		t.Fatalf("the argument reached the flag set:\n%s", errb.String())
	}
}

// The escaping has to be injective, or a served string that spells out an
// escape sequence is indistinguishable from one that carries it, and the
// forwardable evidence becomes ambiguous.
func TestPrintable_IsInjective(t *testing.T) {
	withByte := printable("a\x1b[2Kb")
	spelledOut := printable("a" + string(rune(0x5c)) + "u001b[2Kb")
	if withByte == spelledOut {
		t.Fatalf("two different served strings render identically: %q", withByte)
	}
}

// An empty subcommand — an unset shell variable, usually — must not be read
// as "no command" and exit 0 having verified nothing.
func TestCLI_EmptyCommandIsAUsageError(t *testing.T) {
	f := setup(t)
	var out, errb strings.Builder
	code := run([]string{"--org", orgUUID, "--log-key", f.logKey, ""},
		strings.NewReader(""), &out, &errb)
	if code != exitUsage {
		t.Fatalf("exit %d (stdout %q)", code, out.String())
	}
}

// --quiet means quiet, including the line naming the shipped key: a cron line
// that treats any stderr output as an alert would otherwise fire every run.
func TestCLI_QuietSilencesTheBuiltinKeyLine(t *testing.T) {
	f := setup(t)
	code, _, stderr := f.bare(t, "--org", orgUUID, "--quiet", "checkpoint")
	if strings.Contains(stderr, "using built-in log key") {
		t.Fatalf("--quiet still announced the key:\n%s", stderr)
	}
	if code != exitFailed {
		t.Fatalf("exit %d", code) // the fake log signs with its own key
	}
}

// A second command word must not be dropped on the floor: running only the
// first and reporting "verified" is an answer to a question nobody asked.
func TestCLI_ExtraArgumentIsAUsageError(t *testing.T) {
	f := setup(t)
	var out, errb strings.Builder
	code := run([]string{"--org", orgUUID, "--log-key", f.logKey, "checkpoint", "run"},
		strings.NewReader(""), &out, &errb)
	if code != exitUsage {
		t.Fatalf("exit %d\n%s", code, errb.String())
	}
}

// The override's own name is the origin: a note verifier is named for the log
// it verifies, so the two cannot disagree. It must still be this
// organization's log.
func TestCLI_LogKeyNameSetsTheOrigin(t *testing.T) {
	// A log that is deliberately NOT at the default origin, so the assertions
	// below fail if the origin stops coming from the key's name.
	const otherOrigin = "other.example/" + orgUUID
	f := setupAt(t, otherOrigin)

	// (i) the key named for that log verifies its checkpoints.
	if code, _, stderr := f.bare(t, "--org", orgUUID, "--log-key", f.logKey, "checkpoint"); code != exitOK {
		t.Fatalf("a key named %s was refused: exit %d\n%s", otherOrigin, code, stderr)
	}
	// (ii) with no override the policy is the production origin, which this
	// log's checkpoints do not carry — so the same bytes are refused. Its own
	// state file, or the origin guard on the one (i) wrote would answer first.
	code, _, stderr := f.bare(t, "--org", orgUUID, "--state", filepath.Join(t.TempDir(), "default.state"), "checkpoint")
	if code != exitFailed {
		t.Fatalf("the default origin accepted a checkpoint from %s: exit %d\n%s", otherOrigin, code, stderr)
	}

	// A key naming another organization is refused before anything is fetched.
	elsewhere := strings.Replace(f.logKey, otherOrigin, axtverify.Origin("00000000-0000-0000-0000-000000000000"), 1)
	if code, _, stderr := f.bare(t, "--org", orgUUID, "--log-key", elsewhere, "checkpoint"); code != exitUsage ||
		!strings.Contains(stderr, "must be named <prefix>/<org>") {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	// So is something that is not a note-verifier key at all.
	if code, _, stderr := f.bare(t, "--org", orgUUID, "--log-key", "not-a-key", "checkpoint"); code != exitUsage {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
}

// A signature failure is only actionable if the operator can compare what
// the log signed with against what this release trusts: the published key
// table turns that pair into "upgrade" or "escalate".
func TestCLI_SignatureFailureShowsBothKeyHashes(t *testing.T) {
	f := setup(t)
	code, _, stderr := f.bare(t, "--org", orgUUID, "checkpoint")
	if code != exitFailed {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	for _, want := range []string{"signatures on the served checkpoint:", "key this run trusts:", "(built-in)"} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr does not carry %q:\n%s", want, stderr)
		}
	}
	hashes := regexp.MustCompile(`key hash ([0-9a-f]{8})`).FindAllStringSubmatch(stderr, -1)
	if len(hashes) != 2 || hashes[0][1] == hashes[1][1] {
		t.Fatalf("want the served and the trusted hash, and they must differ:\n%s", stderr)
	}
	// The hint stays after the comparison, not instead of it.
	if !strings.Contains(stderr, "upgrade axt-verify") {
		t.Fatalf("the rotation hint is gone:\n%s", stderr)
	}
}

// The names come off a note that failed verification, so they are whatever
// the log chose to send.
func TestSignatureReportEscapesTheNamesItPrints(t *testing.T) {
	sig := make([]byte, 4+64)
	sig[3] = 7
	note := "body\n\n— evil\x1b[31mname " + base64.StdEncoding.EncodeToString(sig) + "\n"
	err := fmt.Errorf("verifying: %w", &checkpoint.SignatureError{Err: checkpoint.ErrSignature, Note: []byte(note)})

	var b strings.Builder
	printSignatures(&b, err, &checkpoint.Signature{Name: "axt.anthropic.com/x", KeyHash: "1dff5fe4", OK: true}, true)
	if strings.ContainsRune(b.String(), 0x1b) {
		t.Fatalf("an escape sequence reached the terminal:\n%q", b.String())
	}
	if !strings.Contains(b.String(), "key hash 00000007") {
		t.Fatalf("the served key hash is missing:\n%s", b.String())
	}
}

// A note whose signature block cannot be read must still report the key the
// run trusts — that half of the comparison never depends on the log.
func TestSignatureReportWithoutAReadableNote(t *testing.T) {
	var b strings.Builder
	printSignatures(&b, errors.New("some other failure"), &checkpoint.Signature{Name: "axt.anthropic.com/x", KeyHash: "1dff5fe4", OK: true}, false)
	if strings.Contains(b.String(), "signatures on the served checkpoint") {
		t.Fatalf("reported signatures it never read:\n%s", b.String())
	}
	if !strings.Contains(b.String(), "(supplied via --log-key)") {
		t.Fatalf("did not say where the trusted key came from:\n%s", b.String())
	}
}

// Every consumer takes these names from servedSignatures, so that is where
// they are made safe: the JSON report's own escaping is reversible, and a
// name left raw there comes back as live terminal sequences under `jq -r`.
func TestServedSignaturesEscapesTheNamesItReturns(t *testing.T) {
	sig := make([]byte, 4+64)
	sig[3] = 9
	note := "body\n\n— evil\x1b[31mname " + base64.StdEncoding.EncodeToString(sig) + "\n"
	got := servedSignatures(fmt.Errorf("verifying: %w", &checkpoint.SignatureError{Err: checkpoint.ErrSignature, Note: []byte(note)}))
	if len(got) != 1 || got[0].KeyHash != "00000009" {
		t.Fatalf("got %+v", got)
	}
	if strings.ContainsRune(got[0].Name, 0x1b) {
		t.Fatalf("name carries an escape sequence: %q", got[0].Name)
	}
}
