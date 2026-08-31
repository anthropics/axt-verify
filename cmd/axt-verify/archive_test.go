// Copyright 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anthropics/axt-verify/checkpoint"
	"github.com/anthropics/axt-verify/internal/testlog"
)

// The archival cron: hand back yesterday's checkpoint, keep today's.
func TestCLI_FromAndSave(t *testing.T) {
	f := setup(t)
	dir := t.TempDir()
	yesterday := filepath.Join(dir, "yesterday.ckpt")

	if code, _, stderr := f.run(t, "", "checkpoint", "--save", yesterday); code != exitOK {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	saved, err := os.ReadFile(yesterday)
	if err != nil {
		t.Fatal(err)
	}
	// Verbatim: what was saved must be a note the verifier accepts on its
	// own, committing to the tree the pass verified. (Re-signing here would
	// produce different bytes — ECDSA signatures are randomized — so the
	// check is that the saved note itself verifies.)
	cpv, err := checkpoint.New(checkpoint.Policy{Origin: origin, LogKey: f.logKey})
	if err != nil {
		t.Fatal(err)
	}
	cp, err := cpv.Verify(saved)
	if err != nil {
		t.Fatalf("--save wrote a note that does not verify: %v\n%s", err, saved)
	}
	if cp.Size != f.srv.Log.Size() {
		t.Fatalf("saved tree size %d, log is at %d", cp.Size, f.srv.Log.Size())
	}
	if !bytes.HasSuffix(saved, []byte("\n")) {
		t.Fatal("the saved note lost its trailing newline")
	}

	f.srv.Log.Append([]byte(`{"more":"events"}`))
	f.srv.Publish()
	today := filepath.Join(dir, "today.ckpt")
	if code, _, stderr := f.run(t, "", "checkpoint", "--from", yesterday, "--save", today); code != exitOK {
		t.Fatalf("--from an honest archive: exit %d\n%s", code, stderr)
	}
	if _, err := os.Stat(today); err != nil {
		t.Fatalf("nothing saved: %v", err)
	}
}

// A baseline the log cannot extend is the alarm, and the alarm has to be
// forwardable: both notes in the output.
func TestCLI_FromForkedArchivePrintsBothNotes(t *testing.T) {
	f := setup(t)
	forked := testlog.New(origin)
	forked.Key = f.srv.Log.Key
	forked.Append([]byte(`{"a":1}`), []byte(`{"b":2}`))
	path := filepath.Join(t.TempDir(), "forked.ckpt")
	if err := os.WriteFile(path, forked.Checkpoint(forked.Size()), 0o600); err != nil {
		t.Fatal(err)
	}

	code, _, stderr := f.run(t, "", "checkpoint", "--from", path)
	if code != exitFailed {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	for _, want := range []string{"log inconsistency", "older checkpoint", "newer checkpoint", origin} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("the report is missing %q:\n%s", want, stderr)
		}
	}
}

// Nothing is archived from a pass that did not verify.
func TestCLI_SaveWritesNothingOnFailure(t *testing.T) {
	f := setup(t)
	other := testlog.New(origin)
	f.logKey = other.Key.VKey
	path := filepath.Join(t.TempDir(), "never.ckpt")
	if code, _, _ := f.run(t, "", "checkpoint", "--save", path); code != exitFailed {
		t.Fatalf("exit %d", code)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("a checkpoint was archived from a pass that failed")
	}
}

// A --save that cannot be written is exit 3, but the pass verified and the
// state advanced, so the report and the JSON line are still owed.
func TestCLI_SaveFailureStillReports(t *testing.T) {
	f := setup(t)
	unwritable := filepath.Join(t.TempDir(), "no-such-dir", "today.ckpt")
	code, stdout, stderr := f.run(t, "", "checkpoint", "--json", "--save", unwritable)
	if code != exitTransient {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	if !strings.Contains(stdout, `"ok":true`) || !strings.Contains(stdout, "saving the checkpoint") {
		t.Fatalf("no JSON line for a pass that verified:\n%s", stdout)
	}
	if _, err := os.Stat(filepath.Join(f.dir, "axt-verify.state")); err != nil {
		t.Fatalf("state was not saved: %v", err)
	}
}

func TestCLI_PrevPairValidation(t *testing.T) {
	f := setup(t)
	if code, _, stderr := f.run(t, "", "checkpoint", "--prev-size", "3"); code != exitUsage {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	if code, _, stderr := f.run(t, "", "checkpoint", "--prev-hash", strings.Repeat("ab", 32)); code != exitUsage {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	if code, _, _ := f.run(t, "", "checkpoint", "--prev-size", "1", "--prev-hash", strings.Repeat("ab", 32)); code != exitFailed {
		t.Fatalf("a root hash from no tree was accepted: exit %d", code)
	}
}

// A baseline file's own defects have their own exit codes: a note that does
// not verify is a finding, a file that is not a note is a usage error, and
// neither is "rerun and it may work".
func TestCLI_FromFileExitCodes(t *testing.T) {
	f := setup(t)
	dir := t.TempDir()

	elsewhere := testlog.New("axt.anthropic.com/00000000-0000-0000-0000-000000000000")
	elsewhere.Append([]byte(`{"x":1}`))
	wrongOrigin := filepath.Join(dir, "wrong-origin.ckpt")
	if err := os.WriteFile(wrongOrigin, elsewhere.Checkpoint(elsewhere.Size()), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := f.run(t, "", "checkpoint", "--from", wrongOrigin); code != exitFailed {
		t.Fatalf("another origin's note: exit %d\n%s", code, stderr)
	}

	unsigned := testlog.New(origin)
	unsigned.Append([]byte(`{"x":1}`))
	unknownKey := filepath.Join(dir, "unknown-key.ckpt")
	if err := os.WriteFile(unknownKey, unsigned.Checkpoint(unsigned.Size()), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := f.run(t, "", "checkpoint", "--json", "--from", unknownKey)
	if code != exitFailed {
		t.Fatalf("a note signed by an unknown key: exit %d\n%s", code, stderr)
	}
	// The archive, not the log, failed: the remedy is --from-trusted, and the
	// served-checkpoint rotation hint would send the operator the wrong way.
	if !strings.Contains(stderr, "--from-trusted") || strings.Contains(stderr, "upgrade axt-verify") {
		t.Fatalf("wrong advice for an archive under an old key:\n%s", stderr)
	}
	if !strings.Contains(stdout, `"ok":false`) {
		t.Fatalf("no JSON line for an exit-1 result:\n%s", stdout)
	}

	garbage := filepath.Join(dir, "garbage.ckpt")
	if err := os.WriteFile(garbage, []byte("this is not a checkpoint\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := f.run(t, "", "checkpoint", "--from", garbage); code != exitUsage {
		t.Fatalf("a file that is not a note: exit %d\n%s", code, stderr)
	}
	if code, _, stderr := f.run(t, "", "checkpoint", "--from", filepath.Join(dir, "absent.ckpt")); code != exitUsage {
		t.Fatalf("a missing file: exit %d\n%s", code, stderr)
	}
}

// An event that happens to carry a field named "data" is still an event, so
// its own defects stay the verifier's to refuse rather than becoming a usage
// error about a page that was never there.
func TestCLI_EventWithADataFieldIsStillAnEvent(t *testing.T) {
	f := setup(t)
	tampered := strings.Replace(string(f.events[0]), `"reason_code"`,
		`"data":[1,2,3],"reason_code":"smuggled","reason_code"`, 1)
	if code, _, stderr := f.run(t, tampered, "events", "-"); code != exitFailed {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
}

// The JSON report is appended to a file someone will read in a terminal, and
// Go's encoder passes C1 controls through where it escapes C0. They are
// escaped here — losslessly, so an archived checkpoint still reads back
// byte-identically through --from.
func TestEscapeDisplay_IsLosslessAndTerminalSafe(t *testing.T) {
	withC1 := "note" + string(rune(0x9b)) + "2Ktail"
	raw, err := json.Marshal(map[string]string{"note": withC1})
	if err != nil {
		t.Fatal(err)
	}
	out := escapeDisplay(raw)
	if bytes.ContainsRune(out, 0x9b) {
		t.Fatalf("a C1 control survived: %q", out)
	}
	var back map[string]string
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatalf("the escaped JSON does not parse: %v", err)
	}
	if back["note"] != withC1 {
		t.Fatalf("the escaping was not lossless: %q", back["note"])
	}
}

// A credential answer that arrives after the checkpoint verified is the log
// declining to continue, not a misconfigured invocation: the operator must
// not be told to fix their command line.
func TestCLI_MidPassRefusalIsNotAUsageError(t *testing.T) {
	f := setup(t)
	f.srv.FailNext = map[string][]int{"activities": {403, 403, 403, 403, 403, 403}}
	code, _, stderr := f.run(t, "", "run")
	if code == exitUsage {
		t.Fatalf("a mid-pass 403 was reported as a usage error:\n%s", stderr)
	}
	if code != exitTransient && code != exitFailed {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
}

// The log holds the signing key, so a checkpoint that verifies can still
// carry display-hostile characters in a signed C2SP extension line, which the
// parser tolerates by design. They must not reach the .jsonl archive raw —
// and the note --save writes must stay exactly the bytes the log served, or
// the archive stops being evidence.
func TestCLI_JSONEscapesServedNoteButSaveKeepsItRaw(t *testing.T) {
	f := setup(t)
	// Includes astral runes: a JSON \u escape is a UTF-16 code unit, so these
	// need surrogate pairs or the decoded note comes back corrupted.
	hostile := "\u202egnihtemos\u2066\u0085\U000e0001\U000e0100"
	root := base64.StdEncoding.EncodeToString(f.srv.Log.RootAt(f.srv.Log.Size()))
	body := fmt.Sprintf("%s\n%d\n%s\n%s\n", origin, f.srv.Log.Size(), root, hostile)
	f.srv.CheckpointOverride = f.srv.Log.SignedNote(body)

	dir := t.TempDir()
	saved := filepath.Join(dir, "today.ckpt")
	code, stdout, stderr := f.run(t, "", "checkpoint", "--json", "--save", saved)
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	for _, r := range []rune{0x202e, 0x2066, 0x85, 0xe0001, 0xe0100} {
		if strings.ContainsRune(stdout, r) {
			t.Fatalf("U+%04X reached the JSON line raw:\n%q", r, stdout)
		}
	}
	// Lossless: the note decodes back to exactly what was served.
	var back struct {
		Checkpoint struct {
			Note string `json:"note"`
		} `json:"checkpoint"`
	}
	if err := json.Unmarshal([]byte(strings.SplitN(stdout, "\n", 2)[0]), &back); err != nil {
		t.Fatalf("the escaped report does not parse: %v", err)
	}
	if !strings.Contains(back.Checkpoint.Note, hostile) {
		t.Fatalf("the decoded note lost the served bytes: %q", back.Checkpoint.Note)
	}
	// --save writes the served note verbatim, escaping nothing.
	onDisk, err := os.ReadFile(saved)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(onDisk), hostile) {
		t.Fatalf("--save did not write the raw served note: %q", onDisk)
	}
}
