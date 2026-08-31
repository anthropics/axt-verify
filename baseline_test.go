// Copyright 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package axtverify_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/anthropics/axt-verify"
	"github.com/anthropics/axt-verify/internal/testlog"
)

// A checkpoint the customer kept is an additional ratchet: the log has to
// prove it still extends it, whatever the state file says.
func TestRun_BaselineFromArchivedNote(t *testing.T) {
	e := newEnv(t)
	e.logged(3)
	e.srv.Publish()
	e.mustRun()
	archived := e.log.Checkpoint(e.log.Size())

	e.logged(2)
	e.srv.Publish()
	cp, err := e.v.Checkpoints.Verify(archived)
	if err != nil {
		t.Fatal(err)
	}
	e.v.Baselines = []axtverify.Baseline{{Checkpoint: cp, Label: "yesterday.ckpt"}}
	if _, err := e.run(); err != nil {
		t.Fatalf("an honest extension of the archived checkpoint was refused: %v", err)
	}
}

// A baseline from a different tree is the case this feature exists for, and
// the refusal has to carry evidence someone else can check.
func TestRun_BaselineFromForkedTreeCarriesEvidence(t *testing.T) {
	e := newEnv(t)
	e.logged(3)
	e.srv.Publish()

	// A checkpoint of the same size over a different tree.
	other := testlog.New(origin)
	other.Key = e.log.Key
	other.Append([]byte(`{"a":1}`), []byte(`{"b":2}`), []byte(`{"c":3}`))
	forked, err := e.v.Checkpoints.Verify(other.Checkpoint(other.Size()))
	if err != nil {
		t.Fatal(err)
	}
	e.v.Baselines = []axtverify.Baseline{{Checkpoint: forked, Label: "yesterday.ckpt"}}

	_, err = e.run()
	if err == nil {
		t.Fatal("a checkpoint from another tree was accepted as a baseline")
	}
	ie, ok := axtverify.AsInconsistency(err)
	if !ok {
		t.Fatalf("no evidence attached: %v", err)
	}
	// The report has to stand on its own once the log stops answering.
	details := ie.Details()
	for _, want := range []string{origin, "older checkpoint", "newer checkpoint"} {
		if !strings.Contains(details, want) {
			t.Fatalf("evidence is missing %q:\n%s", want, details)
		}
	}
	if ie.Evidence.Older == "" || ie.Evidence.Newer == "" {
		t.Fatalf("evidence carries no notes: %+v", ie.Evidence)
	}
}

// A pair the caller kept somewhere else works the same way, and says in its
// own label that nothing authenticates it.
func TestBaselineFromPair(t *testing.T) {
	e := newEnv(t)
	e.logged(2)
	e.srv.Publish()
	e.mustRun()
	cp, err := e.v.Checkpoints.Verify(e.log.Checkpoint(e.log.Size()))
	if err != nil {
		t.Fatal(err)
	}

	b, err := axtverify.BaselineFromPair(cp.Size, base64.StdEncoding.EncodeToString(cp.Hash))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.Label, "unauthenticated") {
		t.Fatalf("label %q does not say the pair is unauthenticated", b.Label)
	}
	e.logged(1)
	e.srv.Publish()
	e.v.Baselines = []axtverify.Baseline{b}
	if _, err := e.run(); err != nil {
		t.Fatalf("an honest extension of the supplied pair was refused: %v", err)
	}

	// A hash that belongs to no tree of that size is a finding.
	wrong := make([]byte, 32)
	copy(wrong, cp.Hash)
	wrong[0] ^= 0xff
	bad, err := axtverify.BaselineFromPair(cp.Size, base64.StdEncoding.EncodeToString(wrong))
	if err != nil {
		t.Fatal(err)
	}
	e.v.Baselines = []axtverify.Baseline{bad}
	if _, err := e.run(); err == nil {
		t.Fatal("a root hash from no tree was accepted")
	}
}

func TestBaselineFromPair_Rejects(t *testing.T) {
	if _, err := axtverify.BaselineFromPair(0, strings.Repeat("ab", 32)); err == nil {
		t.Fatal("size zero was accepted")
	}
	if _, err := axtverify.BaselineFromPair(5, "not-a-hash"); err == nil {
		t.Fatal("a malformed hash was accepted")
	}
}

// The file a customer hands back may be the note, a --json report line, or a
// state file; what is read liberally is still verified strictly.
func TestReadBaselineNote_Containers(t *testing.T) {
	e := newEnv(t)
	e.logged(2)
	e.srv.Publish()
	note := string(e.log.Checkpoint(e.log.Size()))

	quoted, err := json.Marshal(note)
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{
		"bare note":   note,
		"state file":  `{"checkpoint":` + string(quoted) + `,"feed":{}}`,
		"json report": `{"origin":"x","checkpoint":{"size":2,"note":` + string(quoted) + `}}`,
	} {
		t.Run(name, func(t *testing.T) {
			cp, err := axtverify.ReadBaselineNote([]byte(raw), e.v.Checkpoints, false)
			if err != nil {
				t.Fatal(err)
			}
			if cp.Size != 2 {
				t.Fatalf("size %d", cp.Size)
			}
		})
	}

	// Another origin's note is refused however it is wrapped.
	elsewhere := testlog.New("axt.anthropic.com/00000000-0000-0000-0000-000000000000")
	elsewhere.Append([]byte(`{"x":1}`))
	elseNote := elsewhere.Checkpoint(elsewhere.Size())
	if _, err := axtverify.ReadBaselineNote(elseNote, e.v.Checkpoints, false); err == nil {
		t.Fatal("a note for another origin was accepted")
	}
	// Trusting the file skips signatures, never the origin.
	if _, err := axtverify.ReadBaselineNote(elseNote, e.v.Checkpoints, true); err == nil {
		t.Fatal("--from-trusted accepted another origin")
	}
	// A note signed by a key this installation does not know is exactly what
	// --from-trusted is for: the customer's own archive after a rotation.
	rotated := testlog.New(origin)
	rotated.Append([]byte(`{"x":1}`), []byte(`{"y":2}`))
	rotatedNote := rotated.Checkpoint(rotated.Size())
	if _, err := axtverify.ReadBaselineNote(rotatedNote, e.v.Checkpoints, false); err == nil {
		t.Fatal("a note signed by an unknown key verified")
	}
	if _, err := axtverify.ReadBaselineNote(rotatedNote, e.v.Checkpoints, true); err != nil {
		t.Fatalf("--from-trusted refused an archive signed by a rotated-out key: %v", err)
	}
}

// A log that serves a tree smaller than the customer's own baseline is the
// wipe this feature exists to catch — never a checkpoint to adopt.
func TestRun_BaselineAboveServedSizeIsRefused(t *testing.T) {
	e := newEnv(t)
	e.logged(3)
	e.srv.Publish()
	cp, err := e.v.Checkpoints.Verify(e.log.Checkpoint(e.log.Size()))
	if err != nil {
		t.Fatal(err)
	}

	// The log is recreated empty, keeping its key: the customer still holds
	// yesterday's checkpoint.
	wiped := testlog.New(origin)
	wiped.Key = e.log.Key
	e.srv.Log = wiped
	e.srv.Publish()

	e.v.Baselines = []axtverify.Baseline{{Checkpoint: cp, Label: "yesterday.ckpt"}}
	rep, err := e.run()
	if err == nil {
		t.Fatalf("a wiped log was accepted: %+v", rep)
	}
	if !errors.Is(err, axtverify.ErrVerification) {
		t.Fatalf("err = %v, want a verification failure", err)
	}
	if rep.Checkpoint.Size >= cp.Size {
		t.Fatalf("the baseline was adopted as the pass's checkpoint: %+v", rep.Checkpoint)
	}
}

// A rollback verdict has to carry the same forwardable evidence a failed
// consistency proof does: the checkpoint the customer holds and the one the
// log serves instead.
func TestRun_RollbackCarriesEvidence(t *testing.T) {
	e := newEnv(t)
	e.logged(3)
	e.srv.Publish()
	e.mustRun()

	wiped := testlog.New(origin)
	wiped.Key = e.log.Key
	wiped.Append([]byte(`{"one":1}`))
	e.srv.Log = wiped
	e.srv.Publish()

	_, err := e.run()
	if err == nil {
		t.Fatal("a shrunken log was accepted")
	}
	ie, ok := axtverify.AsInconsistency(err)
	if !ok {
		t.Fatalf("no evidence on a rollback: %v", err)
	}
	if ie.Evidence.Older == "" || ie.Evidence.Newer == "" {
		t.Fatalf("evidence carries no checkpoints: %+v", ie.Evidence)
	}
	if !strings.Contains(ie.Details(), origin) {
		t.Fatalf("evidence does not name the origin:\n%s", ie.Details())
	}
}

// A log that answers the consistency request with a refusal — whatever
// status it picks, and from whichever path the proof was needed — is
// declining to prove itself, not misconfiguring the customer.
func TestRun_RefusedProofIsAFindingWhateverTheStatus(t *testing.T) {
	for _, status := range []int{404, 400, 401, 403} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			e := newEnv(t)
			e.logged(2)
			e.srv.Publish()
			e.mustRun()

			e.logged(2)
			e.srv.Publish()
			e.srv.FailNext = map[string][]int{"consistency": {status, status, status, status, status, status}}
			_, err := e.run()
			if err == nil {
				t.Fatal("a refused consistency proof was accepted")
			}
			if !errors.Is(err, axtverify.ErrVerification) {
				t.Fatalf("status %d: err = %v, want a verification finding", status, err)
			}
			if ie, ok := axtverify.AsInconsistency(err); !ok || ie.Evidence.Older == "" {
				t.Fatalf("status %d: no forwardable evidence: %v", status, err)
			}
		})
	}
}
