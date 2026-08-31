// Copyright 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package checkpoint_test

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/transparency-dev/merkle/rfc6962"

	"github.com/anthropics/axt-verify/checkpoint"
	"github.com/anthropics/axt-verify/internal/testlog"
)

const origin = "axt.anthropic.com/25f6429a-3293-49bf-afed-cb312911554b"

func newLog(t *testing.T, n int) *testlog.Log {
	t.Helper()
	l := testlog.New(origin)
	for i := range n {
		l.Append([]byte{byte(i), 'x'})
	}
	return l
}

func mustNew(t *testing.T, p checkpoint.Policy) *checkpoint.Verifier {
	t.Helper()
	v, err := checkpoint.New(p)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestNew_PolicyValidation(t *testing.T) {
	l := newLog(t, 1)
	other := testlog.NewLogKey("axt.anthropic.com/00000000-0000-0000-0000-000000000000")
	cases := map[string]checkpoint.Policy{
		"origin without uuid":     {Origin: "axt.anthropic.com/not-a-uuid", LogKey: l.Key.VKey},
		"origin uppercase uuid":   {Origin: strings.ToUpper(origin), LogKey: l.Key.VKey},
		"log key named elsewhere": {Origin: origin, LogKey: other.VKey},
		"garbage log key":         {Origin: origin, LogKey: "nope"},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := checkpoint.New(p); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	if got := mustNew(t, checkpoint.Policy{Origin: origin, LogKey: l.Key.VKey}).OrgUUID(); got != "25f6429a-3293-49bf-afed-cb312911554b" {
		t.Fatalf("OrgUUID = %q", got)
	}
}

func TestVerify_LogOnly(t *testing.T) {
	l := newLog(t, 5)
	v := mustNew(t, checkpoint.Policy{Origin: origin, LogKey: l.Key.VKey})
	cp, err := v.Verify(l.Checkpoint(5))
	if err != nil {
		t.Fatal(err)
	}
	if cp.Size != 5 || string(cp.Hash) != string(l.RootAt(5)) {
		t.Fatalf("cp = %+v", cp)
	}
	// A note signed only by a key this verifier does not know is refused.
	stranger := newLog(t, 5)
	if _, err := v.Verify(stranger.Checkpoint(5)); err == nil {
		t.Fatal("a checkpoint signed by an unknown key verified")
	}
}

func TestVerify_Rejections(t *testing.T) {
	l := newLog(t, 5)
	v := mustNew(t, checkpoint.Policy{Origin: origin, LogKey: l.Key.VKey})
	otherOrg := testlog.New("axt.anthropic.com/00000000-0000-0000-0000-000000000000")
	otherOrg.Key = l.Key.Named(otherOrg.Origin) // production: one signing key, named per origin
	otherOrg.Append([]byte("a"))
	impostor := testlog.New(origin) // right origin, wrong key

	root := base64.StdEncoding.EncodeToString(l.RootAt(5))
	logOnly := v

	cases := []struct {
		name string
		v    *checkpoint.Verifier
		raw  []byte
		want error
	}{
		{"garbage", v, []byte("not a note"), checkpoint.ErrMalformed},
		{"wrong log key", v, impostor.Checkpoint(0), checkpoint.ErrSignature},
		{"other org's checkpoint, validly signed", v, otherOrg.Checkpoint(1), checkpoint.ErrSignature},
		{"tampered body", v, tamper(l.Checkpoint(5)), checkpoint.ErrSignature},
		{"no size", logOnly, l.SignedNote(origin + "\n"), checkpoint.ErrMalformed},
		{"no root", logOnly, l.SignedNote(origin + "\n5\n"), checkpoint.ErrMalformed},
		{"short root", logOnly, l.SignedNote(origin + "\n5\nAAAA\n"), checkpoint.ErrMalformed},
		{"negative size", logOnly, l.SignedNote(origin + "\n-1\n" + root + "\n"), checkpoint.ErrMalformed},
		{"hex size", logOnly, l.SignedNote(origin + "\n0x5\n" + root + "\n"), checkpoint.ErrMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := c.v.Verify(c.raw); !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}
	// The other-org case above already fails on the LOG signature because
	// the log key's name embeds the origin; a verifier pinned to a key that
	// did sign must still refuse on the origin line itself.
	bare := testlog.New("axt.anthropic.com/00000000-0000-0000-0000-000000000000")
	vb := mustNew(t, checkpoint.Policy{Origin: bare.Origin, LogKey: bare.Key.VKey})
	if _, err := vb.Verify(bare.CheckpointFor(origin, 1, make([]byte, 32))); !errors.Is(err, checkpoint.ErrOrigin) {
		t.Fatalf("origin mismatch: err = %v", err)
	}
	if _, err := v.Verify(l.Checkpoint(5)); err != nil {
		t.Fatalf("correctly signed: %v", err)
	}
	// C2SP tlog-checkpoint extension lines are signed-over and ignored.
	ext := origin + "\n5\n" + root + "\nsome extension\n"
	if cp, err := v.Verify(l.SignedNote(ext)); err != nil || cp.Size != 5 {
		t.Fatalf("extension line: cp=%+v err=%v", cp, err)
	}
}

func tamper(raw []byte) []byte {
	return []byte(strings.Replace(string(raw), "\n5\n", "\n4\n", 1))
}

func TestProofs(t *testing.T) {
	l := newLog(t, 13)
	v := mustNew(t, checkpoint.Policy{Origin: origin, LogKey: l.Key.VKey})
	cpAt := func(n uint64) checkpoint.Checkpoint {
		cp, err := v.Verify(l.Checkpoint(n))
		if err != nil {
			t.Fatal(err)
		}
		return cp
	}
	cp13, cp8, cp0 := cpAt(13), cpAt(8), cpAt(0)
	for i := range uint64(13) {
		h := rfc6962.DefaultHasher.HashLeaf(l.Entry(i))
		if err := checkpoint.VerifyInclusion(cp13, i, h, l.InclusionProof(i, 13)); err != nil {
			t.Fatalf("inclusion %d: %v", i, err)
		}
	}
	h3 := rfc6962.DefaultHasher.HashLeaf(l.Entry(3))
	bad := map[string]error{
		"wrong leaf":     checkpoint.VerifyInclusion(cp13, 3, rfc6962.DefaultHasher.HashLeaf([]byte("forged")), l.InclusionProof(3, 13)),
		"wrong index":    checkpoint.VerifyInclusion(cp13, 4, h3, l.InclusionProof(3, 13)),
		"index ≥ size":   checkpoint.VerifyInclusion(cp8, 9, h3, l.InclusionProof(3, 13)),
		"other size":     checkpoint.VerifyInclusion(cp8, 3, h3, l.InclusionProof(3, 13)),
		"short hash":     checkpoint.VerifyInclusion(cp13, 3, h3, [][]byte{{1, 2}}),
		"too many":       checkpoint.VerifyInclusion(cp13, 3, h3, make([][]byte, 65)),
		"rollback":       checkpoint.VerifyConsistency(cp13, cp8, nil),
		"wrong proof":    checkpoint.VerifyConsistency(cp8, cp13, l.InclusionProof(3, 13)),
		"same size fork": checkpoint.VerifyConsistency(cp8, checkpoint.Checkpoint{Size: 8, Hash: make([]byte, 32)}, nil),
	}
	for name, err := range bad {
		if !errors.Is(err, checkpoint.ErrProof) {
			t.Errorf("%s: err = %v, want ErrProof", name, err)
		}
	}
	good := map[string]error{
		"8→13":  checkpoint.VerifyConsistency(cp8, cp13, l.ConsistencyProof(8, 13)),
		"8→8":   checkpoint.VerifyConsistency(cp8, cp8, nil),
		"0→13":  checkpoint.VerifyConsistency(cp0, cp13, nil),
		"13→13": checkpoint.VerifyConsistency(cp13, cp13, [][]byte{}),
	}
	for name, err := range good {
		if err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A checkpoint the verifier rejects still has to say which keys signed it,
// so the operator can hold those hashes against the published table. The
// note is untrusted at that point: nothing here may fail on hostile input.
func TestSignatures(t *testing.T) {
	line := func(name string, keyHash uint32) string {
		b := make([]byte, 4+64)
		binary.BigEndian.PutUint32(b, keyHash)
		return "— " + name + " " + base64.StdEncoding.EncodeToString(b)
	}
	const body = "axt.anthropic.com/25f6429a-3293-49bf-afed-cb312911554b\n7\nc2hh\n"
	hostile := "evil\x1b[31mname"

	for _, c := range []struct {
		name string
		raw  string
		want []checkpoint.Signature
	}{
		{"one signature", body + "\n" + line("axt.anthropic.com/org", 0xdc75a2df) + "\n",
			[]checkpoint.Signature{{Name: "axt.anthropic.com/org", KeyHash: "dc75a2df", OK: true}}},
		{"two signatures", body + "\n" + line("a", 1) + "\n" + line("b", 0xffffffff) + "\n",
			[]checkpoint.Signature{{Name: "a", KeyHash: "00000001", OK: true}, {Name: "b", KeyHash: "ffffffff", OK: true}}},
		{"unparseable line", body + "\nnot a signature at all\n", []checkpoint.Signature{{}}},
		{"signature without base64", body + "\n— lonely\n", []checkpoint.Signature{{}}},
		{"no signature block", body, nil},
		// Returned as served: escaping belongs to whoever prints it.
		{"hostile name", body + "\n" + line(hostile, 2) + "\n",
			[]checkpoint.Signature{{Name: hostile, KeyHash: "00000002", OK: true}}},
		{"over-long name", body + "\n" + line(strings.Repeat("n", 200), 3) + "\n", []checkpoint.Signature{{}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := checkpoint.Signatures([]byte(c.raw))
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("got %+v, want %+v", got, c.want)
			}
		})
	}

	// A note carrying more lines than anyone would show is truncated rather
	// than turned into a wall of output.
	var many strings.Builder
	many.WriteString(body + "\n")
	for i := range 40 {
		many.WriteString(line("k", uint32(i)) + "\n")
	}
	if got := checkpoint.Signatures([]byte(many.String())); len(got) != 16 {
		t.Fatalf("got %d signatures, want the reported maximum of 16", len(got))
	}
}
