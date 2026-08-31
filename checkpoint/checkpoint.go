// Copyright 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

// Package checkpoint verifies transparency-log checkpoints against a pinned
// trust policy — the log's origin and the log's note-verifier key — and
// verifies Merkle proofs against verified checkpoints.
package checkpoint

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/transparency-dev/formats/log"
	fnote "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/mod/sumdb/note"
)

// Policy is the trust configuration the caller brings: for axt-verify, the
// key built into the release, or the one --log-key supplies. Nothing in it
// may be learned from the API being verified.
type Policy struct {
	// Origin is the log's fixed origin line, "axt.anthropic.com/<organization_uuid>".
	Origin string
	// LogKey is the log's note-verifier key string. Its key name is the origin.
	LogKey string
}

// Errors returned by Verify and the proof checks. All of them mean the
// bytes must not be trusted.
var (
	ErrMalformed = errors.New("malformed checkpoint")
	ErrSignature = errors.New("checkpoint signature verification failed")
	ErrOrigin    = errors.New("checkpoint origin does not match the pinned origin")
	ErrProof     = errors.New("proof verification failed")
)

var originRE = regexp.MustCompile(`^[^\s/]+(/[^\s/]+)*/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)

// Verifier checks checkpoints against one Policy.
type Verifier struct {
	origin  string
	orgUUID string
	log     note.Verifier
	all     note.Verifiers
}

// New validates p and returns a Verifier for it.
func New(p Policy) (*Verifier, error) {
	m := originRE.FindStringSubmatch(p.Origin)
	if m == nil {
		return nil, fmt.Errorf("origin %q is not of the form <log name>/<organization uuid>", p.Origin)
	}
	logV, err := fnote.NewVerifier(strings.TrimSpace(p.LogKey))
	if err != nil {
		return nil, fmt.Errorf("log verifier key: %w", err)
	}
	if logV.Name() != p.Origin {
		return nil, fmt.Errorf("log verifier key is named %q; it must be named for the pinned origin %q", logV.Name(), p.Origin)
	}
	return &Verifier{origin: p.Origin, orgUUID: m[2], log: logV, all: note.VerifierList(logV)}, nil
}

// Origin is the pinned origin line.
func (v *Verifier) Origin() string { return v.origin }

// OrgUUID is the organization UUID the pinned origin names.
func (v *Verifier) OrgUUID() string { return v.orgUUID }

// Checkpoint is a checkpoint that passed Verify.
type Checkpoint struct {
	// Raw is the signed note exactly as served.
	Raw []byte
	// Size is the tree size (leaf count) the checkpoint commits to.
	Size uint64
	// Hash is the Merkle root hash at Size.
	Hash []byte
}

// SameTree reports whether two verified checkpoints commit to the same tree.
func (c Checkpoint) SameTree(o Checkpoint) bool {
	return c.Size == o.Size && bytes.Equal(c.Hash, o.Hash)
}

// Verify accepts raw only if it is a well-formed checkpoint signed by the log
// key whose origin line is exactly the pinned origin. Signatures by unknown
// keys are ignored. Every organization's log is signed by the same key, so
// the origin comparison — not the signature — is what binds a checkpoint to
// this organization.
func (v *Verifier) Verify(raw []byte) (Checkpoint, error) {
	// A signature failure carries the note it rejected, so the caller can
	// show the operator which keys did sign it.
	sigErr := func(err error) (Checkpoint, error) {
		return Checkpoint{}, &SignatureError{Err: err, Note: bytes.Clone(raw)}
	}
	n, err := note.Open(raw, v.all)
	var unverified *note.UnverifiedNoteError
	var invalid *note.InvalidSignatureError
	switch {
	case errors.As(err, &invalid):
		return sigErr(fmt.Errorf("%w: invalid signature for key %s", ErrSignature, invalid.Name))
	case errors.As(err, &unverified):
		return sigErr(fmt.Errorf("%w: no signature from any pinned key", ErrSignature))
	case err != nil:
		return Checkpoint{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	cp := Checkpoint{Raw: bytes.Clone(raw)}
	if _, ok := findSig(n, v.log); !ok {
		return sigErr(fmt.Errorf("%w: missing signature from %s", ErrSignature, v.log.Name()))
	}
	if cp.Size, cp.Hash, err = parseBody([]byte(n.Text), v.origin); err != nil {
		return Checkpoint{}, err
	}
	return cp, nil
}

// SignatureError is a signature failure carrying the note exactly as it was
// served. Those bytes did not verify: they are diagnostics — which keys
// signed the thing the log offered — never something to act on.
type SignatureError struct {
	Err  error
	Note []byte
}

func (e *SignatureError) Error() string { return e.Err.Error() }
func (e *SignatureError) Unwrap() error { return e.Err }

// Signature is one signature line of a signed note.
type Signature struct {
	// Name is the key name the line carried. On a note that failed
	// verification this is attacker-chosen text: print it escaped.
	Name string `json:"name"`
	// KeyHash is the signing key's 4-byte hash, hex-encoded — what the
	// published key table lists.
	KeyHash string `json:"key_hash"`
	// OK is false for a line that does not parse, where Name and KeyHash
	// are empty and the line itself is not worth showing. It stays out of
	// the JSON: a reader sees an entry with nothing in it, which is what
	// the note gave.
	OK bool `json:"-"`
}

// Bounds on what Signatures will report out of an unverified note: enough
// for a log that signs with several keys, small enough that a hostile note
// cannot turn a failure message into a wall of text.
const (
	maxSignaturesReported = 16
	maxSignatureNameLen   = 100
)

// Signatures lists the signature lines of a signed note WITHOUT verifying
// any of them. It exists for one job: after a checkpoint is rejected, show
// the operator which key hashes the log did sign with, so they can compare
// them against the published table. The note is untrusted input, so at most
// maxSignaturesReported lines come back, an over-long or malformed line
// comes back with OK false rather than as an error, and every name is
// returned as served for the caller to escape before printing.
func Signatures(raw []byte) []Signature {
	// A signed note is its text, a blank line, then the signature lines.
	_, block, ok := bytes.Cut(raw, []byte("\n\n"))
	if !ok {
		return nil
	}
	var out []Signature
	for _, line := range bytes.Split(block, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		if len(out) == maxSignaturesReported {
			break
		}
		out = append(out, parseSignatureLine(line))
	}
	return out
}

func parseSignatureLine(line []byte) Signature {
	rest, ok := bytes.CutPrefix(line, []byte("— "))
	if !ok {
		return Signature{}
	}
	name, encoded, ok := bytes.Cut(rest, []byte(" "))
	if !ok || len(name) == 0 || len(name) > maxSignatureNameLen {
		return Signature{}
	}
	// The signature bytes begin with the 4-byte hash of the signing key.
	sig, err := base64.StdEncoding.DecodeString(string(encoded))
	if err != nil || len(sig) < 4 {
		return Signature{}
	}
	return Signature{Name: string(name), KeyHash: hex.EncodeToString(sig[:4]), OK: true}
}

// LogKey is the key this verifier requires a checkpoint to be signed by, in
// the same shape Signatures reports, so a rejected note's key hashes can be
// held up against it.
func (v *Verifier) LogKey() Signature {
	return Signature{Name: v.log.Name(), KeyHash: fmt.Sprintf("%08x", v.log.KeyHash()), OK: true}
}

// ParseTrusted reads the size and root hash out of a checkpoint WITHOUT
// verifying its signatures — only for a checkpoint this program verified
// earlier and stored itself (its signing keys may since have rotated).
// The origin line must still equal origin.
func ParseTrusted(raw []byte, origin string) (Checkpoint, error) {
	text, _, ok := bytes.Cut(raw, []byte("\n\n"))
	if !ok {
		return Checkpoint{}, fmt.Errorf("%w: no signature block", ErrMalformed)
	}
	cp := Checkpoint{Raw: bytes.Clone(raw)}
	var err error
	if cp.Size, cp.Hash, err = parseBody(append(text, '\n'), origin); err != nil {
		return Checkpoint{}, err
	}
	return cp, nil
}

func parseBody(text []byte, origin string) (uint64, []byte, error) {
	// C2SP tlog-checkpoint permits extension lines after the root hash;
	// they are covered by the signatures and carry nothing this verifier
	// consumes.
	var body log.Checkpoint
	if _, err := body.Unmarshal(text); err != nil {
		return 0, nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if body.Origin != origin {
		return 0, nil, fmt.Errorf("%w: got %q", ErrOrigin, body.Origin)
	}
	if len(body.Hash) != rfc6962.DefaultHasher.Size() {
		return 0, nil, fmt.Errorf("%w: root hash is %d bytes", ErrMalformed, len(body.Hash))
	}
	return body.Size, body.Hash, nil
}

func findSig(n *note.Note, v note.Verifier) (note.Signature, bool) {
	for _, s := range n.Sigs {
		if s.Name == v.Name() && s.Hash == v.KeyHash() {
			return s, true
		}
	}
	return note.Signature{}, false
}

// maxProofLen bounds a proof: one hash per tree level, and 64 levels
// address the whole uint64 index space.
const maxProofLen = 64

// VerifyInclusion checks that leafHash is the leaf at index in the tree cp
// commits to.
func VerifyInclusion(cp Checkpoint, index uint64, leafHash []byte, hashes [][]byte) error {
	if err := checkHashes(hashes); err != nil {
		return err
	}
	if index >= cp.Size {
		return fmt.Errorf("%w: index %d is beyond tree size %d", ErrProof, index, cp.Size)
	}
	if err := proof.VerifyInclusion(rfc6962.DefaultHasher, index, cp.Size, leafHash, hashes, cp.Hash); err != nil {
		return fmt.Errorf("%w: inclusion of index %d in tree size %d: %w", ErrProof, index, cp.Size, err)
	}
	return nil
}

// VerifyConsistency checks that the tree newer commits to is an
// append-only extension of the tree older commits to. Equal sizes require
// equal root hashes; a smaller newer tree is a rollback and always fails.
func VerifyConsistency(older, newer Checkpoint, hashes [][]byte) error {
	if err := checkHashes(hashes); err != nil {
		return err
	}
	if newer.Size < older.Size {
		return fmt.Errorf("%w: tree shrank from %d to %d leaves", ErrProof, older.Size, newer.Size)
	}
	if err := proof.VerifyConsistency(rfc6962.DefaultHasher, older.Size, newer.Size, hashes, older.Hash, newer.Hash); err != nil {
		return fmt.Errorf("%w: consistency from tree size %d to %d: %w", ErrProof, older.Size, newer.Size, err)
	}
	return nil
}

func checkHashes(hashes [][]byte) error {
	if len(hashes) > maxProofLen {
		return fmt.Errorf("%w: %d proof hashes", ErrProof, len(hashes))
	}
	for i, h := range hashes {
		if len(h) != rfc6962.DefaultHasher.Size() {
			return fmt.Errorf("%w: proof hash %d is %d bytes", ErrProof, i, len(h))
		}
	}
	return nil
}
