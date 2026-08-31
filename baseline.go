// Copyright 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package axtverify

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/anthropics/axt-verify/checkpoint"
)

// Baseline is a checkpoint the caller keeps for itself — yesterday's archived
// note, or a size and root hash recorded elsewhere — that this pass must
// prove the log still extends.
type Baseline struct {
	Checkpoint checkpoint.Checkpoint
	// Label says where it came from, for the pass's own output.
	Label string
}

// ReadBaselineNote finds a signed checkpoint note in what the caller handed
// over. It is liberal about the container — the raw note, a --json report, or
// a state file all carry one — and strict about the note itself: verify
// decides whether the signatures must check out, and the origin is enforced
// either way.
func ReadBaselineNote(raw []byte, v *checkpoint.Verifier, trusted bool) (checkpoint.Checkpoint, error) {
	note, err := extractNote(raw)
	if err != nil {
		return checkpoint.Checkpoint{}, err
	}
	if trusted {
		// The signing key may be long rotated out; what the customer is
		// asserting is their own record of (size, root), not a signature.
		return checkpoint.ParseTrusted(note, v.Origin())
	}
	return v.Verify(note)
}

func extractNote(raw []byte) ([]byte, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, errors.New("the file is empty")
	}
	if !strings.HasPrefix(trimmed, "{") {
		return []byte(trimmed + "\n"), nil
	}
	// A JSON container: a --json report or a state file. Both spell the note
	// the same way.
	var doc struct {
		Checkpoint json.RawMessage `json:"checkpoint"`
	}
	if err := json.Unmarshal([]byte(trimmed), &doc); err != nil {
		return nil, fmt.Errorf("the file is neither a checkpoint note nor JSON holding one: %w", err)
	}
	var asString string
	if err := json.Unmarshal(doc.Checkpoint, &asString); err == nil {
		return []byte(strings.TrimSpace(asString) + "\n"), nil
	}
	var asReport struct {
		Note string `json:"note"`
	}
	if err := json.Unmarshal(doc.Checkpoint, &asReport); err == nil && asReport.Note != "" {
		return []byte(strings.TrimSpace(asReport.Note) + "\n"), nil
	}
	return nil, errors.New("the JSON carries no checkpoint note")
}

// BaselineFromPair builds a baseline from a size and root hash the caller
// supplies directly. Nothing authenticates the pair — it is the caller's own
// record — so the label says so wherever the pass reports it.
func BaselineFromPair(size uint64, hash string) (Baseline, error) {
	h, err := decodeHash(hash)
	if err != nil {
		return Baseline{}, err
	}
	if size == 0 {
		return Baseline{}, errors.New("--prev-size must be greater than zero")
	}
	return Baseline{
		Checkpoint: checkpoint.Checkpoint{Size: size, Hash: h},
		Label:      "caller-supplied (size, hash) — unauthenticated pair",
	}, nil
}

func decodeHash(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if h, err := hex.DecodeString(s); err == nil && len(h) == 32 {
		return h, nil
	}
	h, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(h) != 32 {
		return nil, errors.New("--prev-hash must be a 32-byte root hash in base64 or hex")
	}
	return h, nil
}
