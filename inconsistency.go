// Copyright 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package axtverify

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/anthropics/axt-verify/checkpoint"
)

// Inconsistency is everything needed to show that a log broke its
// append-only promise, without asking that log anything further. A verifier
// that reported only "consistency proof failed" would leave the customer
// holding a claim they cannot substantiate once the misbehaving server stops
// answering — or starts answering differently.
type Inconsistency struct {
	// Older and Newer are the two signed notes, verbatim.
	Older string `json:"older"`
	Newer string `json:"newer"`
	// Proof is the consistency proof the log served between them, base64.
	Proof []string `json:"proof"`
}

// InconsistencyError is a verification failure carrying that evidence.
type InconsistencyError struct {
	Evidence Inconsistency
	Err      error
}

func (e *InconsistencyError) Error() string {
	return fmt.Sprintf("log inconsistency: %s", e.Err)
}

func (e *InconsistencyError) Unwrap() []error { return []error{ErrVerification, e.Err} }

// Details renders the evidence for a human, and for whoever they forward it
// to: both notes in full and the proof the log offered between them.
func (e *InconsistencyError) Details() string {
	out := "older checkpoint (as served or as previously recorded):\n" + e.Evidence.Older
	if len(out) > 0 && out[len(out)-1] != '\n' {
		out += "\n"
	}
	out += "\nnewer checkpoint (as served):\n" + e.Evidence.Newer
	if out[len(out)-1] != '\n' {
		out += "\n"
	}
	out += "\nconsistency proof the log served between them:\n"
	if len(e.Evidence.Proof) == 0 {
		out += "  (none)\n"
	}
	for _, h := range e.Evidence.Proof {
		out += "  " + h + "\n"
	}
	return out
}

func inconsistent(err error, older, newer checkpoint.Checkpoint, hashes [][]byte) error {
	proof := make([]string, 0, len(hashes))
	for _, h := range hashes {
		proof = append(proof, base64.StdEncoding.EncodeToString(h))
	}
	return &InconsistencyError{
		Evidence: Inconsistency{Older: noteOrPair(older), Newer: noteOrPair(newer), Proof: proof},
		Err:      err,
	}
}

// noteOrPair renders what the caller can actually forward: the signed note
// when there is one, and otherwise the bare pair they supplied themselves.
func noteOrPair(cp checkpoint.Checkpoint) string {
	if len(cp.Raw) > 0 {
		return string(cp.Raw)
	}
	return fmt.Sprintf("(no signed note — caller-supplied pair) size %d root %s\n",
		cp.Size, base64.StdEncoding.EncodeToString(cp.Hash))
}

// AsInconsistency extracts the evidence from an error chain, if it carries any.
func AsInconsistency(err error) (*InconsistencyError, bool) {
	var ie *InconsistencyError
	ok := errors.As(err, &ie)
	return ie, ok
}
