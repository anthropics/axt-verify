// Copyright 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package axtverify

import (
	"testing"

	"github.com/anthropics/axt-verify/leaf"
)

// A Done entry whose leaf hash is missing (a state file edited by another
// hand) must not exempt the id from re-verification.
func TestRecheckDone_MissingHashReverifies(t *testing.T) {
	idx := uint64(4)
	ev := leaf.Event{ID: "activity_x", Index: &idx, Entry: []byte("\x01{}")}

	if reverify, failure := recheckDone(DoneEvent{Index: &idx, LeafHash: ev.Hash()}, ev); reverify || failure != nil {
		t.Fatalf("same bytes at the same index: reverify=%v failure=%v", reverify, failure)
	}
	if reverify, _ := recheckDone(DoneEvent{Index: &idx}, ev); !reverify {
		t.Fatal("an entry with no leaf hash was trusted instead of re-verified")
	}
	if reverify, _ := recheckDone(DoneEvent{Index: &idx, LeafHash: make([]byte, 32)}, ev); !reverify {
		t.Fatal("an entry with a different leaf hash was trusted instead of re-verified")
	}
}
