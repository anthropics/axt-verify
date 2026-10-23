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

const served = `{"type":"anthropic_access","id":"activity_x","transparency_log_leaf_index":4`

func parse(t *testing.T, raw string) leaf.Event {
	t.Helper()
	ev, err := leaf.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

// A Done entry holds one leaf hash. Either hash of the same serving matches
// it, so a record of the 0x01 entry is not re-verified as changed content. A
// serving that now carries a user_profile_id has no 0x01 hash to match: such
// a record means an id was served that no leaf commits, and it re-verifies.
func TestRecheckDone_EitherHashOfTheServingMatches(t *testing.T) {
	noID, with := parse(t, served+"}"), parse(t, served+`,"user_profile_id":"uprof_a"}`)
	for i, h := range noID.Hashes() {
		if reverify, failure := recheckDone(DoneEvent{Index: noID.Index, LeafHash: h}, noID); reverify || failure != nil {
			t.Fatalf("hash %d of the same serving: reverify=%v failure=%v", i, reverify, failure)
		}
	}
	if reverify, _ := recheckDone(DoneEvent{Index: with.Index, LeafHash: noID.Hashes()[1]}, with); !reverify {
		t.Fatal("a 0x01 record was trusted for a serving that carries a user_profile_id")
	}
}

// A stored pending entry is the same serving when its index and its
// leaf_hash match; for an event that carries a user_profile_id the hash a
// 0x01-only release recorded matches too. Its legacy_leaf_hash is never asked.
func TestSameServing(t *testing.T) {
	noID, with, other := parse(t, served+"}"), parse(t, served+`,"user_profile_id":"uprof_a"}`), parse(t, `{"type":"anthropic_access","id":"activity_y"}`)
	older := noID.Hashes()[1] // what a 0x01-only release records, id or no id
	pe := PendingEvent{Index: 4}
	for name, tc := range map[string]struct {
		old  PendingEvent
		ev   *leaf.Event
		want bool
	}{
		"its own 0x02 hash":                     {PendingEvent{Index: 4, LeafHash: with.Hash()}, &with, true},
		"the older release's hash":              {PendingEvent{Index: 4, LeafHash: older}, &with, true},
		"the stored entry itself":               {PendingEvent{Index: 4}, nil, true},
		"the stored entry at another index":     {PendingEvent{Index: 5}, nil, false},
		"another event's hash":                  {PendingEvent{Index: 4, LeafHash: other.Hashes()[1]}, &with, false},
		"no stored hash":                        {PendingEvent{Index: 4}, &with, false},
		"the same hash at another index":        {PendingEvent{Index: 5, LeafHash: with.Hash()}, &with, false},
		"only its legacy_leaf_hash would match": {PendingEvent{Index: 4, LeafHash: noID.Hash(), LegacyLeafHash: older}, &with, false},
	} {
		if got := sameServing(tc.old, pe, tc.ev); got != tc.want {
			t.Errorf("%s: sameServing = %v, want %v", name, got, tc.want)
		}
	}
}
