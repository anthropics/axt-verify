// Copyright 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package axtverify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const stateVersion = 1

// State is what one run leaves for the next: the last checkpoint it
// verified (the anchor for the append-only check) and how far through the
// activity feed it got. It holds no secrets and no event content.
type State struct {
	Version int `json:"version"`
	// Origin guards against pointing one organization's state at another's
	// configuration.
	Origin string `json:"origin"`
	// Checkpoint is the signed note of the newest checkpoint verified so far.
	Checkpoint string `json:"checkpoint,omitempty"`
	// VerifiedAt is when Checkpoint was verified.
	VerifiedAt time.Time `json:"verified_at,omitzero"`
	Feed       FeedState `json:"feed"`

	// loaded is the file content this state was read from, so Save can
	// refuse to overwrite a file another invocation has written since. Two
	// passes sharing a state file can each be served a different honest
	// extension of the same anchor, and the loser's checkpoint — possibly
	// the only local evidence of a fork — would be gone silently.
	loaded []byte
}

// FeedState tracks progress through the activity feed.
type FeedState struct {
	// HighWater is the newest created_at processed. The next run re-reads
	// an overlap window behind it because events become listable after an
	// ingestion delay, out of created_at order.
	HighWater time.Time `json:"high_water,omitzero"`
	// Done records events inside the overlap window that need no further
	// work (verified, or permanently without a leaf), keyed by activity id.
	Done map[string]DoneEvent `json:"done,omitempty"`
	// Pending records events whose leaf index no published checkpoint
	// covered yet, keyed by activity id.
	Pending map[string]PendingEvent `json:"pending,omitempty"`
}

// DoneEvent is a processed event.
type DoneEvent struct {
	CreatedAt time.Time `json:"created_at"`
	// Index is the verified leaf index; nil for an event served with no leaf.
	Index *uint64 `json:"leaf_index"`
	// LeafHash is the leaf hash that verified, so a re-listing of the same
	// id inside the overlap window is checked against it rather than
	// trusted.
	LeafHash []byte `json:"leaf_hash,omitempty"`
	// RecordedAt is when this pass verified the event, by the verifier's own
	// clock. Retention keys on it rather than on the served created_at,
	// which a serving path could backdate to have the record — the only
	// detector of a later index withdrawal — pruned early.
	RecordedAt time.Time `json:"recorded_at,omitzero"`
}

// PendingEvent is an event awaiting a covering checkpoint. LeafHash lets a
// later run verify it without re-reading the event.
type PendingEvent struct {
	Index     uint64    `json:"leaf_index"`
	LeafHash  []byte    `json:"leaf_hash"`
	CreatedAt time.Time `json:"created_at,omitzero"`
	FirstSeen time.Time `json:"first_seen"`
}

// LoadState reads path; a missing file yields an empty state for origin.
// A state written for a different origin is an error.
func LoadState(path, origin string) (*State, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &State{Version: stateVersion, Origin: origin}, nil
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if s.Version != stateVersion {
		return nil, fmt.Errorf("%s: unsupported state version %d", path, s.Version)
	}
	if s.Origin != origin {
		return nil, fmt.Errorf("%s: state belongs to origin %q, not the configured %q", path, s.Origin, origin)
	}
	s.loaded = raw
	return &s, nil
}

// Save writes the state to path atomically with owner-only permissions. It
// refuses to overwrite a file that changed since LoadState read it — two
// overlapping invocations sharing one state file must fail loudly rather
// than have one silently discard the other's verified checkpoint. This
// detects that collision; it is not a lock, and the README tells a
// concurrent schedule to use a state file of its own.
func (s *State) Save(path string) error {
	switch cur, err := os.ReadFile(path); {
	case errors.Is(err, os.ErrNotExist):
		if s.loaded != nil {
			return fmt.Errorf("%s: state file disappeared while this pass ran; rerun", path)
		}
	case err != nil:
		return err
	case !bytes.Equal(cur, s.loaded):
		return fmt.Errorf("%s: state file changed while this pass ran (another axt-verify sharing it?); rerun with a state file of its own", path)
	}
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) //nolint:errcheck // best-effort cleanup; a successful rename leaves nothing to remove
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(append(raw, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	s.loaded = append(raw, '\n')
	return nil
}

func (fs *FeedState) done(id string, e DoneEvent) {
	if fs.Done == nil {
		fs.Done = map[string]DoneEvent{}
	}
	fs.Done[id] = e
	delete(fs.Pending, id)
}

func (fs *FeedState) pend(id string, e PendingEvent) {
	if fs.Pending == nil {
		fs.Pending = map[string]PendingEvent{}
	}
	if old, ok := fs.Pending[id]; ok {
		e.FirstSeen = old.FirstSeen
	}
	fs.Pending[id] = e
}

// prune drops Done entries recorded longer ago than the window the next run
// re-reads. Recorded, not served: the timestamps in the feed are the serving
// path's to choose.
func (fs *FeedState) prune(notBefore time.Time) {
	for id, e := range fs.Done {
		if e.RecordedAt.Before(notBefore) {
			delete(fs.Done, id)
		}
	}
}
