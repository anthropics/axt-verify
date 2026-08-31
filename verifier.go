// Copyright 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package axtverify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/anthropics/axt-verify/checkpoint"
	"github.com/anthropics/axt-verify/compliance"
	"github.com/anthropics/axt-verify/leaf"
)

// ErrLogAdvancing means the log published new checkpoints faster than one
// run could relate them; rerunning resolves it.
var ErrLogAdvancing = errors.New("the log advanced repeatedly during verification; rerun")

const (
	defaultOverlap      = 168 * time.Hour
	defaultPendingGrace = 24 * time.Hour
	defaultCoverageWait = 60 * time.Second
	defaultCoveragePoll = 15 * time.Second
	defaultPageSize     = 1000
	maxRelateAttempts   = 3
	// maxFeedPages bounds an unbounded (MaxPages == 0) feed read. An honest
	// backlog ends; a served page sequence that does not must not hang the
	// pass, since a process that never exits reports nothing.
	maxFeedPages = 100_000
	// maxFutureSkew is how far ahead of this clock a served created_at may
	// sit and still advance the feed high-water mark; it allows for ordinary
	// clock difference between this machine and the API.
	maxFutureSkew = 5 * time.Minute
)

// Verifier runs verification passes for one organization's log.
type Verifier struct {
	Checkpoints *checkpoint.Verifier
	Client      *compliance.Client

	// Baselines are checkpoints the caller keeps for itself — an archived
	// note, or a bare (size, hash) pair. Each must be a prefix of what this
	// pass verifies, on top of whatever the state file already ratchets.
	Baselines []Baseline
	// Overlap is how far behind the feed high-water mark each run
	// re-reads (default 168h). It must exceed the feed's ingestion and
	// delivery delays so late-listed events are not skipped.
	Overlap time.Duration
	// PendingGrace is how long an event may wait for a covering checkpoint
	// before that becomes a failure (default 24h).
	PendingGrace time.Duration
	// CoverageWait bounds how long `events` waits for a checkpoint covering
	// an index it was handed (default 60s). `run` never waits: it remembers
	// the event and settles it on a later pass.
	CoverageWait time.Duration
	// CoveragePoll is how often that wait re-reads the log (default 15s,
	// the log's publish cadence).
	CoveragePoll time.Duration
	// PageSize is the feed page size (default 1000).
	PageSize int
	// MaxPages bounds feed pages per run; zero is unbounded. A bounded run
	// reports Truncated and resumes where it stopped.
	MaxPages int
	// Now is time.Now unless replaced.
	Now func() time.Time
	// Logf receives progress lines; nil discards them.
	Logf func(format string, args ...any)
}

// Report summarizes one pass. Failed events and a non-nil error from the
// pass are the two ways verification can fail; everything else is
// informational.
type Report struct {
	Origin string `json:"origin"`
	// Inconsistency carries the evidence of a broken append-only property,
	// when that is why the pass failed.
	Inconsistency *Inconsistency   `json:"inconsistency,omitempty"`
	Checkpoint    CheckpointReport `json:"checkpoint"`
	// PreviousSize is the tree size of the checkpoint the append-only check
	// started from; nil on a first run.
	PreviousSize *uint64     `json:"previous_size"`
	Events       EventReport `json:"events"`
	// Truncated is set when MaxPages stopped the feed read early.
	Truncated bool `json:"truncated,omitempty"`
}

// CheckpointReport describes the newest checkpoint verified in the pass.
type CheckpointReport struct {
	Size     uint64 `json:"size"`
	RootHash []byte `json:"root_hash"`
	// Note is the signed checkpoint exactly as served, so a caller can keep
	// it as its own record of what this pass verified.
	Note string `json:"note,omitempty"`
}

// EventReport tallies the events examined.
type EventReport struct {
	// Verified events have a valid inclusion proof for their rebuilt leaf.
	Verified int `json:"verified"`
	// NotLogged events were served with a null leaf index: recorded while
	// the organization had no active log. Expected before enrollment and
	// in a sealed gap. They are reported, never failed: the absence of an
	// index is served, not committed, so there is nothing to verify it
	// against.
	NotLogged []string `json:"not_logged"`
	// Pending events carry a leaf index no published checkpoint covers yet.
	Pending []string `json:"pending"`
	// Failed events could not be verified; each is a finding to escalate.
	Failed []EventFailure `json:"failed"`
	// SkippedOtherTypes counts rows that are not Access Transparency records
	// at all — other activity types in the same feed or export. They are not
	// this tool's to check, and passing over them is not a finding.
	SkippedOtherTypes int `json:"skipped_other_types"`
}

// EventFailure is one event that failed verification.
type EventFailure struct {
	ID     string  `json:"id"`
	Index  *uint64 `json:"leaf_index,omitempty"`
	Reason string  `json:"reason"`
}

// OK reports whether the pass verified everything it examined.
func (r Report) OK() bool { return len(r.Events.Failed) == 0 }

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

func (v *Verifier) logf(format string, args ...any) {
	if v.Logf != nil {
		v.Logf(format, args...)
	}
}

func orDefault[T comparable](val, def T) T {
	var zero T
	if val == zero {
		return def
	}
	return val
}

// session holds the checkpoints one pass has verified and related to each
// other by consistency proofs. latest is the newest; bySize maps every
// related checkpoint's tree size to its root hash.
type session struct {
	v  *Verifier
	st *State
	// defers is set by the pass that records pending events for a later one
	// to settle. Without it there is no later verdict, so a proof the log
	// does not serve for a covered index is settled inside the pass — by a
	// bounded re-read — rather than carried forward as pending.
	defers bool
	// coveredAtStart is the tree size a non-deferring pass began with. An
	// index at or above it was published while the pass waited, so nothing
	// the log has not served yet can be held against it; an index below it
	// is one the pass can rule on, once a bounded re-read has told replica
	// lag apart from a proof the log will not serve.
	coveredAtStart uint64
	// waited is the wall-clock this pass has already spent re-reading the
	// log. Waiting for a covering checkpoint and waiting for a proof draw
	// on one budget, so a file needing both does not wait twice over.
	waited time.Duration
	// anchored is set once this pass has proven the saved checkpoint is a
	// prefix of its history. Until then a checkpoint reached mid-proof is a
	// candidate, not something to persist over the saved anchor.
	anchored bool
	ctx      context.Context
	latest   checkpoint.Checkpoint
	bySize   map[uint64][]byte
	// noteBySize keeps the signed note behind each linked size, so a fork is
	// reported with both notes rather than as a bare assertion.
	noteBySize map[uint64][]byte
}

// start fetches and verifies the latest checkpoint and, when the state
// holds an earlier one, proves the log only appended since.
func (v *Verifier) start(ctx context.Context, st *State, rep *Report) (*session, error) {
	rep.Origin = v.Checkpoints.Origin()
	raw, err := v.Client.Checkpoint(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching checkpoint: %w", err)
	}
	cp, err := v.Checkpoints.Verify(raw)
	if err != nil {
		return nil, verr(err)
	}
	s := &session{v: v, st: st, ctx: ctx, latest: cp,
		bySize:     map[uint64][]byte{cp.Size: cp.Hash},
		noteBySize: map[uint64][]byte{cp.Size: cp.Raw},
	}
	v.logf("checkpoint: tree size %d verified (log signature, origin %s)", cp.Size, v.Checkpoints.Origin())

	if st != nil && st.Checkpoint != "" {
		old, err := checkpoint.ParseTrusted([]byte(st.Checkpoint), v.Checkpoints.Origin())
		if err != nil {
			return nil, fmt.Errorf("saved checkpoint in state: %w", err)
		}
		rep.PreviousSize = &old.Size
		if err := s.proveAppendOnly(old); err != nil {
			return nil, err
		}
		v.logf("append-only: tree size %d → %d consistent with the checkpoint saved %s", old.Size, s.latest.Size, st.VerifiedAt.UTC().Format(time.RFC3339))
	}
	// A baseline the caller brought is an additional ratchet, never a
	// replacement: it is proven a prefix of this pass's head just as the
	// saved anchor is, and neither can excuse the other.
	for _, b := range v.Baselines {
		// Through the same rollback-aware path the saved anchor takes, not a
		// plain link: a log serving a tree smaller than the baseline — the
		// wipe this feature exists to catch — must be refused, never
		// promoted to this pass's head.
		if err := s.proveAppendOnly(b.Checkpoint); err != nil {
			return nil, err
		}
		v.logf("append-only: tree size %d → %d consistent with %s", b.Checkpoint.Size, s.latest.Size, b.Label)
	}
	s.anchored = true
	// The anchor is committed here, not at the end of the pass: a log that
	// could force a later transient failure would otherwise keep everything
	// past the previously saved size rewritable.
	s.commit()
	s.report(rep)
	return s, nil
}

func (s *session) report(rep *Report) {
	rep.Checkpoint = CheckpointReport{Size: s.latest.Size, RootHash: s.latest.Hash, Note: string(s.latest.Raw)}
}

// finish records the newest verified checkpoint as the next run's anchor.
func (s *session) finish(st *State, rep *Report) {
	s.report(rep)
	if st != nil {
		st.Checkpoint = string(s.latest.Raw)
		st.VerifiedAt = s.v.now().UTC()
	}
}

// refusedProof reports whether a status is the log declining to answer for
// itself rather than a transport failure. A credential answer counts too:
// the same key fetched this pass's checkpoint a moment ago, so a 401/403
// aimed at a proof request is the log declining to prove itself, not a
// configuration problem.
func refusedProof(err error) bool {
	var se *compliance.StatusError
	if !errors.As(err, &se) {
		return false
	}
	switch se.StatusCode {
	case http.StatusNotFound, http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden:
		return true
	}
	return false
}

// classifyRefusal reads a failed consistency request. A log that will not
// serve a proof from a size it published no longer has the tree that size
// commits to, so the refusal is returned as the finding it is, with whatever
// both parties can still show for it; anything else — rate limiting, server
// faults — is a pass that could not complete.
func (s *session) classifyRefusal(err error, from uint64, older checkpoint.Checkpoint) error {
	var se *compliance.StatusError
	if !refusedProof(err) || !errors.As(err, &se) {
		return err
	}
	// The customer keeps the checkpoint the log will not stand behind, and
	// the one it serves instead: that pair is the whole finding.
	return &InconsistencyError{
		Evidence: Inconsistency{Older: noteOrPair(older), Newer: noteOrPair(s.latest)},
		Err:      fmt.Errorf("the log shrank: it will not serve a consistency proof from tree size %d (HTTP %d)", from, se.StatusCode),
	}
}

// proveAppendOnly proves that old — the saved anchor, or a baseline the
// caller brought — is a prefix of the session's latest tree.
func (s *session) proveAppendOnly(old checkpoint.Checkpoint) error {
	if old.Size > s.latest.Size {
		// The served tree is behind the one a previous pass verified. That
		// is lag only if the log can still show a head that covers the saved
		// size and prove the saved checkpoint is a prefix of it; a rollback
		// cannot. The saved checkpoint is local state, never a served
		// answer, so it may not become this pass's head on its own.
		served := s.latest
		p, head, err := s.consistencyFrom(old.Size)
		if err != nil {
			return s.classifyRefusal(err, old.Size, old)
		}
		if head.Size < old.Size {
			return &InconsistencyError{
				Evidence: Inconsistency{Older: noteOrPair(old), Newer: noteOrPair(head)},
				Err:      fmt.Errorf("the log shrank: the saved checkpoint has tree size %d, the log now serves %d", old.Size, head.Size),
			}
		}
		if err := checkpoint.VerifyConsistency(old, head, p.Hashes); err != nil {
			return inconsistent(err, old, head, p.Hashes)
		}
		s.bySize[old.Size] = old.Hash
		s.remember(old)
		s.setLatest(head)
		// The checkpoint /checkpoint served is in bySize on its signature
		// alone; prove it belongs to this history too, or a fork below the
		// saved size would sit there unchallenged. Its seeded entry has to
		// go first — otherwise link finds it and returns without asking the
		// log for anything.
		delete(s.bySize, served.Size)
		if err := s.link(served); err != nil {
			return s.classifyRefusal(err, served.Size, served)
		}
		return nil
	}
	if err := s.link(old); err != nil {
		return s.classifyRefusal(err, old.Size, old)
	}
	return nil
}

// relate verifies a checkpoint served alongside a proof and links it into
// the session's history; the returned checkpoint is safe to check that
// proof against.
func (s *session) relate(raw []byte) (checkpoint.Checkpoint, error) {
	cp, err := s.v.Checkpoints.Verify(raw)
	if err != nil {
		return checkpoint.Checkpoint{}, verr(err)
	}
	if err := s.link(cp); err != nil {
		return checkpoint.Checkpoint{}, err
	}
	return cp, nil
}

// link ties a verified checkpoint to the session's single history by
// consistency proof, so that every proof in one pass is checked against
// mutually consistent views of the log: on return cp is latest or a proven
// prefix of it. The proof endpoints answer against the log's newest
// checkpoint, which can move mid-pass; latest follows it, and a bounded
// number of rounds absorbs the movement.
func (s *session) link(cp checkpoint.Checkpoint) error {
	for range maxRelateAttempts {
		if err := s.forkCheck(cp); err != nil {
			return err
		}
		if _, ok := s.bySize[cp.Size]; ok {
			return nil
		}
		var err error
		if cp.Size > s.latest.Size {
			err = s.advance(cp)
		} else {
			err = s.provePrefix(cp)
		}
		if err != nil {
			return err
		}
	}
	if _, ok := s.bySize[cp.Size]; ok {
		return s.forkCheck(cp)
	}
	return ErrLogAdvancing
}

// forkCheck refuses a second root hash for an already-linked tree size.
func (s *session) forkCheck(cp checkpoint.Checkpoint) error {
	root, ok := s.bySize[cp.Size]
	if !ok || bytes.Equal(root, cp.Hash) {
		return nil
	}
	// Two checkpoints for one size is the plainest evidence there is, and it
	// is only evidence while both notes are in hand.
	return &InconsistencyError{
		Evidence: Inconsistency{
			Older: noteOrPair(checkpoint.Checkpoint{Size: cp.Size, Hash: root, Raw: s.noteBySize[cp.Size]}),
			Newer: noteOrPair(cp),
		},
		Err: fmt.Errorf("the log forked: two signed checkpoints for tree size %d have different root hashes", cp.Size),
	}
}

// remember records the note behind a linked tree size.
func (s *session) remember(cp checkpoint.Checkpoint) {
	if len(cp.Raw) == 0 {
		return
	}
	if s.noteBySize == nil {
		s.noteBySize = map[uint64][]byte{}
	}
	s.noteBySize[cp.Size] = cp.Raw
}

func (s *session) setLatest(cp checkpoint.Checkpoint) {
	s.bySize[cp.Size] = cp.Hash
	s.remember(cp)
	s.latest = cp
	// Committed as it advances, not at the end of the pass: a checkpoint
	// linked into this history mid-pass is as verified as the one start
	// began with, and a pass that breaks off must not leave the state
	// anchored behind it.
	s.commit()
}

// commit records the newest verified checkpoint in the state the pass was
// given, if any.
func (s *session) commit() {
	if s.st == nil || !s.anchored {
		return
	}
	s.st.Checkpoint = string(s.latest.Raw)
	s.st.VerifiedAt = s.v.now().UTC()
}

// consistencyFrom fetches the proof from tree size `from` to whatever the
// log now calls latest, and verifies that checkpoint's signatures.
func (s *session) consistencyFrom(from uint64) (compliance.Proof, checkpoint.Checkpoint, error) {
	p, err := s.v.Client.Consistency(s.ctx, from)
	if err != nil {
		return compliance.Proof{}, checkpoint.Checkpoint{}, fmt.Errorf("fetching consistency proof from tree size %d: %w", from, err)
	}
	head, err := s.v.Checkpoints.Verify(p.Checkpoint)
	if err != nil {
		return compliance.Proof{}, checkpoint.Checkpoint{}, verr(err)
	}
	return p, head, s.forkCheck(head)
}

// advance moves latest forward, by verified consistency proof, to target
// or past it. target.Size > latest.Size.
func (s *session) advance(target checkpoint.Checkpoint) error {
	if s.latest.Size == 0 {
		s.setLatest(target) // every tree extends the empty tree
		return nil
	}
	p, head, err := s.consistencyFrom(s.latest.Size)
	if err != nil {
		return s.classifyRefusal(err, s.latest.Size, s.latest)
	}
	if head.Size < target.Size {
		return nil // answered from behind target: a lagging read; go round again
	}
	if err := checkpoint.VerifyConsistency(s.latest, head, p.Hashes); err != nil {
		return inconsistent(err, s.latest, head, p.Hashes)
	}
	s.setLatest(head)
	return s.forkCheck(target)
}

// provePrefix proves cp is a prefix of latest. cp.Size < latest.Size.
func (s *session) provePrefix(cp checkpoint.Checkpoint) error {
	if cp.Size == 0 {
		s.bySize[0] = cp.Hash
		s.remember(cp)
		return nil
	}
	p, head, err := s.consistencyFrom(cp.Size)
	if err != nil {
		return s.classifyRefusal(err, cp.Size, cp)
	}
	if head.Size > s.latest.Size {
		// The log grew since latest was fetched: move latest up to head
		// first (its own proof), after which p — computed against head —
		// is the proof cp → latest.
		if err := s.advance(head); err != nil {
			return err
		}
	}
	if !head.SameTree(s.latest) {
		return nil // lagging or moved again; go round again
	}
	if err := checkpoint.VerifyConsistency(cp, s.latest, p.Hashes); err != nil {
		return inconsistent(err, cp, s.latest, p.Hashes)
	}
	s.bySize[cp.Size] = cp.Hash
	s.remember(cp)
	return nil
}

type outcome int

const (
	verified outcome = iota
	notLogged
	pending
)

// verifyEvent verifies one parsed event's inclusion. A returned
// *EventFailure is a finding about this event; error aborts the pass.
func (s *session) verifyEvent(ev leaf.Event) (outcome, *EventFailure, error) {
	fail := func(format string, args ...any) (outcome, *EventFailure, error) {
		return 0, &EventFailure{ID: ev.ID, Index: ev.Index, Reason: fmt.Sprintf(format, args...)}, nil
	}
	if org := s.v.Checkpoints.OrgUUID(); ev.OrganizationUUID != org {
		return fail("event belongs to organization %q, not the pinned log's %q", ev.OrganizationUUID, org)
	}
	if ev.Index == nil {
		return notLogged, nil, nil
	}
	if *ev.Index >= s.latest.Size {
		return pending, nil, nil
	}
	return s.verifyInclusion(ev.ID, *ev.Index, ev.Hash())
}

func (s *session) verifyInclusion(id string, idx uint64, leafHash []byte) (outcome, *EventFailure, error) {
	p, err := s.v.Client.Inclusion(s.ctx, idx)
	// The checkpoint covers idx, so the proof must exist — but an inclusion
	// replica behind the checkpoint read answers 404 for a freshly covered
	// index, exactly as a log withholding the proof does. A pass that
	// records the event settles that on the grace deadline. A pass that
	// records nothing has only itself, so it re-reads the endpoint for as
	// long as its wait budget allows: an answer that arrives is lag, and
	// silence to the end of the wait is the log declining.
	if compliance.IsNotFound(err) && !s.defers && idx < s.coveredAtStart {
		if perr := s.pollLog(func() (bool, error) {
			p, err = s.v.Client.Inclusion(s.ctx, idx)
			return !compliance.IsNotFound(err), nil
		}); perr != nil {
			return 0, nil, perr
		}
	}
	if compliance.IsNotFound(err) {
		if !s.defers && idx < s.coveredAtStart {
			return 0, &EventFailure{ID: id, Index: &idx, Reason: fmt.Sprintf("the verified checkpoint (tree size %d) covers leaf index %d but the log serves no proof for it", s.latest.Size, idx)}, nil
		}
		return pending, nil, nil
	}
	if err != nil {
		// A log that answers this request with a refusal is declining to
		// prove one event, which is the evasion this tool exists to catch —
		// not a transport problem, and not the operator's mistake.
		if refusedProof(err) {
			return 0, &EventFailure{ID: id, Index: &idx, Reason: fmt.Sprintf("the log will not prove this event's inclusion at leaf index %d: %s", idx, err)}, nil
		}
		return 0, nil, fmt.Errorf("fetching inclusion proof for leaf index %d: %w", idx, err)
	}
	if p.LeafIndex != idx {
		// Answering for a different leaf is this event's finding, not a
		// transport problem: a log that keeps doing it would otherwise hold
		// the tool at "rerun" forever, with no FAILED line for the event it
		// is declining to prove.
		return 0, &EventFailure{ID: id, Index: &idx, Reason: fmt.Sprintf("the log answered the inclusion request for leaf index %d with a proof for leaf index %d", idx, p.LeafIndex)}, nil
	}
	cp, err := s.relate(p.Checkpoint)
	if err != nil {
		return 0, nil, err
	}
	if err := checkpoint.VerifyInclusion(cp, idx, leafHash, p.Hashes); err != nil {
		//nolint:nilerr // a bad proof is a finding about this event, not a pass-aborting error
		return 0, &EventFailure{ID: id, Index: &idx, Reason: "the event as served is not what the log committed at its leaf index: " + err.Error()}, nil
	}
	return verified, nil, nil
}

// VerifyCheckpoint fetches and verifies the latest checkpoint and, given a
// state with an earlier one, the append-only property since. On success
// the state's checkpoint advances.
func (v *Verifier) VerifyCheckpoint(ctx context.Context, st *State) (Report, error) {
	var rep Report
	s, err := v.start(ctx, st, &rep)
	if err != nil {
		return rep, err
	}
	s.finish(st, &rep)
	return rep, nil
}

// VerifyEvents verifies served events supplied by the caller (a feed page,
// a SIEM export). st may be nil; when given, the append-only check runs
// and the state's checkpoint advances.
func (v *Verifier) VerifyEvents(ctx context.Context, st *State, events []json.RawMessage) (Report, error) {
	var rep Report
	s, err := v.start(ctx, st, &rep)
	if err != nil {
		return rep, err
	}
	seen := map[string]leaf.Event{}
	parsed := make([]leaf.Event, 0, len(events))
	for i, raw := range events {
		// A raw activities page or a SIEM export carries other activity
		// types; those rows are somebody else's to check. The probe is the
		// same strict decode Parse performs, so a row that decodes two ways —
		// a repeated member, a member differing only in case — is a finding
		// rather than something to pass over, and anything claiming one of
		// our type names still goes through Parse so a schema this build does
		// not know fails loudly.
		typ, terr := leaf.TypeOf(raw)
		switch {
		case terr != nil:
			rep.Events.Failed = append(rep.Events.Failed, EventFailure{ID: eventID(raw, i), Reason: "cannot rebuild leaf: " + terr.Error()})
			continue
		case !leaf.ClaimsOurType(typ):
			rep.Events.SkippedOtherTypes++
			continue
		}
		ev, err := leaf.Parse(raw)
		if err != nil {
			rep.Events.Failed = append(rep.Events.Failed, EventFailure{ID: eventID(raw, i), Reason: "cannot rebuild leaf: " + err.Error()})
			continue
		}
		// One id claiming two positions is a contradiction no proof settles,
		// and both proofs verify on their own — the index is not committed
		// in the leaf, so only an id-level check catches it. `run` refuses
		// the same input.
		prev, dup := seen[ev.ID]
		bothPlaced := dup && prev.Index != nil && ev.Index != nil
		switch {
		case bothPlaced && *prev.Index != *ev.Index:
			rep.Events.Failed = append(rep.Events.Failed, EventFailure{ID: ev.ID, Index: prev.Index, Reason: fmt.Sprintf("supplied twice at different leaf indices %d and %d", *prev.Index, *ev.Index)})
			continue
		case bothPlaced && !bytes.Equal(prev.Hash(), ev.Hash()):
			rep.Events.Failed = append(rep.Events.Failed, EventFailure{ID: ev.ID, Index: prev.Index, Reason: fmt.Sprintf("supplied twice at leaf index %d with different content", *prev.Index)})
			continue
		}
		if !dup || (prev.Index == nil && ev.Index != nil) {
			// A null-index copy never displaces a remembered position, or
			// interleaving one would launder the contradiction.
			seen[ev.ID] = ev
		}
		parsed = append(parsed, ev)
	}
	// Every event is parsed before any is verified so the whole file waits
	// on one covering checkpoint rather than each event waiting in turn.
	s.coveredAtStart = s.latest.Size
	want, err := s.awaitCoverage(parsed)
	if err != nil {
		return rep, err
	}
	var deferred []leaf.Event
	for _, ev := range parsed {
		oc, failure, err := s.verifyEvent(ev)
		if err != nil {
			return rep, err
		}
		if failure == nil && oc == pending {
			deferred = append(deferred, ev) // held back for the second look below
			continue
		}
		rep.tally(ev.ID, oc, failure)
	}
	// A proof is answered against the log's newest tree, which can be ahead
	// of what the checkpoint endpoint serves, so verifying one event can
	// advance this pass's head past an event judged pending before it.
	// Judging those again against the head the pass ends on keeps the
	// verdict off the order the file happens to list its rows in. One more
	// round settles it: that advance carries the head to the log's newest
	// tree, so an index still beyond it is beyond the log, not beyond this
	// pass.
	for _, ev := range deferred {
		oc, failure, err := s.verifyEvent(ev)
		if err != nil {
			return rep, err
		}
		rep.tally(ev.ID, oc, failure)
	}
	s.finish(st, &rep)
	if n := len(rep.Events.Pending); n > 0 {
		// Not a finding: an index no published checkpoint covers, and one
		// published so recently that its proof has not replicated, are both
		// what a freshly stamped event looks like. Nothing here records
		// either for a later pass to settle, so the rerun is the operator's
		// and the pass ends as one that could not complete rather than one
		// that verified everything it was given.
		if want > rep.Checkpoint.Size {
			return rep, fmt.Errorf("no checkpoint published within %s covers leaf index %d (latest tree size %d); %d event(s) could not be checked — re-run later, and treat it as a finding if it persists", orDefault(v.CoverageWait, defaultCoverageWait), want-1, rep.Checkpoint.Size, n)
		}
		return rep, fmt.Errorf("%d event(s) sit at a leaf index this check saw published (tree size %d) but the log serves no proof for yet — re-run later, and treat it as a finding if it persists", n, rep.Checkpoint.Size)
	}
	return rep, nil
}

// awaitCoverage waits for the log to publish a checkpoint covering the
// largest leaf index this pass was handed. It returns the tree size that
// takes — one past that index, or zero for a file carrying none. A pass
// that records nothing has no later verdict to give, so it waits out the
// log's publish cadence here rather than ruling on an index a checkpoint
// minutes away would settle. Each re-read is signature-verified and proven
// an extension of the checkpoint already held, by the same path every other
// checkpoint in the pass takes, and becomes the pass's head.
func (s *session) awaitCoverage(evs []leaf.Event) (uint64, error) {
	var want uint64
	for _, ev := range evs {
		if ev.Index != nil && *ev.Index+1 > want {
			want = *ev.Index + 1
		}
	}
	if s.latest.Size >= want {
		return want, nil
	}
	return want, s.pollLog(func() (bool, error) {
		raw, err := s.v.Client.Checkpoint(s.ctx)
		if err != nil {
			return false, fmt.Errorf("fetching checkpoint: %w", err)
		}
		held := s.latest.Size
		if _, err := s.relate(raw); err != nil {
			return false, err
		}
		if s.latest.Size > held {
			s.v.logf("checkpoint: tree size %d verified while waiting for leaf index %d", s.latest.Size, want-1)
		}
		return s.latest.Size >= want, nil
	})
}

// pollLog re-reads the log in poll-sized steps until try reports it has what
// it came for, this pass's wait budget is spent, or something fails. The
// budget is the pass's, not the caller's, so a file that waits for a
// checkpoint and then for a proof waits once in total rather than twice.
func (s *session) pollLog(try func() (bool, error)) error {
	poll := orDefault(s.v.CoveragePoll, defaultCoveragePoll)
	budget := orDefault(s.v.CoverageWait, defaultCoverageWait)
	for s.waited+poll <= budget {
		select {
		case <-s.ctx.Done():
			return s.ctx.Err()
		case <-time.After(poll):
		}
		s.waited += poll
		done, err := try()
		if err != nil || done {
			return err
		}
	}
	return nil
}

func (rep *Report) tally(id string, oc outcome, failure *EventFailure) {
	switch {
	case failure != nil:
		rep.Events.Failed = append(rep.Events.Failed, *failure)
	case oc == verified:
		rep.Events.Verified++
	case oc == notLogged:
		rep.Events.NotLogged = append(rep.Events.NotLogged, id)
	case oc == pending:
		rep.Events.Pending = append(rep.Events.Pending, id)
	}
}

// servedEvent is one activity as the feed served it, after the copies of one
// id have been collapsed.
type servedEvent struct {
	ev      leaf.Event
	created time.Time
	// conflict is set when the page served this id at two different leaf
	// indices — a contradiction no proof can settle.
	conflict *EventFailure
}

// coalesce collapses the copies of one activity id a single page may carry.
// The feed serves an event twice around the moment its leaf index is stamped
// — once with a null index, once with the real one — and the API's contract
// is that a reader deduplicates by id. The indexed copy therefore supersedes
// a null-index one, whatever order they arrive in, so the verdict does not
// depend on the order the page happens to use; only two different non-null
// indices for one id are a finding.
func coalesce(raws []json.RawMessage) ([]servedEvent, []EventFailure) {
	out := make([]servedEvent, 0, len(raws))
	at := map[string]int{}
	var bad []EventFailure
	for i, raw := range raws {
		ev, err := leaf.Parse(raw)
		if err != nil {
			bad = append(bad, EventFailure{ID: eventID(raw, i), Reason: "cannot rebuild leaf: " + err.Error()})
			continue
		}
		se := servedEvent{ev: ev, created: createdAt(raw)}
		j, dup := at[ev.ID]
		if !dup {
			at[ev.ID] = len(out)
			out = append(out, se)
			continue
		}
		cur := out[j]
		switch {
		case cur.conflict != nil:
		case cur.ev.Index != nil && ev.Index != nil && *cur.ev.Index != *ev.Index:
			out[j].conflict = &EventFailure{ID: ev.ID, Index: cur.ev.Index, Reason: fmt.Sprintf("served twice in one page at different leaf indices %d and %d", *cur.ev.Index, *ev.Index)}
		case cur.ev.Index != nil && ev.Index != nil && !bytes.Equal(cur.ev.Hash(), ev.Hash()):
			// Both copies claim the same position in the log, so both claim
			// the log committed them; they cannot both be right. Content
			// differences against a null-index copy are not this case — that
			// copy claims nothing, and the indexed one is what gets checked.
			out[j].conflict = &EventFailure{ID: ev.ID, Index: cur.ev.Index, Reason: fmt.Sprintf("served twice in one page at leaf index %d with different content", *cur.ev.Index)}
		case cur.ev.Index == nil && ev.Index != nil:
			se.created = cur.created // the earlier copy's place in the window
			out[j] = se
		}
	}
	return out, bad
}

// recheckDone examines an event the state already recorded Done that the
// overlap window has listed again. The window protects nothing if a later
// serving of the same id can ride on the earlier success: different bytes go
// back through the full inclusion check, and an index the serving path has
// since withdrawn is a finding by itself — the index is not committed in the
// leaf, so withdrawing it changes no hash to catch.
func recheckDone(d DoneEvent, ev leaf.Event) (reverify bool, failure *EventFailure) {
	switch {
	case d.Index != nil && ev.Index == nil:
		return false, &EventFailure{ID: ev.ID, Index: d.Index, Reason: fmt.Sprintf("verified at leaf index %d on an earlier run and is now served without a leaf index", *d.Index)}
	case d.Index != nil && ev.Index != nil && *d.Index != *ev.Index:
		return false, &EventFailure{ID: ev.ID, Index: d.Index, Reason: fmt.Sprintf("verified at leaf index %d on an earlier run and is now served at leaf index %d", *d.Index, *ev.Index)}
	case !bytes.Equal(d.LeafHash, ev.Hash()):
		// An entry with no hash vouches for nothing, so it re-verifies too.
		return true, nil
	default:
		return false, nil
	}
}

// eventID names an unparseable event for the report.
func eventID(raw json.RawMessage, i int) string {
	var probe struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(raw, &probe) == nil && probe.ID != "" {
		return probe.ID
	}
	return fmt.Sprintf("input event #%d", i+1)
}

// Run is the scheduled pass: verify the latest checkpoint and the
// append-only property, then read the organization's Access Transparency
// events from the activity feed — everything since the last run, plus an
// overlap window — and verify each one's inclusion. Progress is recorded
// in st, which the caller saves.
func (v *Verifier) Run(ctx context.Context, st *State) (Report, error) {
	var rep Report
	s, err := v.start(ctx, st, &rep)
	if err != nil {
		return rep, err
	}
	s.defers = true
	now := v.now()
	// Negative would put the window ahead of the mark: every later pass
	// would list nothing, prune every recorded event, and exit 0.
	if v.Overlap < 0 || v.PendingGrace < 0 {
		return rep, errors.New("the overlap window and pending grace must not be negative")
	}
	overlap := orDefault(v.Overlap, defaultOverlap)
	grace := orDefault(v.PendingGrace, defaultPendingGrace)

	listed := map[string]bool{}
	seen := map[string]bool{}
	copies := map[string]bool{}
	cursors := map[string]int{}
	seenThisPass := map[string]servedEvent{}
	withdrawn := map[string]EventFailure{}
	reverifying := map[string]bool{}

	// retract withdraws what the superseded null-index copy itself
	// reported; a failure another copy of the id earned stands.
	retract := func(id string) {
		rep.Events.NotLogged = slices.DeleteFunc(rep.Events.NotLogged, func(x string) bool { return x == id })
		rep.Events.Pending = slices.DeleteFunc(rep.Events.Pending, func(x string) bool { return x == id })
		delete(withdrawn, id)
	}

	// fail records a finding. Every failure goes through here so the record
	// that catches the next serving is kept alive: retention runs on
	// wall-clock time whether or not a finding is open.
	fail := func(f EventFailure) {
		rep.Events.Failed = append(rep.Events.Failed, f)
		listed[f.ID] = true
		if d, ok := st.Feed.Done[f.ID]; ok {
			d.RecordedAt = now
			st.Feed.Done[f.ID] = d
		}
	}

	// settle records a verified/not-logged/pending outcome in the report
	// and the state; an event pending past the grace period becomes a
	// failure.
	settle := func(id string, oc outcome, failure *EventFailure, pe PendingEvent) {
		// A pending event's stored hash and index are what a later pass
		// verifies it from, so a rewrite before coverage must not quietly
		// replace them.
		if failure == nil && oc == pending {
			if old, ok := st.Feed.Pending[id]; ok && (!bytes.Equal(old.LeafHash, pe.LeafHash) || old.Index != pe.Index) {
				failure = &EventFailure{ID: id, Index: &old.Index, Reason: fmt.Sprintf("was served at leaf index %d awaiting a checkpoint and is now served differently (leaf index %d)", old.Index, pe.Index)}
			}
		}
		if failure == nil && oc == pending {
			if old, ok := st.Feed.Pending[id]; ok && now.Sub(old.FirstSeen) > grace {
				failure = &EventFailure{ID: id, Index: &pe.Index, Reason: fmt.Sprintf("leaf index %d still not covered by a published checkpoint (tree size %d) %s after the event was first seen", pe.Index, s.latest.Size, now.Sub(old.FirstSeen).Truncate(time.Minute))}
			}
		}
		// A verified serving that retires a pending entry recorded from
		// different bytes would otherwise reset the grace deadline every
		// time, so alternating tampered and honest servings never expire.
		if failure == nil && oc == verified {
			if old, ok := st.Feed.Pending[id]; ok && (!bytes.Equal(old.LeafHash, pe.LeafHash) || old.Index != pe.Index) {
				failure = &EventFailure{ID: id, Index: &old.Index, Reason: fmt.Sprintf("was served awaiting a checkpoint at leaf index %d, and the serving that now verifies differs from it (leaf index %d)", old.Index, pe.Index)}
			}
		}
		// An index claimed on an earlier run and withdrawn now would
		// otherwise retire the grace deadline the claim started.
		if failure == nil && oc == notLogged {
			if old, ok := st.Feed.Pending[id]; ok {
				// Deferred like the recorded-event case: the copy carrying
				// the index may still be on a later page.
				withdrawn[id] = EventFailure{ID: id, Index: &old.Index, Reason: fmt.Sprintf("claimed leaf index %d on an earlier run and is now served without a leaf index", old.Index)}
			}
		}
		rep.tally(id, oc, failure)
		switch {
		case failure != nil:
			// Retention runs on wall-clock time whether or not a finding is
			// open, so keep any record of this id alive: it is what catches
			// the next serving, and the pass that reports a failure must not
			// be the one that forgets the event.
			if d, ok := st.Feed.Done[id]; ok {
				d.RecordedAt = now
				st.Feed.Done[id] = d
			}
		case oc == pending:
			st.Feed.pend(id, pe)
		case oc == notLogged:
			// Not recorded Done: the index is not part of the leaf, so
			// nulling it costs a serving path nothing. Re-examine the event
			// on every run the window still lists it.
			delete(st.Feed.Done, id)
		default:
			st.Feed.done(id, DoneEvent{CreatedAt: pe.CreatedAt, RecordedAt: now, Index: &pe.Index, LeafHash: pe.LeafHash})
		}
	}

	var readErr error
	// feedComplete records that the feed itself was read to its end. A
	// failure in the pending re-check afterwards leaves the pass incomplete
	// but says nothing about whether a copy carrying an index was listed.
	feedComplete := false
	var notBefore time.Time
	if !st.Feed.HighWater.IsZero() {
		notBefore = st.Feed.HighWater.Add(-overlap)
	}
	q := compliance.FeedQuery{Types: leaf.Types(), NotBefore: notBefore, Limit: orDefault(v.PageSize, defaultPageSize)}
	highWater := st.Feed.HighWater
	for page := 1; ; page++ {
		if v.MaxPages > 0 && page > v.MaxPages {
			rep.Truncated = true
			v.logf("feed: stopped after %d pages (page limit); rerun to continue", v.MaxPages)
			break
		}
		pg, err := v.Client.Activities(ctx, q)
		if err != nil {
			readErr = fmt.Errorf("listing activities: %w", err)
			break
		}
		coalesced, badLeaves := coalesce(pg.Events)
		freshPage := false
		for _, se := range coalesced {
			key := se.ev.ID + "|" + string(se.ev.Hash())
			if se.ev.Index != nil {
				key += "|" + strconv.FormatUint(*se.ev.Index, 10)
			}
			if !copies[key] {
				copies[key] = true
				freshPage = true
			}
		}
		for _, f := range badLeaves {
			// Listed, though it did not parse: the pending fallback must not
			// settle this id from the honest leaf hash it stored earlier
			// while the form served now verifies nothing.
			fail(f)
		}
		for _, se := range coalesced {
			ev, created := se.ev, se.created
			// The high-water mark sets where the next run's window starts and
			// what prune() forgets, so a served timestamp may never carry it
			// past this clock: one far-future created_at would otherwise empty
			// every later window permanently.
			if created.After(highWater) && !created.After(now.Add(maxFutureSkew)) {
				highWater = created
			}
			if se.conflict != nil {
				fail(*se.conflict)
				continue
			}
			// A copy of an id this pass already settled. The feed serves an
			// event twice around the moment its leaf index is stamped, and
			// the API's contract is that a reader deduplicates by id, so a
			// second copy is news only when it carries an index the first
			// one did not — or a different one, which no log can resolve.
			if prev, ok := seenThisPass[ev.ID]; ok {
				switch {
				case prev.ev.Index != nil && ev.Index != nil && *prev.ev.Index != *ev.Index:
					fail(EventFailure{ID: ev.ID, Index: prev.ev.Index, Reason: fmt.Sprintf("served twice in one pass at different leaf indices %d and %d", *prev.ev.Index, *ev.Index)})
					continue
				case prev.ev.Index != nil && ev.Index != nil && !bytes.Equal(prev.ev.Hash(), ev.Hash()):
					fail(EventFailure{ID: ev.ID, Index: prev.ev.Index, Reason: fmt.Sprintf("served twice in one pass at leaf index %d with different content", *prev.ev.Index)})
					continue
				case prev.ev.Index != nil || ev.Index == nil:
					continue
				}
				// The indexed copy supersedes a null-index one this pass
				// already reported, wherever the paging put them: one
				// activity gets one outcome, and not the one reported for
				// the copy that claimed no position.
				retract(ev.ID)
			}
			seenThisPass[ev.ID] = se
			if d, ok := st.Feed.Done[ev.ID]; ok {
				reverify, failure := recheckDone(d, ev)
				switch {
				case failure != nil && ev.Index == nil:
					// A withdrawal verdict waits for the whole pass: paging
					// can split the cutover pair that serves one event with
					// and without its index across two pages, and the copy
					// carrying the index may still be ahead.
					withdrawn[ev.ID] = *failure
					continue
				case failure != nil:
					fail(*failure)
					continue
				case !reverify:
					// Still being listed, so keep the record that catches a
					// later withdrawal alive for another window.
					d.RecordedAt = now
					st.Feed.Done[ev.ID] = d
					continue
				}
				// The recorded entry stays until the newly served bytes
				// verify — settle replaces it then. Dropping it here would
				// leave nothing to catch the next serving with.
				reverifying[ev.ID] = true
			}
			listed[ev.ID] = true
			oc, failure, err := s.verifyEvent(ev)
			if err != nil {
				// Same exit as any other read that broke off: the deferral
				// below has to run before this returns.
				readErr = err
				break
			}
			if reverifying[ev.ID] && failure == nil && oc == pending {
				// This event verified once at this index and is now served
				// with different bytes. A missing proof is not a replica
				// behind the checkpoint read; it is the log declining to
				// stand behind what was just served.
				failure = &EventFailure{ID: ev.ID, Index: ev.Index, Reason: "re-served with different content than the copy that verified, and the log serves no proof for it"}
				oc = 0
			}
			pe := PendingEvent{LeafHash: ev.Hash(), CreatedAt: created, FirstSeen: now}
			if ev.Index != nil {
				pe.Index = *ev.Index
			}
			settle(ev.ID, oc, failure, pe)
		}
		if readErr != nil {
			break
		}
		v.logf("feed: page %d: %d events", page, len(pg.Events))
		if !pg.HasMore {
			feedComplete = true
			break
		}
		// No cursor sequence may page forever: a run that never exits raises
		// no alarm at all, the one outcome this tool must not have. A repeat
		// is a stall only when the page also carried no copy this pass had
		// not already read — the cursor names an activity id, and a page
		// boundary can fall between two copies of one id, which repeats the
		// cursor legitimately while still making progress.
		if pg.LastID == "" || cursors[pg.LastID] >= 2 || (seen[pg.LastID] && !freshPage) {
			readErr = fmt.Errorf("%w: activities: page %d reports more results but the cursor did not advance", compliance.ErrResponse, page)
			break
		}
		if len(seen) >= maxFeedPages {
			readErr = fmt.Errorf("%w: activities: the feed served %d pages without ending; use --max-pages to read it in bounded runs", compliance.ErrResponse, maxFeedPages)
			break
		}
		seen[pg.LastID] = true
		cursors[pg.LastID]++
		q.AfterID = pg.LastID
	}
	// Pending events the feed pass did not list again (outside the window,
	// or a truncated pass) are checked from their stored leaf hash.
	for _, id := range slices.Sorted(maps.Keys(st.Feed.Pending)) {
		if listed[id] || readErr != nil {
			continue
		}
		pe := st.Feed.Pending[id]
		oc, failure := pending, (*EventFailure)(nil)
		if pe.Index < s.latest.Size {
			var err error
			if oc, failure, err = s.verifyInclusion(id, pe.Index, pe.LeafHash); err != nil {
				// Breaking off here leaves the pass as incomplete as a cut
				// feed read does, so it takes the same exit: the deferral
				// below has to run before this returns.
				readErr = err
				continue
			}
		}
		settle(id, oc, failure, pe)
	}
	// A pass that did not read the feed to the end — a page cap, or a read
	// that broke off — cannot conclude that no copy carrying the index
	// exists, so verdicts a record contests wait for a pass that does. Only
	// those: a first sighting of an event with no leaf is contested by
	// nothing, and deferring every one would freeze the window on any
	// backlog that has them.
	deferred := false
	if rep.Truncated || !feedComplete {
		deferred = len(withdrawn) > 0
		for id := range withdrawn {
			retract(id)
		}
	}
	// A withdrawal stands only if no copy carrying the index turned up
	// anywhere in this pass.
	for _, id := range slices.Sorted(maps.Keys(withdrawn)) {
		if se, ok := seenThisPass[id]; ok && se.ev.Index != nil {
			continue
		}
		f := withdrawn[id]
		retract(id)
		fail(f)
	}
	// An unresolved failure, or a deferred verdict, freezes the window where
	// it already was: the window is the only thing that lists an event
	// again, so a finding must not age out of it into a clean exit 0 and a
	// deferral must not become a deletion. Freezing uses the mark this pass
	// started from, never a served timestamp.
	if len(rep.Events.Failed) > 0 || deferred {
		highWater = st.Feed.HighWater
	}
	// What actually went wrong outranks how the pass was configured: a
	// forged checkpoint reached through a pending id's proof must not come
	// back as "raise --max-pages".
	if readErr != nil {
		return rep, readErr
	}
	// Decided on the mark that will actually be saved: a truncated pass that
	// leaves it where it was repeats itself forever, and would otherwise
	// report only "truncated" while doing it.
	if rep.Truncated && !highWater.After(st.Feed.HighWater) {
		return rep, errors.New("the page limit was reached before the feed passed the previous pass's high-water mark; raise --max-pages, or every later pass re-reads the same events and never reaches newer ones")
	}
	st.Feed.HighWater = highWater
	st.Feed.prune(now.Add(-overlap))
	s.finish(st, &rep)
	return rep, nil
}

func createdAt(raw json.RawMessage) time.Time {
	var probe struct {
		CreatedAt time.Time `json:"created_at"`
	}
	_ = json.Unmarshal(raw, &probe)
	return probe.CreatedAt
}
