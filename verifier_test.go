// Copyright 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package axtverify_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anthropics/axt-verify"
	"github.com/anthropics/axt-verify/checkpoint"
	"github.com/anthropics/axt-verify/compliance"
	"github.com/anthropics/axt-verify/internal/testlog"
	"github.com/anthropics/axt-verify/leaf"
)

const IndexKey = leaf.IndexKey

var t0 = time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)

// env is one organization's fake log + API and a verifier pinned to it.
type env struct {
	t     *testing.T
	log   *testlog.Log
	srv   *testlog.Server
	v     *axtverify.Verifier
	st    *axtverify.State
	clock time.Time
	n     int // events minted so far
}

func newEnv(t *testing.T) *env {
	t.Helper()
	l := testlog.New(origin)
	srv := testlog.NewServer(l)
	t.Cleanup(srv.Close)
	cpv, err := checkpoint.New(checkpoint.Policy{Origin: origin, LogKey: l.Key.VKey})
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, log: l, srv: srv, clock: t0.Add(30 * 24 * time.Hour)}
	e.v = &axtverify.Verifier{
		Checkpoints: cpv,
		Client: &compliance.Client{
			BaseURL: srv.HTTP.URL, APIKey: testlog.APIKey, OrgUUID: orgUUID, HTTP: srv.Client(),
			Sleep: func(context.Context, time.Duration) {},
		},
		Now:  func() time.Time { return e.clock },
		Logf: func(f string, a ...any) { t.Logf(f, a...) },
	}
	e.st, err = axtverify.LoadState(filepath.Join(t.TempDir(), "state"), origin)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// served mints the next event as the feed serves it. A non-nil index is
// stamped as transparency_log_leaf_index but nothing is appended.
func (e *env) served(index *uint64) json.RawMessage {
	e.n++
	ev := map[string]any{
		"id":                  fmt.Sprintf("activity_%04d", e.n),
		"type":                leaf.Types()[e.n%2],
		"created_at":          t0.Add(time.Duration(e.n) * time.Hour).Format(time.RFC3339Nano),
		"accessed_at":         "2026-07-31T23:59:58.123Z",
		"organization_id":     "org_015gtSHLz269eTwgrH8NX5yk",
		"organization_uuid":   orgUUID,
		"workspace_id":        nil,
		"workspace_uuid":      nil,
		"accessor_department": "Trust & Safety",
		"reason_code":         "safety_review",
		"actor":               map[string]any{"type": "anthropic_actor", "email_address": nil},
		"resource_details":    map[string]any{"type": "message", "id": fmt.Sprintf("msg_%04d", e.n)},
		IndexKey:              index,
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		e.t.Fatal(err)
	}
	return raw
}

// logged mints n events, appends their leaves to the log, stamps their
// indices, and adds them to the feed. It does not publish a checkpoint.
func (e *env) logged(n int) []json.RawMessage {
	var out []json.RawMessage
	for range n {
		idx := e.log.Size()
		raw := e.served(&idx)
		ev, err := leaf.Parse(raw)
		if err != nil {
			e.t.Fatal(err)
		}
		if got := e.log.Append(ev.Entry); got != idx {
			e.t.Fatalf("appended at %d, want %d", got, idx)
		}
		e.srv.Events = append(e.srv.Events, raw)
		out = append(out, raw)
	}
	return out
}

func (e *env) run() (axtverify.Report, error) {
	e.t.Helper()
	rep, err := e.v.Run(context.Background(), e.st)
	e.t.Logf("run → %+v err=%v", rep.Events, err)
	return rep, err
}

func (e *env) mustRun() axtverify.Report {
	e.t.Helper()
	rep, err := e.run()
	if err != nil {
		e.t.Fatal(err)
	}
	if !rep.OK() {
		e.t.Fatalf("failed events: %+v", rep.Events.Failed)
	}
	return rep
}

func TestRun_VerifiesFeedAndAdvancesState(t *testing.T) {
	e := newEnv(t)
	e.logged(5)
	e.srv.Publish()

	rep := e.mustRun()
	if rep.Events.Verified != 5 || rep.Checkpoint.Size != 5 || rep.PreviousSize != nil {
		t.Fatalf("first run: %+v", rep)
	}
	if e.st.Checkpoint == "" || len(e.st.Feed.Done) != 5 || !e.st.Feed.HighWater.Equal(t0.Add(5*time.Hour)) {
		t.Fatalf("state after first run: %+v", e.st)
	}

	e.logged(3)
	e.srv.Publish()
	e.clock = e.clock.Add(time.Hour)
	rep = e.mustRun()
	if rep.Events.Verified != 3 || *rep.PreviousSize != 5 || rep.Checkpoint.Size != 8 {
		t.Fatalf("second run: %+v", rep)
	}
	if e.srv.Requests["consistency"] == 0 {
		t.Fatal("append-only check made no consistency request")
	}

	// Nothing new: no inclusion requests, same checkpoint.
	before := e.srv.Requests["inclusion"]
	rep = e.mustRun()
	if rep.Events.Verified != 0 || e.srv.Requests["inclusion"] != before || *rep.PreviousSize != 8 {
		t.Fatalf("idle run: %+v (inclusion requests %d→%d)", rep, before, e.srv.Requests["inclusion"])
	}
}

func TestRun_TamperedServedEventFails(t *testing.T) {
	e := newEnv(t)
	evs := e.logged(4)
	e.srv.Publish()
	// The feed now serves event 2 with a different reason code than the
	// log committed.
	e.srv.Events[2] = json.RawMessage(strings.Replace(string(evs[2]), `"safety_review"`, `"incident_response"`, 1))

	rep, err := e.run()
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK() || len(rep.Events.Failed) != 1 || rep.Events.Failed[0].ID != "activity_0003" || rep.Events.Verified != 3 {
		t.Fatalf("report: %+v", rep.Events)
	}
	if !strings.Contains(rep.Events.Failed[0].Reason, "not what the log committed") {
		t.Fatalf("reason: %s", rep.Events.Failed[0].Reason)
	}
	// A failed event is not Done: the next run re-examines it.
	if _, done := e.st.Feed.Done["activity_0003"]; done {
		t.Fatal("failed event recorded as done")
	}
	rep, _ = e.run()
	if len(rep.Events.Failed) != 1 {
		t.Fatalf("rerun: %+v", rep.Events)
	}
}

func TestRun_ServerLies(t *testing.T) {
	t.Run("proof for another leaf", func(t *testing.T) {
		e := newEnv(t)
		e.logged(4)
		e.srv.Publish()
		e.srv.InclusionLeafSwap = map[uint64]uint64{1: 2}
		rep, err := e.run()
		if err != nil || len(rep.Events.Failed) != 1 || *rep.Events.Failed[0].Index != 1 {
			t.Fatalf("rep=%+v err=%v", rep.Events, err)
		}
	})
	t.Run("covered index has no proof", func(t *testing.T) {
		// A replica behind the checkpoint read answers the same 404 as a
		// proof that will never exist, so the grace deadline decides.
		e := newEnv(t)
		e.logged(4)
		e.srv.Publish()
		e.srv.InclusionAgainst = map[uint64]uint64{3: 3} // 404 for index 3 despite tree size 4
		rep, err := e.run()
		if err != nil || len(rep.Events.Failed) != 0 || len(rep.Events.Pending) != 1 {
			t.Fatalf("rep=%+v err=%v", rep.Events, err)
		}
		e.clock = e.clock.Add(25 * time.Hour)
		rep, err = e.run()
		if err != nil || len(rep.Events.Failed) != 1 || !strings.Contains(rep.Events.Failed[0].Reason, "still not covered") {
			t.Fatalf("after the grace period: rep=%+v err=%v", rep.Events, err)
		}
	})
	t.Run("rollback", func(t *testing.T) {
		e := newEnv(t)
		e.logged(6)
		e.srv.Publish()
		e.mustRun()
		e.srv.Published = 4
		_, err := e.run()
		requireVerification(t, err, "shrank")
	})
	t.Run("fork at equal size", func(t *testing.T) {
		e := newEnv(t)
		e.logged(6)
		e.srv.Publish()
		e.mustRun()
		e.srv.CheckpointOverride = e.log.CheckpointFor(origin, 6, make([]byte, 32))
		_, err := e.run()
		requireVerification(t, err, "forked")
	})
	t.Run("bad consistency proof", func(t *testing.T) {
		e := newEnv(t)
		e.logged(6)
		e.srv.Publish()
		e.mustRun()
		e.logged(3)
		e.srv.Publish()
		e.srv.ConsistencyGarbage = true
		_, err := e.run()
		requireVerification(t, err, "consistency")
	})
	t.Run("forged checkpoint signature", func(t *testing.T) {
		e := newEnv(t)
		e.logged(2)
		e.srv.Publish()
		e.srv.CheckpointOverride = testlog.New(origin).CheckpointFor(origin, 2, e.log.RootAt(2))
		_, err := e.run()
		requireVerification(t, err, "signature")
	})
	t.Run("another org's checkpoint", func(t *testing.T) {
		e := newEnv(t)
		e.logged(2)
		e.srv.Publish()
		other := "axt.anthropic.com/00000000-0000-0000-0000-000000000000"
		e.srv.CheckpointOverride = e.log.CheckpointFor(other, 2, e.log.RootAt(2))
		_, err := e.run()
		requireVerification(t, err, "origin")
	})
	t.Run("event from another org on this feed", func(t *testing.T) {
		e := newEnv(t)
		evs := e.logged(2)
		e.srv.Publish()
		e.srv.Events[1] = json.RawMessage(strings.Replace(string(evs[1]), orgUUID, "00000000-0000-0000-0000-000000000000", 1))
		rep, err := e.run()
		if err != nil || len(rep.Events.Failed) != 1 || !strings.Contains(rep.Events.Failed[0].Reason, "belongs to organization") {
			t.Fatalf("rep=%+v err=%v", rep.Events, err)
		}
	})
}

func TestRun_PendingUntilCovered(t *testing.T) {
	e := newEnv(t)
	e.logged(3)
	e.srv.Publish()
	e.logged(2) // sequenced, feed-visible, but no checkpoint covers them yet
	null := e.served(nil)
	e.srv.Events = append(e.srv.Events, null)

	rep := e.mustRun()
	if rep.Events.Verified != 3 || len(rep.Events.Pending) != 2 || len(rep.Events.NotLogged) != 1 || len(e.st.Feed.Pending) != 2 {
		t.Fatalf("run 1: %+v state=%+v", rep.Events, e.st.Feed)
	}

	// Still uncovered an hour later: still pending, not failed.
	e.clock = e.clock.Add(time.Hour)
	rep = e.mustRun()
	if rep.Events.Verified != 0 || len(rep.Events.Pending) != 2 {
		t.Fatalf("run 2: %+v", rep.Events)
	}

	// Covered: verified from the stored leaf hash without re-reading them
	// (they are Done on the feed pass).
	e.srv.Publish()
	rep = e.mustRun()
	if rep.Events.Verified != 2 || len(rep.Events.Pending) != 0 || len(e.st.Feed.Pending) != 0 {
		t.Fatalf("run 3: %+v state=%+v", rep.Events, e.st.Feed)
	}

	// A new uncovered event that outlives the grace period fails.
	e.logged(1)
	e.mustRun()
	e.clock = e.clock.Add(25 * time.Hour)
	rep, err := e.run()
	if err != nil || len(rep.Events.Failed) != 1 || !strings.Contains(rep.Events.Failed[0].Reason, "still not covered") {
		t.Fatalf("overdue: %+v err=%v", rep.Events, err)
	}
}

func TestRun_LogMovesMidPass(t *testing.T) {
	t.Run("grows between checkpoint and proofs", func(t *testing.T) {
		e := newEnv(t)
		e.logged(7)
		e.srv.Publish()
		// /checkpoint answers from before the last publish; every proof
		// embeds the newer checkpoint, which must be linked by consistency
		// — after which it is the pass's latest and covers the rest.
		e.srv.CheckpointOverride = e.log.Checkpoint(4)
		rep := e.mustRun()
		if rep.Events.Verified != 7 || rep.Checkpoint.Size != 7 || e.srv.Requests["consistency"] == 0 {
			t.Fatalf("%+v consistency requests=%d", rep, e.srv.Requests["consistency"])
		}
		if got, _ := checkpoint.ParseTrusted([]byte(e.st.Checkpoint), origin); got.Size != 7 {
			t.Fatalf("saved checkpoint size %d, want the newest linked (7)", got.Size)
		}
	})
	t.Run("proof served from a lagging read", func(t *testing.T) {
		e := newEnv(t)
		e.logged(7)
		e.srv.Publish()
		e.srv.InclusionAgainst = map[uint64]uint64{2: 5, 3: 6}
		rep := e.mustRun()
		if rep.Events.Verified != 7 || rep.Checkpoint.Size != 7 {
			t.Fatalf("%+v", rep)
		}
	})
}

// An event verified once must not carry a later, different serving of the
// same id: the overlap re-read is only protective if it re-checks.
func TestRun_LaterServingCannotRideOnAnEarlierSuccess(t *testing.T) {
	t.Run("rewritten after it verified", func(t *testing.T) {
		e := newEnv(t)
		evs := e.logged(3)
		e.srv.Publish()
		e.mustRun()

		e.srv.Events[1] = json.RawMessage(strings.Replace(string(evs[1]), `"safety_review"`, `"incident_response"`, 1))
		e.clock = e.clock.Add(time.Hour)
		rep, err := e.run()
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.Events.Failed) != 1 || !strings.Contains(rep.Events.Failed[0].Reason, "not what the log committed") {
			t.Fatalf("report: %+v", rep.Events)
		}
	})
	t.Run("leaf index withdrawn after it verified", func(t *testing.T) {
		e := newEnv(t)
		evs := e.logged(3)
		e.srv.Publish()
		e.mustRun()

		// The index is not committed in the leaf, so dropping it rewrites no
		// hash — only the state remembers that this event had one.
		e.srv.Events[1] = json.RawMessage(strings.Replace(string(evs[1]), `"`+IndexKey+`":1`, `"`+IndexKey+`":null`, 1))
		e.clock = e.clock.Add(time.Hour)
		rep, err := e.run()
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.Events.Failed) != 1 || !strings.Contains(rep.Events.Failed[0].Reason, "now served without a leaf index") {
			t.Fatalf("report: %+v", rep.Events)
		}
	})
	t.Run("not logged is re-examined, not banked", func(t *testing.T) {
		e := newEnv(t)
		e.logged(1)
		raw := e.served(nil)
		e.srv.Events = append(e.srv.Events, raw)
		e.srv.Publish()

		rep := e.mustRun()
		if len(rep.Events.NotLogged) != 1 || len(e.st.Feed.Done) != 1 {
			t.Fatalf("first run: %+v done=%d", rep.Events, len(e.st.Feed.Done))
		}

		// The same event, now with a leaf, must be verified rather than
		// skipped by the earlier "no leaf" answer.
		ev, err := leaf.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		idx := e.log.Append(ev.Entry)
		e.srv.Events[1] = json.RawMessage(strings.Replace(string(raw), `"`+IndexKey+`":null`, fmt.Sprintf(`"%s":%d`, IndexKey, idx), 1))
		e.srv.Publish()
		e.clock = e.clock.Add(time.Hour)
		rep = e.mustRun()
		if rep.Events.Verified != 1 || len(rep.Events.NotLogged) != 0 {
			t.Fatalf("second run: %+v", rep.Events)
		}
	})
}

// A served created_at steers the next run's window and what the state
// forgets, so it may not carry either past this clock.
func TestRun_FutureCreatedAtCannotEmptyTheWindow(t *testing.T) {
	e := newEnv(t)
	e.logged(2)

	idx := e.log.Size()
	var m map[string]any
	if err := json.Unmarshal(e.served(&idx), &m); err != nil {
		t.Fatal(err)
	}
	m["created_at"] = "2099-01-01T00:00:00Z"
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := leaf.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	e.log.Append(ev.Entry)
	e.srv.Events = append(e.srv.Events, raw)
	e.srv.Publish()

	rep := e.mustRun()
	if rep.Events.Verified != 3 {
		t.Fatalf("report: %+v", rep.Events)
	}
	if e.st.Feed.HighWater.After(e.clock.Add(10 * time.Minute)) {
		t.Fatalf("high water = %s, carried past the clock %s", e.st.Feed.HighWater, e.clock)
	}
	if len(e.st.Feed.Done) != 3 {
		t.Fatalf("done = %d entries, want 3: the window was pruned away", len(e.st.Feed.Done))
	}
}

// The window is the only thing that lists an event again, so a finding must
// not age out of it into a clean exit 0.
func TestRun_FailureHoldsTheWindowOpen(t *testing.T) {
	e := newEnv(t)
	evs := e.logged(3)
	e.srv.Publish()
	e.srv.Events[0] = json.RawMessage(strings.Replace(string(evs[0]), `"safety_review"`, `"incident_response"`, 1))

	e.v.Overlap = time.Minute // far shorter than the events' spacing
	rep, err := e.run()
	if err != nil || len(rep.Events.Failed) != 1 {
		t.Fatalf("first run: %+v err=%v", rep.Events, err)
	}
	// The window is frozen where the pass started rather than moved to the
	// newest event at t0+3h, which a 1m overlap would have put it past.
	if hw := e.st.Feed.HighWater; !hw.IsZero() {
		t.Fatalf("high water = %s, advanced while a failure was unresolved", hw)
	}
	rep, err = e.run()
	if err != nil || len(rep.Events.Failed) != 1 {
		t.Fatalf("second run stopped reporting it: %+v err=%v", rep.Events, err)
	}
}

// The index is not committed in the leaf, so a Done event re-served at a
// different index rebuilds the same hash — only the state catches it.
func TestRun_MovedIndexOnADoneEventFails(t *testing.T) {
	e := newEnv(t)
	evs := e.logged(2)
	e.srv.Publish()
	e.mustRun()

	e.srv.Events[1] = json.RawMessage(strings.Replace(string(evs[1]), fmt.Sprintf(`"%s":1`, IndexKey), fmt.Sprintf(`"%s":0`, IndexKey), 1))
	e.clock = e.clock.Add(time.Hour)
	rep, err := e.run()
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Events.Failed) != 1 || !strings.Contains(rep.Events.Failed[0].Reason, "now served at leaf index") {
		t.Fatalf("report: %+v", rep.Events)
	}
}

// A rewrite that fails must not consume the recorded entry: the next
// serving has to meet the same guard.
func TestRun_FailedReverificationKeepsTheRecordedEvent(t *testing.T) {
	e := newEnv(t)
	evs := e.logged(2)
	e.srv.Publish()
	e.mustRun()

	e.srv.Events[1] = json.RawMessage(strings.Replace(string(evs[1]), `"safety_review"`, `"incident_response"`, 1))
	e.clock = e.clock.Add(time.Hour)
	if rep, err := e.run(); err != nil || len(rep.Events.Failed) != 1 {
		t.Fatalf("rewrite: %+v err=%v", rep.Events, err)
	}
	// Withdrawing the index now must still be caught, which needs the entry
	// recorded when the event first verified.
	e.srv.Events[1] = json.RawMessage(strings.Replace(string(evs[1]), fmt.Sprintf(`"%s":1`, IndexKey), `"`+IndexKey+`":null`, 1))
	e.clock = e.clock.Add(time.Hour)
	rep, err := e.run()
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Events.Failed) != 1 || !strings.Contains(rep.Events.Failed[0].Reason, "without a leaf index") {
		t.Fatalf("withdrawal after a failed rewrite: %+v", rep.Events)
	}
}

// What a pending event is verified from later must not be quietly replaced,
// and the record that catches a withdrawal must not age out on a served
// timestamp.
func TestRun_PendingRewriteFails(t *testing.T) {
	e := newEnv(t)
	beyond := e.log.Size() + 5
	raw := e.served(&beyond)
	e.logged(1)
	e.srv.Events = append(e.srv.Events, raw)
	e.srv.Publish()
	if rep := e.mustRun(); len(rep.Events.Pending) != 1 {
		t.Fatalf("first run: %+v", rep.Events)
	}

	e.srv.Events[1] = json.RawMessage(strings.Replace(string(raw), `"safety_review"`, `"incident_response"`, 1))
	e.clock = e.clock.Add(time.Hour)
	rep, err := e.run()
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Events.Failed) != 1 || !strings.Contains(rep.Events.Failed[0].Reason, "is now served differently") {
		t.Fatalf("rewrite while pending: %+v", rep.Events)
	}
}

// Retention runs on the verifier's clock: a backdated created_at must not
// have a record dropped in the pass that wrote it.
func TestRun_BackdatedCreatedAtKeepsTheRecord(t *testing.T) {
	e := newEnv(t)
	idx := e.log.Size()
	var m map[string]any
	if err := json.Unmarshal(e.served(&idx), &m); err != nil {
		t.Fatal(err)
	}
	m["created_at"] = "1971-01-01T00:00:00Z"
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := leaf.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	e.log.Append(ev.Entry)
	e.srv.Events = append(e.srv.Events, raw)
	e.srv.Publish()

	if rep := e.mustRun(); rep.Events.Verified != 1 {
		t.Fatalf("report: %+v", rep.Events)
	}
	if len(e.st.Feed.Done) != 1 {
		t.Fatalf("the record was pruned in the pass that wrote it: %+v", e.st.Feed)
	}
}

// The feed serves an event twice around the moment its leaf index is
// stamped. Both copies name one activity, so the verdict must not depend on
// which one the page lists first.
func TestRun_SameIdCopiesCoalesce(t *testing.T) {
	for name, indexedFirst := range map[string]bool{"indexed copy first": true, "null copy first": false} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			indexed := e.logged(1)[0]
			nulled := json.RawMessage(strings.Replace(string(indexed), fmt.Sprintf(`"%s":0`, IndexKey), `"`+IndexKey+`":null`, 1))
			if indexedFirst {
				e.srv.Events = []json.RawMessage{indexed, nulled}
			} else {
				e.srv.Events = []json.RawMessage{nulled, indexed}
			}
			e.srv.Publish()
			e.v.PageSize = 1 // and split across pages, either way round

			rep := e.mustRun()
			if rep.Events.Verified != 1 || len(rep.Events.NotLogged) != 0 || len(rep.Events.Failed) != 0 {
				t.Fatalf("report: %+v", rep.Events)
			}
		})
	}
	// Two copies at different indices are a contradiction no proof settles.
	t.Run("different indices", func(t *testing.T) {
		e := newEnv(t)
		first := e.logged(2)[0]
		moved := json.RawMessage(strings.Replace(string(first), fmt.Sprintf(`"%s":0`, IndexKey), fmt.Sprintf(`"%s":1`, IndexKey), 1))
		e.srv.Events = append(e.srv.Events, moved)
		e.srv.Publish()

		rep, err := e.run()
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.Events.Failed) != 1 || !strings.Contains(rep.Events.Failed[0].Reason, "different leaf indices") {
			t.Fatalf("report: %+v", rep.Events)
		}
	})
}

// A checkpoint read served from behind the tree a previous pass verified is
// lag, not a rollback: the log can still prove it covers the saved one.
func TestRun_LaggingCheckpointReadRecovers(t *testing.T) {
	e := newEnv(t)
	e.logged(4)
	e.srv.Publish()
	e.mustRun()

	// The log grew and the pass saved the larger tree; then /checkpoint
	// answers from a replica behind it while the proof endpoints do not.
	e.logged(2)
	e.srv.Publish()
	e.clock = e.clock.Add(time.Hour)
	e.mustRun()

	e.srv.Published = 4
	e.srv.ProofsAhead = true
	e.clock = e.clock.Add(time.Hour)
	before := e.srv.Requests["consistency"]
	if _, err := e.run(); err != nil {
		t.Fatalf("a lagging read was called a rollback: %v", err)
	}
	// Both the saved anchor and the checkpoint served behind it are proven
	// against the log, not accepted on their signatures.
	if got := e.srv.Requests["consistency"] - before; got < 2 {
		t.Fatalf("%d consistency requests, want the served checkpoint proven too", got)
	}
}

// A checkpoint that verified must survive a pass that later breaks off, or a
// log able to force transient failures keeps rewriting past it.
func TestRun_VerifiedCheckpointSurvivesATransientFailure(t *testing.T) {
	e := newEnv(t)
	e.logged(2)
	e.srv.Publish()
	e.srv.FailNext = map[string][]int{"activities": {500, 500, 500, 500, 500}}

	if _, err := e.run(); err == nil {
		t.Fatal("the pass completed")
	}
	if e.st.Checkpoint == "" {
		t.Fatal("the verified checkpoint was discarded with the failed pass")
	}
	if e.st.Feed.HighWater.After(t0) {
		t.Fatalf("feed progress was recorded for a pass that did not read the feed: %s", e.st.Feed.HighWater)
	}
}

// Retention runs on wall-clock time whether or not a finding is open, so the
// pass that reports a failure must not be the one that forgets the event.
func TestRun_FailureKeepsTheRecordAlive(t *testing.T) {
	e := newEnv(t)
	evs := e.logged(2)
	e.srv.Publish()
	e.mustRun()

	e.v.Overlap = time.Hour
	e.srv.Events[1] = json.RawMessage(strings.Replace(string(evs[1]), `"safety_review"`, `"incident_response"`, 1))
	e.clock = e.clock.Add(2 * time.Hour) // past the retention window
	if rep, err := e.run(); err != nil || len(rep.Events.Failed) != 1 {
		t.Fatalf("rewrite: %+v err=%v", rep.Events, err)
	}
	if _, ok := e.st.Feed.Done["activity_0002"]; !ok {
		t.Fatal("the record was forgotten by the pass that reported the failure")
	}
	// With the record still there, withdrawing the index is still caught.
	e.srv.Events[1] = json.RawMessage(strings.Replace(string(evs[1]), fmt.Sprintf(`"%s":1`, IndexKey), `"`+IndexKey+`":null`, 1))
	e.clock = e.clock.Add(time.Minute)
	rep, err := e.run()
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Events.Failed) != 1 || !strings.Contains(rep.Events.Failed[0].Reason, "without a leaf index") {
		t.Fatalf("withdrawal after the rewrite: %+v", rep.Events)
	}
}

// The saved checkpoint is local state, not a served answer, so it must never
// become the pass's head on its own: a log replaying its genesis checkpoint
// is the most complete rollback there is.
func TestRun_GenesisReplayIsNotAppendOnly(t *testing.T) {
	e := newEnv(t)
	e.logged(4)
	e.srv.Publish()
	e.mustRun()

	// /checkpoint now answers with the empty tree, validly signed.
	e.srv.Published = 0
	e.clock = e.clock.Add(time.Hour)
	_, err := e.run()
	if !errors.Is(err, axtverify.ErrVerification) {
		t.Fatalf("err = %v, want a verification failure", err)
	}
	if !strings.Contains(err.Error(), "shrank") {
		t.Fatalf("err = %q, want it to name the shrunken log", err)
	}
}

// Paging can split the cutover pair that serves one event with and without
// its index, so a withdrawal verdict must wait for the whole pass.
func TestRun_WithdrawalVerdictWaitsForTheWholePass(t *testing.T) {
	e := newEnv(t)
	indexed := e.logged(1)[0]
	e.srv.Publish()
	e.mustRun()

	// The null copy is listed first, the indexed one lands on the next page.
	nulled := json.RawMessage(strings.Replace(string(indexed), fmt.Sprintf(`"%s":0`, IndexKey), `"`+IndexKey+`":null`, 1))
	e.srv.Events = []json.RawMessage{nulled, indexed}
	e.v.PageSize = 1
	e.clock = e.clock.Add(time.Hour)
	rep, err := e.run()
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Events.Failed) != 0 {
		t.Fatalf("a split cutover pair was read as a withdrawal: %+v", rep.Events.Failed)
	}
	if len(rep.Events.NotLogged) != 0 || rep.Events.Verified != 0 {
		t.Fatalf("one activity, two outcomes: %+v", rep.Events)
	}
	// With no indexed copy anywhere in the pass it is a withdrawal again.
	e.srv.Events = []json.RawMessage{nulled}
	e.clock = e.clock.Add(time.Hour)
	rep, err = e.run()
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Events.Failed) != 1 || !strings.Contains(rep.Events.Failed[0].Reason, "without a leaf index") {
		t.Fatalf("report: %+v", rep.Events)
	}
}

// A cutover pair must not launder a tamper finding for the same id: only the
// superseded copy's own verdict is withdrawn.
func TestRun_SupersedeDoesNotEraseATamperFinding(t *testing.T) {
	e := newEnv(t)
	indexed := e.logged(1)[0]
	nulled := json.RawMessage(strings.Replace(string(indexed), fmt.Sprintf(`"%s":0`, IndexKey), `"`+IndexKey+`":null`, 1))
	tampered := json.RawMessage(strings.Replace(string(indexed), `"safety_review"`, `"incident_response"`, 1))
	e.srv.Publish()
	e.mustRun()

	// null copy, then a tampered copy at the real index, then the honest
	// indexed copy.
	e.srv.Events = []json.RawMessage{nulled, tampered, indexed}
	e.clock = e.clock.Add(time.Hour)
	rep, err := e.run()
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK() {
		t.Fatalf("the tamper finding was erased by the cutover pair: %+v", rep.Events)
	}
}

// A backlog of events with no leaf must not freeze the window: only a
// verdict contested by a record the pass holds waits for a fuller read.
func TestRun_TruncatedPassStillAdvancesOverNotLoggedEvents(t *testing.T) {
	e := newEnv(t)
	e.logged(1)
	e.srv.Publish()
	e.mustRun()
	before := e.st.Feed.HighWater

	for range 3 {
		e.srv.Events = append(e.srv.Events, e.served(nil))
	}
	e.v.PageSize, e.v.MaxPages = 2, 1
	e.clock = e.clock.Add(time.Hour)
	rep := e.mustRun()
	if !rep.Truncated {
		t.Fatalf("expected truncation: %+v", rep)
	}
	if !e.st.Feed.HighWater.After(before) {
		t.Fatalf("high water stuck at %s: a not-logged backlog froze the window", e.st.Feed.HighWater)
	}
}

// A truncated pass has not read the whole feed, so it cannot conclude that
// no copy carrying the index exists.
func TestRun_TruncatedPassDefersNullCopyVerdicts(t *testing.T) {
	e := newEnv(t)
	indexed := e.logged(1)[0]
	e.srv.Publish()
	e.mustRun()

	// Two newer events bracket a null-index copy of the verified one, so the
	// page budget stops right after that copy and before the page its
	// indexed twin would be on.
	e.logged(2)
	e.srv.Publish()
	nulled := json.RawMessage(strings.Replace(
		strings.Replace(string(indexed), fmt.Sprintf(`"%s":0`, IndexKey), `"`+IndexKey+`":null`, 1),
		t0.Add(time.Hour).Format(time.RFC3339Nano), t0.Add(150*time.Minute).Format(time.RFC3339Nano), 1))
	e.srv.Events = append(e.srv.Events[1:], nulled)
	e.v.PageSize, e.v.MaxPages = 2, 1
	e.clock = e.clock.Add(time.Hour)

	rep, err := e.run()
	if len(rep.Events.Failed) != 0 || len(rep.Events.NotLogged) != 0 {
		t.Fatalf("a verdict was passed on a null copy whose twin was not read: %+v", rep.Events)
	}
	// Deferral, not deletion: the window may not move past the deferred
	// verdict, and a truncated pass that cannot move it says so rather than
	// re-reading the same window on every later run.
	if err == nil || !strings.Contains(err.Error(), "--max-pages") {
		t.Fatalf("err = %v, want the stalled-truncation error", err)
	}
	if !e.st.Feed.HighWater.Equal(t0.Add(time.Hour)) {
		t.Fatalf("high water = %s, moved past a deferred verdict", e.st.Feed.HighWater)
	}
}

// Copies of one id are collapsed only when they are copies: same id with
// different bytes is not a duplicate, whatever the index says.
func TestRun_SameIdDifferentContentFails(t *testing.T) {
	e := newEnv(t)
	first := e.logged(1)[0]
	tampered := json.RawMessage(strings.Replace(string(first), `"safety_review"`, `"incident_response"`, 1))
	e.srv.Events = []json.RawMessage{first, tampered}
	e.srv.Publish()
	// Both copies carry the same index, so both claim the log committed them.

	rep, err := e.run()
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Events.Failed) != 1 || !strings.Contains(rep.Events.Failed[0].Reason, "different content") {
		t.Fatalf("report: %+v", rep.Events)
	}

	// A null-index copy claims no position, so a content difference against
	// it is cutover noise, not a contradiction: the indexed copy is checked.
	e2 := newEnv(t)
	indexed := e2.logged(1)[0]
	noisy := json.RawMessage(strings.Replace(strings.Replace(string(indexed), fmt.Sprintf(`"%s":0`, IndexKey), `"`+IndexKey+`":null`, 1), `"safety_review"`, `"incident_response"`, 1))
	e2.srv.Events = []json.RawMessage{noisy, indexed}
	e2.srv.Publish()
	if rep := e2.mustRun(); rep.Events.Verified != 1 {
		t.Fatalf("cutover pair: %+v", rep.Events)
	}
}

// `events` sees no state, but one id claiming two positions is a
// contradiction the input carries on its own.
func TestVerifyEvents_SameIdTwoIndicesFails(t *testing.T) {
	e := newEnv(t)
	evs := e.logged(2)
	e.srv.Publish()
	moved := json.RawMessage(strings.Replace(string(evs[0]), fmt.Sprintf(`"%s":0`, IndexKey), fmt.Sprintf(`"%s":1`, IndexKey), 1))

	rep, err := e.v.VerifyEvents(context.Background(), nil, []json.RawMessage{evs[0], moved})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Events.Failed) != 1 || !strings.Contains(rep.Events.Failed[0].Reason, "different leaf indices") {
		t.Fatalf("report: %+v", rep.Events)
	}
}

// A pass that fills its page budget without passing where the last one
// stopped repeats forever; it must say so rather than report truncation.
func TestRun_TruncatedWithoutProgressFails(t *testing.T) {
	e := newEnv(t)
	e.logged(4)
	e.srv.Publish()
	e.v.PageSize = 2
	e.mustRun()

	// Re-reading the overlap window now exhausts the budget before any new
	// event: the pass would otherwise save an unchanged high-water mark.
	e.v.MaxPages = 1
	e.logged(2)
	e.srv.Publish()
	e.clock = e.clock.Add(time.Hour)
	if _, err := e.run(); err == nil || !strings.Contains(err.Error(), "--max-pages") {
		t.Fatalf("err = %v, want the stalled-truncation error", err)
	}
}

// The grace deadline a claimed index starts must not be retired by serving
// the same event without one.
func TestRun_WithdrawnIndexOnAPendingEventFails(t *testing.T) {
	e := newEnv(t)
	beyond := e.log.Size() + 5
	raw := e.served(&beyond)
	e.logged(1)
	e.srv.Events = append(e.srv.Events, raw)
	e.srv.Publish()

	rep := e.mustRun()
	if len(rep.Events.Pending) != 1 {
		t.Fatalf("first run: %+v", rep.Events)
	}
	e.srv.Events[1] = json.RawMessage(strings.Replace(string(raw), fmt.Sprintf(`"%s":%d`, IndexKey, beyond), `"`+IndexKey+`":null`, 1))
	e.clock = e.clock.Add(time.Hour)
	rep, err := e.run()
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Events.Failed) != 1 || !strings.Contains(rep.Events.Failed[0].Reason, "claimed leaf index") {
		t.Fatalf("second run: %+v", rep.Events)
	}
}

// A feed cursor that never moves would page forever, and a run that never
// exits raises no alarm.
func TestRun_StuckFeedCursorIsRefused(t *testing.T) {
	e := newEnv(t)
	e.logged(2)
	e.srv.Publish()
	e.srv.FeedStuckCursor = true

	_, err := e.run()
	if !errors.Is(err, compliance.ErrResponse) || errors.Is(err, axtverify.ErrVerification) {
		t.Fatalf("err = %v, want ErrResponse", err)
	}
}

// A cursor that never moves must end the pass even when each page carries
// something new — otherwise the read only stops when memory does.
func TestRun_StuckCursorWithNewEventsIsRefused(t *testing.T) {
	e := newEnv(t)
	e.logged(1)
	e.srv.Publish()
	e.srv.FeedStuckWithNew = true

	_, err := e.run()
	if !errors.Is(err, compliance.ErrResponse) {
		t.Fatalf("err = %v, want ErrResponse", err)
	}
}

func TestRun_FeedPagingAndWindow(t *testing.T) {
	e := newEnv(t)
	e.logged(10)
	e.srv.Publish()
	e.v.PageSize = 3
	e.v.MaxPages = 2
	rep := e.mustRun()
	if rep.Events.Verified != 6 || !rep.Truncated || !e.st.Feed.HighWater.Equal(t0.Add(6*time.Hour)) {
		t.Fatalf("truncated run: %+v hw=%s", rep, e.st.Feed.HighWater)
	}
	e.v.MaxPages = 0
	rep = e.mustRun()
	if rep.Events.Verified != 4 || rep.Truncated || e.srv.Requests["activities"] != 2+4 {
		t.Fatalf("resumed run: %+v activities requests=%d", rep, e.srv.Requests["activities"])
	}
	// Overlap: with a 3h window behind the 10h high-water mark, only events
	// at ≥7h are re-listed. Their records are kept alive by that listing;
	// the rest age out of retention, which runs on the verifier's clock.
	e.v.Overlap = 3 * time.Hour
	e.clock = e.clock.Add(4 * time.Hour)
	e.mustRun()
	if len(e.st.Feed.Done) != 4 {
		t.Fatalf("done after prune: %d entries, want 4 (hours 7..10)", len(e.st.Feed.Done))
	}
}

func TestRun_TransportFailures(t *testing.T) {
	e := newEnv(t)
	e.logged(2)
	e.srv.Publish()

	e.srv.FailNext = map[string][]int{"checkpoint": {503, 429}, "inclusion": {502}, "activities": {504}}
	e.mustRun() // retried through

	e.srv.FailNext = map[string][]int{"checkpoint": {503, 503, 503, 503, 503}}
	_, err := e.run()
	if !errors.Is(err, compliance.ErrTransient) || errors.Is(err, axtverify.ErrVerification) {
		t.Fatalf("exhausted retries: err = %v", err)
	}

	e.srv.FailNext = map[string][]int{"checkpoint": {http.StatusUnauthorized}}
	_, err = e.run()
	var se *compliance.StatusError
	if !errors.As(err, &se) || se.StatusCode != http.StatusUnauthorized || errors.Is(err, axtverify.ErrVerification) || e.srv.Requests["checkpoint"] < 1 {
		t.Fatalf("401: err = %v", err)
	}

	e.v.Client.APIKey = "wrong"
	if _, err = e.run(); !errors.As(err, &se) || se.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad key: err = %v", err)
	}
}

func TestVerifyEvents_FromExport(t *testing.T) {
	e := newEnv(t)
	evs := e.logged(3)
	e.srv.Publish()
	// An export carries other activity types; those are not ours to check.
	other := json.RawMessage(`{"type":"user_login","id":"activity_zzz"}`)
	// One that claims to be ours but cannot be rebuilt is still a finding.
	broken := json.RawMessage(`{"type":"anthropic_access","id":"activity_yyy"}`)
	rep, err := e.v.VerifyEvents(context.Background(), nil, append(evs, other, broken, e.served(nil)))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Events.Verified != 3 || len(rep.Events.NotLogged) != 1 || rep.Events.SkippedOtherTypes != 1 {
		t.Fatalf("%+v", rep.Events)
	}
	if len(rep.Events.Failed) != 1 || rep.Events.Failed[0].ID != "activity_yyy" {
		t.Fatalf("failed = %+v", rep.Events.Failed)
	}
}

// VerifyEvents records nothing for a later pass to settle, so an index the
// checkpoint does not cover yet is waited out rather than ruled on: an event
// stamped moments ago is covered by the next checkpoint the log publishes.
func TestVerifyEvents_WaitsForACoveringCheckpoint(t *testing.T) {
	e := newEnv(t)
	e.logged(1)
	e.srv.Publish()
	evs := e.logged(1) // appended, not published: leaf index 1 against a tree of size 1
	e.v.CoverageWait, e.v.CoveragePoll = 2*time.Second, 20*time.Millisecond
	timer := time.AfterFunc(50*time.Millisecond, e.srv.Publish)
	defer timer.Stop()

	rep, err := e.v.VerifyEvents(context.Background(), nil, evs)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK() || rep.Events.Verified != 1 || len(rep.Events.Pending) != 0 || rep.Checkpoint.Size != 2 {
		t.Fatalf("%+v at tree size %d", rep.Events, rep.Checkpoint.Size)
	}
}

// An index no checkpoint covers by the end of the wait is not a finding —
// the tool cannot tell a freshly stamped event from a fabricated index — so
// it is reported and the pass ends as one that could not complete: an OK
// report with an error that is not a verification failure, which the command
// exits 3 on. Only a rerun settles it.
func TestVerifyEvents_UncoveredIndexIsPendingAndIncomplete(t *testing.T) {
	e := newEnv(t)
	e.logged(1)
	e.srv.Publish()
	e.v.CoverageWait, e.v.CoveragePoll = 30*time.Millisecond, 10*time.Millisecond
	beyond := uint64(99)

	rep, err := e.v.VerifyEvents(context.Background(), nil, []json.RawMessage{e.served(&beyond)})
	if err == nil || errors.Is(err, axtverify.ErrVerification) {
		t.Fatalf("err = %v, want a could-not-complete error", err)
	}
	if !strings.Contains(err.Error(), "leaf index 99") {
		t.Fatalf("err = %q, want it to name the index", err)
	}
	if !rep.OK() || len(rep.Events.Pending) != 1 || len(rep.Events.Failed) != 0 {
		t.Fatalf("%+v", rep.Events)
	}
}

// The wait covers an index moments after the log published it, which is
// exactly when an inclusion replica still behind the checkpoint read answers
// 404. That must not be reported as tampering: the pass reports it and ends
// as one that could not complete, like the index it waited for.
func TestVerifyEvents_NoProofYetForAnIndexPublishedDuringTheWait(t *testing.T) {
	e := newEnv(t)
	e.logged(1)
	e.srv.Publish()
	evs := e.logged(1)                               // leaf index 1, not yet published
	e.srv.InclusionAgainst = map[uint64]uint64{1: 1} // 404 for index 1 once the tree covers it
	e.v.CoverageWait, e.v.CoveragePoll = 2*time.Second, 20*time.Millisecond
	timer := time.AfterFunc(50*time.Millisecond, e.srv.Publish)
	defer timer.Stop()

	rep, err := e.v.VerifyEvents(context.Background(), nil, evs)
	if err == nil || errors.Is(err, axtverify.ErrVerification) {
		t.Fatalf("err = %v, want a could-not-complete error", err)
	}
	if !rep.OK() || len(rep.Events.Pending) != 1 || len(rep.Events.Failed) != 0 {
		t.Fatalf("%+v", rep.Events)
	}
}

// An index the pass's own starting checkpoint already covered is another
// matter — this pass has no later verdict to soften it — but a replica
// behind the checkpoint read answers 404 for a freshly published index just
// as a withholding log does, and nothing bounds how fresh that starting
// checkpoint is. So the endpoint is re-read before anything is ruled: a
// proof that turns up was lag.
func TestVerifyEvents_NoProofThatClearsOnARepollVerifies(t *testing.T) {
	e := newEnv(t)
	evs := e.logged(1)
	e.srv.Publish()
	e.srv.FailNext = map[string][]int{"inclusion": {404}} // one lagging answer, then honest
	e.v.CoverageWait, e.v.CoveragePoll = 100*time.Millisecond, 20*time.Millisecond

	rep, err := e.v.VerifyEvents(context.Background(), nil, evs)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK() || rep.Events.Verified != 1 || len(rep.Events.Pending) != 0 {
		t.Fatalf("%+v", rep.Events)
	}
	if e.srv.Requests["inclusion"] < 2 {
		t.Fatalf("the proof was not re-read: %d inclusion requests", e.srv.Requests["inclusion"])
	}
}

// Waiting for a covering checkpoint and waiting for a proof draw on one
// budget: a file that needs both must not wait twice over.
func TestVerifyEvents_TheTwoWaitsShareOneBudget(t *testing.T) {
	e := newEnv(t)
	evs := e.logged(2)
	e.srv.Publish()
	e.srv.CheckpointOverride = e.log.Checkpoint(1)   // head 1: leaf 0 covered, nothing else
	e.srv.InclusionAgainst = map[uint64]uint64{0: 0} // and no proof for leaf 0, ever
	e.v.CoverageWait, e.v.CoveragePoll = 40*time.Millisecond, 20*time.Millisecond
	beyond := uint64(99)

	// The beyond-the-head row spends the whole budget waiting for coverage,
	// so nothing is left to re-read leaf 0's missing proof with.
	rep, err := e.v.VerifyEvents(context.Background(), nil, []json.RawMessage{e.served(&beyond), evs[0]})
	if err == nil {
		t.Fatal("a pass that settled nothing reported no error")
	}
	if len(rep.Events.Failed) != 1 || len(rep.Events.Pending) != 1 {
		t.Fatalf("%+v", rep.Events)
	}
	if got := e.srv.Requests["inclusion"]; got != 1 {
		t.Fatalf("inclusion requested %d times; the spent budget must leave none for a re-read", got)
	}
}

// Silence to the end of the wait is the log declining to prove an event it
// has committed, which is the evasion this tool exists to catch.
func TestVerifyEvents_NoProofForAnAlreadyCoveredIndexFails(t *testing.T) {
	e := newEnv(t)
	evs := e.logged(2)
	e.srv.Publish()
	e.srv.InclusionAgainst = map[uint64]uint64{1: 1} // 404 for index 1 despite tree size 2
	e.v.CoverageWait, e.v.CoveragePoll = 60*time.Millisecond, 20*time.Millisecond

	rep, err := e.v.VerifyEvents(context.Background(), nil, evs)
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK() || len(rep.Events.Failed) != 1 || len(rep.Events.Pending) != 0 {
		t.Fatalf("%+v", rep.Events)
	}
	if !strings.Contains(rep.Events.Failed[0].Reason, "serves no proof") {
		t.Fatalf("reason = %q", rep.Events.Failed[0].Reason)
	}
	// Ruled only after the re-reads, not on the first answer.
	if e.srv.Requests["inclusion"] < 3 {
		t.Fatalf("the proof was not re-read: %d inclusion requests", e.srv.Requests["inclusion"])
	}
}

// The proof endpoints answer against the log's newest tree while the
// checkpoint endpoint lags, so verifying one row advances the pass's head
// past a row already judged pending. Whether that row verifies must not
// depend on the file listing it after the one that moved the head.
func TestVerifyEvents_PendingRowsAreJudgedAgainstTheFinalHead(t *testing.T) {
	e := newEnv(t)
	evs := e.logged(2)
	e.srv.Publish() // proofs answer at tree size 2 and embed that checkpoint
	// /checkpoint lags a publish behind, so leaf index 1 is beyond the head
	// this pass starts on and no amount of waiting moves it.
	e.srv.CheckpointOverride = e.log.Checkpoint(1)
	e.v.CoverageWait, e.v.CoveragePoll = 30*time.Millisecond, 10*time.Millisecond

	// The beyond-the-head row first: it is judged before anything can cover it.
	rep, err := e.v.VerifyEvents(context.Background(), nil, []json.RawMessage{evs[1], evs[0]})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK() || rep.Events.Verified != 2 || len(rep.Events.Pending) != 0 {
		t.Fatalf("%+v at tree size %d", rep.Events, rep.Checkpoint.Size)
	}

	// The same file the other way round has always verified; it must still.
	e2 := newEnv(t)
	evs2 := e2.logged(2)
	e2.srv.Publish()
	e2.srv.CheckpointOverride = e2.log.Checkpoint(1)
	e2.v.CoverageWait, e2.v.CoveragePoll = 30*time.Millisecond, 10*time.Millisecond
	rep2, err := e2.v.VerifyEvents(context.Background(), nil, []json.RawMessage{evs2[0], evs2[1]})
	if err != nil {
		t.Fatal(err)
	}
	if !rep2.OK() || rep2.Events.Verified != 2 || len(rep2.Events.Pending) != 0 {
		t.Fatalf("reversed: %+v", rep2.Events)
	}
}

// A checkpoint fetched during the wait is verified and proven an extension
// of the one already held, by the same path every other checkpoint in the
// pass takes: waiting must not become a way to slip a forked tree in.
func TestVerifyEvents_WaitRefusesACheckpointThatDoesNotExtend(t *testing.T) {
	e := newEnv(t)
	e.logged(1)
	e.srv.Publish()
	evs := e.logged(1)
	e.srv.ConsistencyGarbage = true
	e.v.CoverageWait, e.v.CoveragePoll = 2*time.Second, 20*time.Millisecond
	timer := time.AfterFunc(50*time.Millisecond, e.srv.Publish)
	defer timer.Stop()

	_, err := e.v.VerifyEvents(context.Background(), nil, evs)
	requireVerification(t, err, "consistency")
	if _, ok := axtverify.AsInconsistency(err); !ok {
		t.Fatalf("err = %v, want the inconsistency evidence", err)
	}
}

// Two invocations sharing a state file must not silently discard each
// other's verified checkpoint.
func TestState_SaveRefusesAConcurrentOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	first, err := axtverify.LoadState(path, origin)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Save(path); err != nil {
		t.Fatal(err)
	}
	other, err := axtverify.LoadState(path, origin)
	if err != nil {
		t.Fatal(err)
	}
	other.Feed.HighWater = t0
	if err := other.Save(path); err != nil {
		t.Fatal(err)
	}
	if err := first.Save(path); err == nil {
		t.Fatal("overwrote a state file written since it was read")
	}
	back, err := axtverify.LoadState(path, origin)
	if err != nil {
		t.Fatal(err)
	}
	if !back.Feed.HighWater.Equal(t0) {
		t.Fatalf("high water = %s, want the other invocation's %s", back.Feed.HighWater, t0)
	}
}

func TestState_RoundTripAndOriginGuard(t *testing.T) {
	e := newEnv(t)
	e.logged(2)
	e.srv.Publish()
	e.logged(1)
	e.mustRun()
	path := filepath.Join(t.TempDir(), "s.json")
	if err := e.st.Save(path); err != nil {
		t.Fatal(err)
	}
	back, err := axtverify.LoadState(path, origin)
	if err != nil {
		t.Fatal(err)
	}
	if back.Checkpoint != e.st.Checkpoint || len(back.Feed.Done) != 2 || len(back.Feed.Pending) != 1 {
		t.Fatalf("round trip: %+v", back)
	}
	if _, err := axtverify.LoadState(path, "axt.anthropic.com/00000000-0000-0000-0000-000000000000"); err == nil {
		t.Fatal("state accepted for another origin")
	}
}

// A log that refuses to prove one event's inclusion is dodging that event,
// not failing to talk to us: the event fails, the pass reports it, and the
// exit code is the security one.
func TestRun_RefusedInclusionIsAnEventFailure(t *testing.T) {
	for _, status := range []int{400, 401, 403} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			e := newEnv(t)
			e.logged(2)
			e.srv.Publish()
			e.srv.FailNext = map[string][]int{"inclusion": {status, status, status, status, status, status}}
			rep, err := e.run()
			if err != nil {
				t.Fatalf("the pass aborted instead of recording the refusal: %v", err)
			}
			if rep.OK() || len(rep.Events.Failed) == 0 {
				t.Fatalf("status %d: the refusal was not recorded: %+v", status, rep.Events)
			}
			if !strings.Contains(rep.Events.Failed[0].Reason, "will not prove") {
				t.Fatalf("reason = %q", rep.Events.Failed[0].Reason)
			}
		})
	}
}

// A well-formed 200 that answers for a different leaf is the log declining to
// prove this event, not weather: it belongs in Failed with the two indices,
// not in a pass-aborting "rerun".
func TestRun_InclusionAnsweredForAnotherLeafIsAnEventFailure(t *testing.T) {
	e := newEnv(t)
	e.logged(2)
	e.srv.Publish()
	e.srv.InclusionIndexLie = map[uint64]uint64{0: 1}

	rep, err := e.run()
	if err != nil {
		t.Fatalf("the pass aborted instead of recording the finding: %v", err)
	}
	if rep.OK() || len(rep.Events.Failed) == 0 {
		t.Fatalf("no failure recorded: %+v", rep.Events)
	}
	got := rep.Events.Failed[0].Reason
	if !strings.Contains(got, "leaf index 0") || !strings.Contains(got, "leaf index 1") {
		t.Fatalf("the reason does not name both indices: %q", got)
	}
}

// A raw activities page carries rows that are not Access Transparency at all.
// Those are somebody else's to check — passed over, counted, not failed —
// while anything claiming one of our type names still has to verify.
func TestVerifyEvents_SkipsOtherActivityTypes(t *testing.T) {
	e := newEnv(t)
	served := e.logged(1)
	e.srv.Publish()

	other := json.RawMessage(`{"id":"activity_other","type":"api_key_created","created_at":"2026-08-01T00:00:00Z"}`)
	rep, err := e.v.VerifyEvents(context.Background(), nil, []json.RawMessage{served[0], other})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Events.Verified != 1 || rep.Events.SkippedOtherTypes != 1 || len(rep.Events.Failed) != 0 {
		t.Fatalf("%+v", rep.Events)
	}
	if !rep.OK() {
		t.Fatal("a page with an unrelated row was reported as not OK")
	}

	// A type claiming to be ours is a schema this build does not know: that
	// must fail loudly rather than be passed over as someone else's row.
	ours := json.RawMessage(`{"id":"activity_x","type":"anthropic_access_v2","created_at":"2026-08-01T00:00:00Z"}`)
	rep, err = e.v.VerifyEvents(context.Background(), nil, []json.RawMessage{ours})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Events.SkippedOtherTypes != 0 || len(rep.Events.Failed) != 1 {
		t.Fatalf("%+v", rep.Events)
	}
	if !strings.Contains(rep.Events.Failed[0].Reason, "type") {
		t.Fatalf("reason = %q", rep.Events.Failed[0].Reason)
	}
}

// The gate that decides "is this row ours to check" must not be more
// forgiving than the canonicalizer: a row that decodes two ways is a finding,
// and a type that merely looks like ours must still be rendered, not skipped.
func TestVerifyEvents_SkipGateIsAsStrictAsParse(t *testing.T) {
	e := newEnv(t)
	e.logged(1)
	e.srv.Publish()

	cases := []struct {
		name    string
		raw     string
		skipped int
		failed  int
	}{
		{"plainly another product's row", `{"id":"a1","type":"user_login"}`, 1, 0},
		{"type repeated", `{"id":"a2","type":"user_login","type":"anthropic_access"}`, 0, 1},
		{"member differing only in case", `{"id":"a3","Type":"user_login"}`, 0, 1},
		{"case variant of ours", `{"id":"a4","type":"Anthropic_Access"}`, 0, 1},
		{"versioned name claiming ours", `{"id":"a5","type":"anthropic_access_v2"}`, 0, 1},
		{"no type at all", `{"id":"a6"}`, 0, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rep, err := e.v.VerifyEvents(context.Background(), nil, []json.RawMessage{json.RawMessage(c.raw)})
			if err != nil {
				t.Fatal(err)
			}
			if rep.Events.SkippedOtherTypes != c.skipped || len(rep.Events.Failed) != c.failed {
				t.Fatalf("skipped=%d failed=%d, want %d/%d: %+v",
					rep.Events.SkippedOtherTypes, len(rep.Events.Failed), c.skipped, c.failed, rep.Events)
			}
		})
	}
}
