// Copyright 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package testlog

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// APIKey is the key the fake accepts.
const APIKey = "sk-ant-test-compliance-key"

// Server fakes the Compliance API endpoints axt-verify reads, over one Log.
type Server struct {
	Log     *Log
	OrgUUID string
	HTTP    *httptest.Server

	mu sync.Mutex
	// Published is the tree size the served checkpoint commits to; proofs
	// are computed against it. Publish() advances it to the log's size.
	Published uint64
	// Fault hooks. Zero values serve honestly.
	CheckpointOverride []byte            // served verbatim by /checkpoint
	InclusionAgainst   map[uint64]uint64 // leaf index → tree size its proof (and embedded checkpoint) use
	InclusionLeafSwap  map[uint64]uint64 // leaf index → index whose proof is served instead
	InclusionIndexLie  map[uint64]uint64 // leaf index → the leaf_index the answer reports
	ConsistencyGarbage bool              // /consistency serves a wrong proof
	FailNext           map[string][]int  // endpoint name → statuses to return before serving honestly
	FeedStuckCursor    bool              // /activities always reports more, with a cursor that never moves
	ProofsAhead        bool              // proof endpoints answer at the log's real size while /checkpoint lags at Published
	FeedStuckWithNew   bool              // /activities holds last_id constant while serving one new event per page
	Events             []json.RawMessage // the activity feed, any order
	Requests           map[string]int    // endpoint name → count
	stuckSeq           int
}

// NewServer starts a fake over l for the organization its origin names.
func NewServer(l *Log) *Server {
	org := l.Origin[strings.LastIndex(l.Origin, "/")+1:]
	s := &Server{Log: l, OrgUUID: org, Requests: map[string]int{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/compliance/transparency_log/checkpoint", s.wrap("checkpoint", s.checkpoint))
	mux.HandleFunc("GET /v1/compliance/transparency_log/inclusion", s.wrap("inclusion", s.inclusion))
	mux.HandleFunc("GET /v1/compliance/transparency_log/consistency", s.wrap("consistency", s.consistency))
	mux.HandleFunc("GET /v1/compliance/activities", s.wrap("activities", s.activities))
	s.HTTP = httptest.NewTLSServer(mux)
	return s
}

func (s *Server) Close() { s.HTTP.Close() }

// Client returns an HTTP client that trusts the fake's TLS certificate.
func (s *Server) Client() *http.Client { return s.HTTP.Client() }

// Publish makes the served checkpoint cover everything appended so far.
func (s *Server) Publish() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Published = s.Log.Size()
}

func apiError(w http.ResponseWriter, code int, typ, msg string) {
	w.Header().Set("content-type", "application/json")
	w.Header().Set("request-id", "req_test")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "error", "error": map[string]string{"type": typ, "message": msg}})
}

func (s *Server) wrap(name string, h func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.Requests[name]++
		if q := s.FailNext[name]; len(q) > 0 {
			s.FailNext[name] = q[1:]
			s.mu.Unlock()
			if q[0] == http.StatusTooManyRequests {
				w.Header().Set("retry-after", "0")
			}
			apiError(w, q[0], "injected_error", "injected")
			return
		}
		s.mu.Unlock()

		if r.Header.Get("x-api-key") != APIKey {
			apiError(w, http.StatusUnauthorized, "authentication_error", "invalid x-api-key")
			return
		}
		if r.Header.Get("anthropic-version") == "" {
			apiError(w, http.StatusBadRequest, "invalid_request_error", "anthropic-version header is required")
			return
		}
		org := r.URL.Query().Get("organization_id")
		if name == "activities" {
			org = r.URL.Query().Get("organization_ids[]")
		}
		if org != "" && org != s.OrgUUID {
			apiError(w, http.StatusNotFound, "not_found_error", "not found")
			return
		}
		h(w, r)
	}
}

func (s *Server) checkpoint(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	raw, size := s.CheckpointOverride, s.Published
	s.mu.Unlock()
	if raw == nil {
		raw = s.Log.Checkpoint(size)
	}
	w.Header().Set("content-type", "text/plain; charset=utf-8")
	_, _ = w.Write(raw)
}

func (s *Server) inclusion(w http.ResponseWriter, r *http.Request) {
	idx, err := strconv.ParseUint(r.URL.Query().Get("leaf_index"), 10, 64)
	if err != nil {
		apiError(w, http.StatusBadRequest, "invalid_request_error", "leaf_index must be a non-negative integer")
		return
	}
	s.mu.Lock()
	size := s.Published
	if against, ok := s.InclusionAgainst[idx]; ok {
		size = against
	}
	proofIdx := idx
	if swap, ok := s.InclusionLeafSwap[idx]; ok {
		proofIdx = swap
	}
	reported := idx
	if lie, ok := s.InclusionIndexLie[idx]; ok {
		reported = lie
	}
	s.mu.Unlock()
	if idx >= size {
		apiError(w, http.StatusNotFound, "not_found_error", "not found")
		return
	}
	s.writeProof(w, "transparency_log_inclusion_proof", &reported, s.Log.InclusionProof(proofIdx, size), s.Log.Checkpoint(size))
}

func (s *Server) consistency(w http.ResponseWriter, r *http.Request) {
	from, err := strconv.ParseUint(r.URL.Query().Get("from"), 10, 64)
	s.mu.Lock()
	size, garbage := s.Published, s.ConsistencyGarbage
	if s.ProofsAhead {
		size = s.Log.Size()
	}
	s.mu.Unlock()
	if err != nil || from < 1 || from > size {
		apiError(w, http.StatusBadRequest, "invalid_request_error", "from must be in [1, tree size]")
		return
	}
	hashes := s.Log.ConsistencyProof(from, size)
	if garbage && len(hashes) > 0 {
		hashes[0] = append([]byte{hashes[0][0] ^ 1}, hashes[0][1:]...)
	}
	s.writeProof(w, "transparency_log_consistency_proof", nil, hashes, s.Log.Checkpoint(size))
}

func (s *Server) writeProof(w http.ResponseWriter, typ string, idx *uint64, hashes [][]byte, cp []byte) {
	resp := map[string]any{"type": typ, "checkpoint": string(cp)}
	b64 := make([]string, len(hashes))
	for i, h := range hashes {
		b64[i] = base64.StdEncoding.EncodeToString(h)
	}
	resp["hashes"] = b64
	if idx != nil {
		resp["leaf_index"] = *idx
	}
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

type feedRow struct {
	id, typ string
	created time.Time
	raw     json.RawMessage
}

func (s *Server) activities(w http.ResponseWriter, r *http.Request) {
	if s.FeedStuckWithNew {
		s.mu.Lock()
		s.stuckSeq++
		raw := json.RawMessage(fmt.Sprintf(`{"id":"activity_stuck_%04d","type":"cmek_preserve","created_at":%q,"transparency_log_leaf_index":null}`, s.stuckSeq, time.Unix(0, 0).UTC().Add(time.Duration(s.stuckSeq)*time.Second).Format(time.RFC3339Nano)))
		s.mu.Unlock()
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []json.RawMessage{raw}, "has_more": true, "first_id": nil, "last_id": "cursor:stuck"})
		return
	}
	if s.FeedStuckCursor {
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []json.RawMessage{}, "has_more": true, "first_id": nil, "last_id": "cursor:stuck"})
		return
	}
	q := r.URL.Query()
	if q.Get("order") != "asc" {
		apiError(w, http.StatusBadRequest, "invalid_request_error", "fake serves order=asc only")
		return
	}
	limit := 100
	if l := q.Get("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 1 || n > 5000 {
			apiError(w, http.StatusBadRequest, "invalid_request_error", "bad limit")
			return
		}
		limit = n
	}
	var notBefore time.Time
	if g := q.Get("created_at.gte"); g != "" {
		t, err := time.Parse(time.RFC3339Nano, g)
		if err != nil {
			apiError(w, http.StatusBadRequest, "invalid_request_error", "bad created_at.gte")
			return
		}
		notBefore = t
	}
	types := map[string]bool{}
	for _, t := range q["activity_types[]"] {
		types[t] = true
	}

	s.mu.Lock()
	rows := make([]feedRow, 0, len(s.Events))
	for _, raw := range s.Events {
		var ev struct {
			ID, Type  string
			CreatedAt time.Time `json:"created_at"`
		}
		if err := json.Unmarshal(raw, &ev); err != nil {
			panic(fmt.Sprintf("testlog: bad feed event: %v", err))
		}
		rows = append(rows, feedRow{ev.ID, ev.Type, ev.CreatedAt, raw})
	}
	s.mu.Unlock()
	sort.Slice(rows, func(i, j int) bool {
		if !rows[i].created.Equal(rows[j].created) {
			return rows[i].created.Before(rows[j].created)
		}
		return rows[i].id < rows[j].id
	})

	after := q.Get("after_id")
	var out []json.RawMessage
	var lastID string
	hasMore := false
	passedCursor := after == ""
	for _, row := range rows {
		if !passedCursor {
			if "cursor:"+row.id == after {
				passedCursor = true
			}
			continue
		}
		if (len(types) > 0 && !types[row.typ]) || row.created.Before(notBefore) {
			continue
		}
		if len(out) == limit {
			hasMore = true
			break
		}
		out = append(out, row.raw)
		lastID = "cursor:" + row.id
	}
	if !passedCursor {
		apiError(w, http.StatusBadRequest, "invalid_request_error", "unknown after_id cursor")
		return
	}
	resp := map[string]any{"data": append([]json.RawMessage{}, out...), "has_more": hasMore, "first_id": nil, "last_id": nil}
	if lastID != "" {
		resp["last_id"] = lastID
	}
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
