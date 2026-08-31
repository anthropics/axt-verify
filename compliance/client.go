// Copyright 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

// Package compliance is a client for the slice of the Anthropic Compliance
// API that axt-verify reads: an organization's transparency log
// (/v1/compliance/transparency_log/…) and its Access Transparency events on
// the activity feed (/v1/compliance/activities). It authenticates with a
// Compliance Access Key and treats everything it receives as untrusted
// input to be verified by the caller.
package compliance

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultBaseURL is the public API host.
	DefaultBaseURL = "https://api.anthropic.com"
	// DefaultAPIVersion is sent as the anthropic-version header.
	DefaultAPIVersion = "2023-06-01"

	logPath        = "/v1/compliance/transparency_log/"
	activitiesPath = "/v1/compliance/activities"

	// Response caps. A conforming checkpoint is a few hundred bytes and a
	// proof at most 64 hashes; the feed page cap covers the maximum page
	// size with headroom. Oversize bodies fail rather than buffer.
	maxCheckpointBytes = 64 << 10
	maxProofBytes      = 1 << 20
	maxPageBytes       = 64 << 20
	maxErrorBytes      = 16 << 10

	defaultAttempts = 5
	backoffBase     = 500 * time.Millisecond
	backoffCap      = 20 * time.Second
	// statusOverloaded is the API's load-shed status; net/http has no
	// constant for it.
	statusOverloaded = 529
	retryAfterCap    = 60 * time.Second
)

// Client reads one organization's log and feed.
type Client struct {
	// BaseURL is the API origin, e.g. https://api.anthropic.com.
	BaseURL string
	// APIKey is the Compliance Access Key, sent as x-api-key.
	APIKey string
	// OrgUUID names the organization whose log is read; sent as
	// organization_id / organization_ids[] on every request.
	OrgUUID string
	// APIVersion is the anthropic-version header value.
	APIVersion string
	// UserAgent is sent verbatim.
	UserAgent string
	// HTTP is the transport; nil means a client with a 30s timeout.
	HTTP *http.Client
	// Attempts bounds tries per request on retryable failures (429, 502,
	// 503, 504, transport errors); zero means 5.
	Attempts int
	// Sleep is time.Sleep unless replaced by tests.
	Sleep func(context.Context, time.Duration)
	// AllowInsecure permits a non-https BaseURL — only for tests against a
	// local server. The API key travels in a header.
	AllowInsecure bool
}

// StatusError is a non-2xx answer.
type StatusError struct {
	StatusCode int
	// Type and Message come from the API's JSON error envelope when present.
	Type, Message string
	RequestID     string
}

func (e *StatusError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP %d", e.StatusCode)
	if e.Type != "" {
		fmt.Fprintf(&b, " %s", e.Type)
	}
	if e.Message != "" {
		fmt.Fprintf(&b, ": %s", e.Message)
	}
	if e.RequestID != "" {
		fmt.Fprintf(&b, " (request-id %s)", e.RequestID)
	}
	return b.String()
}

// ErrTransient wraps the last error after retryable failures exhausted the
// attempt budget; the operation may succeed if rerun later.
var ErrTransient = errors.New("transient API failure")

// ErrResponse means a 2xx body was not the documented shape.
var ErrResponse = errors.New("malformed API response")

// IsNotFound reports whether err is an HTTP 404 from the API.
func IsNotFound(err error) bool {
	var se *StatusError
	return errors.As(err, &se) && se.StatusCode == http.StatusNotFound
}

// Proof is an inclusion or consistency proof response: audit-path hashes
// ordered leaf to root, and the signed checkpoint they were computed
// against.
type Proof struct {
	LeafIndex  uint64
	Hashes     [][]byte
	Checkpoint []byte
}

// Checkpoint fetches the organization's latest signed checkpoint.
func (c *Client) Checkpoint(ctx context.Context) ([]byte, error) {
	return c.get(ctx, logPath+"checkpoint", c.orgQuery(), maxCheckpointBytes)
}

// Inclusion fetches the inclusion proof for the leaf at index against the
// latest checkpoint. A 404 (IsNotFound) means no published checkpoint
// covers index yet — or the organization has no log.
func (c *Client) Inclusion(ctx context.Context, index uint64) (Proof, error) {
	q := c.orgQuery()
	q.Set("leaf_index", strconv.FormatUint(index, 10))
	return c.proof(ctx, "inclusion", q, "transparency_log_inclusion_proof")
}

// Consistency fetches the consistency proof from tree size from to the
// latest checkpoint.
func (c *Client) Consistency(ctx context.Context, from uint64) (Proof, error) {
	q := c.orgQuery()
	q.Set("from", strconv.FormatUint(from, 10))
	return c.proof(ctx, "consistency", q, "transparency_log_consistency_proof")
}

func (c *Client) proof(ctx context.Context, endpoint string, q url.Values, wantType string) (Proof, error) {
	body, err := c.get(ctx, logPath+endpoint, q, maxProofBytes)
	if err != nil {
		return Proof{}, err
	}
	var resp struct {
		Type       string   `json:"type"`
		LeafIndex  *uint64  `json:"leaf_index"`
		Hashes     []string `json:"hashes"`
		Checkpoint *string  `json:"checkpoint"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return Proof{}, fmt.Errorf("%w: %s: %w", ErrResponse, endpoint, err)
	}
	if resp.Type != wantType || resp.Hashes == nil || resp.Checkpoint == nil {
		return Proof{}, fmt.Errorf("%w: %s: missing or mistyped fields", ErrResponse, endpoint)
	}
	p := Proof{Checkpoint: []byte(*resp.Checkpoint), Hashes: make([][]byte, len(resp.Hashes))}
	if resp.LeafIndex != nil {
		p.LeafIndex = *resp.LeafIndex
	}
	for i, h := range resp.Hashes {
		if p.Hashes[i], err = base64.StdEncoding.DecodeString(h); err != nil {
			return Proof{}, fmt.Errorf("%w: %s: hash %d: %w", ErrResponse, endpoint, i, err)
		}
	}
	return p, nil
}

// FeedQuery selects a window of the organization's Access Transparency
// events, oldest first.
type FeedQuery struct {
	// Types are the activity types to list (activity_types[]).
	Types []string
	// NotBefore, when non-zero, is sent as created_at.gte.
	NotBefore time.Time
	// AfterID continues from a previous page's LastID.
	AfterID string
	// Limit is the page size; zero uses the API default.
	Limit int
}

// Page is one activity-feed page. Events are raw JSON objects exactly as
// served — the form leaf canonicalization is defined over.
type Page struct {
	Events  []json.RawMessage
	HasMore bool
	LastID  string
}

// Activities lists one page of the feed.
func (c *Client) Activities(ctx context.Context, fq FeedQuery) (Page, error) {
	q := url.Values{}
	q.Set("organization_ids[]", c.OrgUUID)
	q.Set("order", "asc")
	for _, t := range fq.Types {
		q.Add("activity_types[]", t)
	}
	if !fq.NotBefore.IsZero() {
		q.Set("created_at.gte", fq.NotBefore.UTC().Format(time.RFC3339Nano))
	}
	if fq.AfterID != "" {
		q.Set("after_id", fq.AfterID)
	}
	if fq.Limit > 0 {
		q.Set("limit", strconv.Itoa(fq.Limit))
	}
	body, err := c.get(ctx, activitiesPath, q, maxPageBytes)
	if err != nil {
		return Page{}, err
	}
	var resp struct {
		Data    []json.RawMessage `json:"data"`
		HasMore bool              `json:"has_more"`
		LastID  *string           `json:"last_id"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return Page{}, fmt.Errorf("%w: activities: %w", ErrResponse, err)
	}
	if resp.Data == nil {
		return Page{}, fmt.Errorf("%w: activities: no data array", ErrResponse)
	}
	if fq.Limit > 0 && len(resp.Data) > fq.Limit {
		// A page larger than the one asked for is the server setting the
		// caller's memory budget.
		return Page{}, fmt.Errorf("%w: activities: %d events in a page of at most %d", ErrResponse, len(resp.Data), fq.Limit)
	}
	p := Page{Events: resp.Data, HasMore: resp.HasMore}
	if resp.LastID != nil {
		p.LastID = *resp.LastID
	}
	if p.HasMore && p.LastID == "" {
		return Page{}, fmt.Errorf("%w: activities: has_more without last_id", ErrResponse)
	}
	return p, nil
}

func (c *Client) orgQuery() url.Values {
	return url.Values{"organization_id": {c.OrgUUID}}
}

func (c *Client) get(ctx context.Context, path string, q url.Values, maxBytes int64) ([]byte, error) {
	base, err := url.Parse(strings.TrimRight(c.BaseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("invalid base URL %q: %w", c.BaseURL, err)
	}
	insecureOK := c.AllowInsecure && base.Scheme == "http"
	if base.Host == "" || (base.Scheme != "https" && !insecureOK) ||
		base.User != nil || base.Path != "" || base.RawQuery != "" || base.Fragment != "" {
		return nil, fmt.Errorf("invalid base URL %q: must be https://host[:port] and nothing more", c.BaseURL)
	}
	u := base.JoinPath(path)
	u.RawQuery = q.Encode()

	httpc := c.HTTP
	if httpc != nil {
		// A caller's client gets the same refusal whatever redirect policy
		// it came with — a policy that returns nil would hand the API key to
		// whoever named the Location. Copy rather than mutate what the
		// caller handed us.
		cp := *httpc
		cp.CheckRedirect = refuseRedirect
		httpc = &cp
	}
	if httpc == nil {
		// Go forwards a custom header like x-api-key across a redirect,
		// including to another host or scheme. None of the four endpoints
		// redirects, so treat a 3xx as the answer and let it fail as an
		// unexpected status rather than hand the key to whoever named the
		// Location.
		httpc = &http.Client{Timeout: 30 * time.Second, CheckRedirect: refuseRedirect}
	}
	attempts := c.Attempts
	if attempts <= 0 {
		attempts = defaultAttempts
	}
	sleep := c.Sleep
	if sleep == nil {
		sleep = sleepCtx
	}

	var last error
	for attempt := range attempts {
		if attempt > 0 {
			sleep(ctx, backoff(attempt, last))
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		body, retry, err := c.do(ctx, httpc, u.String(), maxBytes)
		if err == nil {
			return body, nil
		}
		if !retry || ctx.Err() != nil {
			return nil, err
		}
		last = err
	}
	return nil, fmt.Errorf("%w after %d attempts: %w", ErrTransient, attempts, last)
}

// refuseRedirect answers a 3xx rather than replaying the request — Go
// forwards a custom header like x-api-key across a redirect, to any host or
// scheme the Location names, and none of the four endpoints redirects.
func refuseRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func (c *Client) do(ctx context.Context, httpc *http.Client, u string, maxBytes int64) (body []byte, retry bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("x-api-key", c.APIKey)
	req.Header.Set("anthropic-version", nonEmpty(c.APIVersion, DefaultAPIVersion))
	req.Header.Set("user-agent", nonEmpty(c.UserAgent, "axt-verify"))
	resp, err := httpc.Do(req)
	if err != nil {
		// url.Error embeds the URL, which carries no secret (the key is a
		// header), but keep messages to the operation and cause.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, true, fmt.Errorf("GET %s: %w", req.URL.Path, err)
	}
	defer resp.Body.Close() //nolint:errcheck // body fully read or abandoned below

	if resp.StatusCode/100 == 2 {
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
		if err != nil {
			return nil, true, fmt.Errorf("GET %s: reading body: %w", req.URL.Path, err)
		}
		if int64(len(body)) > maxBytes {
			return nil, false, fmt.Errorf("%w: GET %s: body exceeds %d bytes", ErrResponse, req.URL.Path, maxBytes)
		}
		return body, false, nil
	}

	se := &StatusError{StatusCode: resp.StatusCode, RequestID: resp.Header.Get("request-id")}
	if eb, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBytes)); len(eb) > 0 {
		var env struct {
			Error struct {
				Type    string `json:"type"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(eb, &env) == nil {
			se.Type, se.Message = env.Error.Type, env.Error.Message
		}
	}
	switch resp.StatusCode {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout, statusOverloaded:
		after, ok := retryAfter(resp.Header.Get("retry-after"))
		return nil, true, &retryable{se, after, ok}
	}
	return nil, false, se
}

// retryable is a StatusError worth retrying, with the server's retry-after
// hint when it sent one.
type retryable struct {
	*StatusError
	after    time.Duration
	hasAfter bool
}

func backoff(attempt int, last error) time.Duration {
	var r *retryable
	if errors.As(last, &r) && r.hasAfter {
		return r.after
	}
	// Clamp the exponent, not just the product: Attempts is a caller's knob,
	// and a large one would shift the base past int64 and wrap negative.
	d := backoffCap
	if shift := attempt - 1; shift < 32 {
		d = min(backoffBase<<shift, backoffCap)
	}
	// Full jitter.
	return time.Duration(rand.Int64N(int64(d)) + 1)
}

func retryAfter(h string) (time.Duration, bool) {
	if h == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(strings.TrimSpace(h)); err == nil && secs >= 0 {
		// Clamp the seconds, not the product: a large enough value would
		// overflow the multiplication and come back negative, which min
		// then keeps as the "backoff".
		if secs > int(retryAfterCap/time.Second) {
			return retryAfterCap, true
		}
		return min(time.Duration(secs)*time.Second, retryAfterCap), true
	}
	if t, err := http.ParseTime(h); err == nil {
		return min(max(time.Until(t), 0), retryAfterCap), true
	}
	return 0, false
}

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func nonEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
