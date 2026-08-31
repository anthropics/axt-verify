// Copyright 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package compliance_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/anthropics/axt-verify/compliance"
)

// Go forwards a custom header such as x-api-key across a redirect, to any
// host or scheme the Location names. None of the API's four reads redirects,
// so the client must answer a 3xx rather than hand the key on.
func TestClient_DoesNotFollowRedirects(t *testing.T) {
	var got string
	target := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("x-api-key")
	}))
	defer target.Close()
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusFound)
	}))
	defer front.Close()

	c := &compliance.Client{
		BaseURL:       front.URL,
		APIKey:        "sk-ant-secret",
		OrgUUID:       "25f6429a-3293-49bf-afed-cb312911554b",
		AllowInsecure: true,
		Sleep:         func(context.Context, time.Duration) {},
	}
	if _, err := c.Checkpoint(context.Background()); err == nil {
		t.Fatal("a redirect was accepted as an answer")
	}
	if got != "" {
		t.Fatalf("x-api-key %q reached the redirect target", got)
	}
}

// A caller's own redirect policy must not put the API key back on the wire to
// wherever a Location names.
func TestClient_RefusesRedirectsEvenWithACallerPolicy(t *testing.T) {
	var leaked string
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("x-api-key")
		w.WriteHeader(http.StatusOK)
	}))
	defer elsewhere.Close()
	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL, http.StatusFound)
	}))
	defer redirecting.Close()

	c := &compliance.Client{
		BaseURL: redirecting.URL, APIKey: "sk-ant-secret",
		OrgUUID: "25f6429a-3293-49bf-afed-cb312911554b", UserAgent: "test",
		AllowInsecure: true,
		Sleep:         func(context.Context, time.Duration) {},
	}
	// The caller brings the common "follow it" policy, which must not put
	// the key back on the wire.
	c.HTTP = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return nil }}
	if _, err := c.Checkpoint(context.Background()); err == nil {
		t.Fatal("a redirect was followed")
	}
	if leaked != "" {
		t.Fatalf("the API key was sent to the redirect target: %q", leaked)
	}
}
