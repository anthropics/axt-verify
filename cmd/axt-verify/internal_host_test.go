// Copyright 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

//go:build axtverify_internal

package main

import (
	"io"
	"testing"

	"github.com/anthropics/axt-verify/compliance"
)

// Under the internal build tag the environment variable is read, so our own
// acceptance runs can point at a deployment that is not production — and it
// goes through the same validation any base URL does.
func TestInternalBuild_HostEnvironmentVariableIsHonoured(t *testing.T) {
	f := setup(t)
	t.Setenv("AXT_VERIFY_API_BASE_URL", f.srv.HTTP.URL)
	pointAt(t, readInternalBaseURL())

	o := trustOptions{org: orgUUID, baseURL: internalBaseURL, logKey: f.logKey,
		stderr: io.Discard, logf: func(string, ...any) {}}
	_, client, _, err := o.resolve("sk-ant-test")
	if err != nil {
		t.Fatal(err)
	}
	if client.BaseURL != f.srv.HTTP.URL {
		t.Fatalf("base URL %q, want the fake at %q", client.BaseURL, f.srv.HTTP.URL)
	}
	if client.BaseURL == compliance.DefaultBaseURL {
		t.Fatal("the override did nothing")
	}

	// Still validated: an override is not a way around the https rule.
	pointAt(t, "http://insecure.example")
	o.baseURL = internalBaseURL
	if _, _, _, err := o.resolve("sk-ant-test"); err == nil {
		t.Fatal("a plain-http override was accepted")
	}
}
