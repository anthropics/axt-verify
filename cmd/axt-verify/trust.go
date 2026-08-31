// Copyright 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/anthropics/axt-verify"
	"github.com/anthropics/axt-verify/checkpoint"
	"github.com/anthropics/axt-verify/compliance"
)

// logKeyEnv lets a cron line set the override once.
const logKeyEnv = "AXT_VERIFY_LOG_KEY"

var canonicalUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// trustOptions is everything that decides what this run verifies, and where.
type trustOptions struct {
	org, baseURL, logKey string
	stderr               io.Writer
	// logf is the quiet-gated progress writer: a cron line that asked for
	// silence gets silence.
	logf func(string, ...any)
}

// resolve turns the flags into a checkpoint verifier and an API client.
// Trust comes from the key this release ships for the origin prefix, or from
// --log-key when an operator overrides it; nothing is ever fetched to learn a
// key, so at no point does the party being verified say what it should be
// verified against.
func (o trustOptions) resolve(apiKey string) (*checkpoint.Verifier, *compliance.Client, bool, error) {
	if err := checkBaseURL(o.baseURL); err != nil {
		return nil, nil, false, err
	}
	if o.org == "" {
		return nil, nil, false, usageError{fmt.Errorf("--org is required: the organization whose log to verify")}
	}
	if !canonicalUUID.MatchString(o.org) {
		hint := ""
		if strings.HasPrefix(o.org, "org_") {
			hint = " — that is the tagged id; use the organization_uuid the Activity Feed serves"
		}
		return nil, nil, false, usageError{fmt.Errorf("--org %q must be a canonical lowercase UUID%s", o.org, hint)}
	}
	// Without an override the origin is the production one and the key is
	// the one this release ships. With an override the key's own name is the
	// origin — a note verifier is named for the log it verifies, so the two
	// cannot disagree — and it must still be this organization's log.
	key, builtin, source := o.logKey, false, "--log-key"
	origin := axtverify.Origin(o.org)
	if key == "" {
		k, ok := axtverify.BuiltinVerifierKey(o.org)
		if !ok {
			return nil, nil, false, usageError{errors.New("this release carries no log key; upgrade axt-verify, or pass --log-key")}
		}
		key, builtin, source = k, true, "the built-in log key"
	} else {
		name, ok := verifierKeyName(key)
		if !ok {
			return nil, nil, false, usageError{errors.New("--log-key is not a note-verifier key: expected <name>+<key hash>+<base64>")}
		}
		if !strings.HasSuffix(name, "/"+o.org) {
			return nil, nil, false, usageError{fmt.Errorf("--log-key must be named <prefix>/<org>, and this one is named %q, which is not organization %s", name, o.org)}
		}
		origin = name
	}

	// A key whose name is not this origin would verify signatures from
	// somewhere else entirely, so the policy is what enforces the match.
	cpv, err := checkpoint.New(checkpoint.Policy{Origin: origin, LogKey: key})
	if err != nil {
		return nil, nil, false, usageError{fmt.Errorf("%s: %w", source, err)}
	}
	if builtin {
		fp, _ := axtverify.BuiltinFingerprint()
		o.logf("using built-in log key for %s (sha256:%s)", printable(axtverify.OriginPrefix), printable(fp))
	} else {
		// Not gated by --quiet: --log-key can arrive from the environment,
		// so a swapped key would otherwise change what this run trusts
		// without leaving a trace in the log the run writes.
		name, _ := verifierKeyName(key)
		hash, _ := axtverify.KeyHash(key)
		line := fmt.Sprintf("verifying with a supplied log key, not the built-in one: %s (key hash %s",
			printable(name), printable(hash))
		// The published fingerprint is SHA-256 of the SPKI, which only the
		// ECDSA encoding carries; printing a hash of an Ed25519 key's raw
		// bytes would name a value nobody published.
		if fp, ok := axtverify.FingerprintOfVerifierKey(key); ok {
			line += ", sha256:" + printable(fp)
		}
		fmt.Fprintln(o.stderr, line+")")
	}

	base := o.baseURL
	if base == "" {
		base = compliance.DefaultBaseURL
	}
	client := &compliance.Client{BaseURL: base, APIKey: apiKey, OrgUUID: o.org, UserAgent: "axt-verify/" + buildVersion()}
	client.HTTP = httpClient
	return cpv, client, builtin, nil
}

// permanentRequestError reports whether the API rejected the credential
// itself, which no amount of rerunning will fix.
//
// Only 401 and 403 count. A 400 is deliberately excluded: it is an answer a
// serving path chooses, and treating it as "fix your invocation" would let a
// log answer 400 to the proof request that would expose it and have the
// refusal reported as the operator's mistake. A 404 is excluded too — the log
// of a newly enrolled organization appears on its own.
func permanentRequestError(err error) bool {
	var se *compliance.StatusError
	if !errors.As(err, &se) {
		return false
	}
	return se.StatusCode == http.StatusUnauthorized || se.StatusCode == http.StatusForbidden
}

// checkBaseURL refuses anything that is not a bare https origin: userinfo
// would go out as an Authorization header (and lets another host read as
// api.anthropic.com@…), and a path would be joined under every endpoint.
func checkBaseURL(base string) error {
	if base == "" {
		return nil
	}
	if u, err := url.Parse(strings.TrimRight(base, "/")); err != nil || u.Scheme != "https" || u.Host == "" ||
		u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return usageError{fmt.Errorf("the API base URL must be https://host[:port] and nothing more, not %q", base)}
	}
	return nil
}

// logKeyFrom prefers the flag and falls back to the environment, which is
// what a cron line can set once.
func logKeyFrom(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	return os.Getenv(logKeyEnv)
}

// verifierKeyName is the name a note-verifier key carries — everything before
// the key hash. For this log that name is the origin.
func verifierKeyName(vkey string) (string, bool) {
	parts := strings.SplitN(strings.TrimSpace(vkey), "+", 3)
	if len(parts) != 3 || parts[0] == "" {
		return "", false
	}
	return parts[0], true
}
