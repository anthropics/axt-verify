// Copyright 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package axtverify_test

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/note"

	"github.com/anthropics/axt-verify"
	"github.com/anthropics/axt-verify/checkpoint"
)

// What this release ships has to be usable as trust on its own: it must build
// a policy the checkpoint verifier accepts.
func TestBuiltinKeys_UsableAsPinnedTrust(t *testing.T) {
	const org = "25f6429a-3293-49bf-afed-cb312911554b"
	vkey, ok := axtverify.BuiltinVerifierKey(org)
	if !ok {
		t.Fatal("this release ships no log key at all")
	}
	origin := axtverify.Origin(org)
	if origin != axtverify.OriginPrefix+"/"+org {
		t.Fatalf("origin %q", origin)
	}
	if _, err := checkpoint.New(checkpoint.Policy{Origin: origin, LogKey: vkey}); err != nil {
		t.Fatalf("the shipped key does not make a usable policy: %v", err)
	}
	fp, ok := axtverify.BuiltinFingerprint()
	if !ok || len(fp) != 64 {
		t.Fatalf("fingerprint %q", fp)
	}
	// The verifier string must carry the key hash the note format derives, or
	// a checkpoint's signature would never be matched to it.
	if !strings.HasPrefix(vkey, origin+"+"+fp[:8]) {
		t.Fatalf("verifier key %q does not carry the key hash from %s", vkey, fp)
	}
}

func TestBuiltinKeys_Production(t *testing.T) {
	vkey, ok := axtverify.BuiltinVerifierKey("25f6429a-3293-49bf-afed-cb312911554b")
	if !ok {
		t.Fatal("no built-in key for production: every default invocation would exit 2")
	}
	if !strings.Contains(vkey, "+1dff5fe4+") {
		t.Fatalf("production key hash changed: %s", vkey)
	}
	if fp, _ := axtverify.BuiltinFingerprint(); fp != "1dff5fe420d49743fe444a04fc17f818eea856699dec2ebbc24df15602c74a58" {
		t.Fatalf("production fingerprint changed: %s (README's key table must change with it)", fp)
	}
}

// VerifierKeyFor is this module's only encoder for the note-verifier format:
// "<origin>+<8 hex key hash>+base64(0x02 || SPKI)". Whoever signs a checkpoint
// and whoever verifies it must derive the same string from the same key, or a
// signature would never be matched to the key that made it — so this pins the
// exact bytes for a fixed key. The key is a throwaway generated for the test;
// nothing here depends on which key it is.
func TestVerifierKeyFor_MatchesTheNoteFormat(t *testing.T) {
	der, err := base64.StdEncoding.DecodeString("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4Y2Ux7quyahtKp3v01vgJ6oE9NNOp97ZiYxkDnEG8oS3WnfNLnHohIld1a9lHle9mpOPGHsj29oJsoeK+Qk09g==")
	if err != nil {
		t.Fatal(err)
	}
	got := axtverify.VerifierKeyFor("example.test/org", der)
	want := "example.test/org+a6fbbac1+AjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOGNlMe6rsmobSqd79Nb4CeqBPTTTqfe2YmMZA5xBvKEt1p3zS5x6ISJXdWvZR5XvZqTjxh7I9vaCbKHivkJNPY="
	if got != want {
		t.Fatalf("verifier key %q, want %q", got, want)
	}
	if fp := axtverify.Fingerprint(der); !strings.HasPrefix(fp, "a6fbbac1") {
		t.Fatalf("fingerprint %q does not start with the key hash", fp)
	}
}

// The published fingerprint is SHA-256 of the SPKI, and only the ECDSA
// encoding this log signs with carries one. A standard Ed25519 note key (the
// signed-note default) carries the raw 32-byte key instead, so no published
// fingerprint can be derived from it, and the key hash is the value that is
// meaningful for both.
func TestFingerprintOfVerifierKey_OnlyWhereItIsDerivable(t *testing.T) {
	_, ed, err := note.GenerateKey(rand.Reader, "example.test/org")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := axtverify.FingerprintOfVerifierKey(ed); ok {
		t.Fatalf("an Ed25519 note key reported a published fingerprint: %s", ed)
	}
	if hash, ok := axtverify.KeyHash(ed); !ok || len(hash) != 8 {
		t.Fatalf("key hash %q for %s", hash, ed)
	}

	// The ECDSA form this log uses does carry one, and it is the fingerprint
	// the README publishes.
	prod, ok := axtverify.BuiltinVerifierKey("25f6429a-3293-49bf-afed-cb312911554b")
	if !ok {
		t.Fatal("no built-in key")
	}
	fp, ok := axtverify.FingerprintOfVerifierKey(prod)
	if !ok {
		t.Fatal("the shipped key reported no fingerprint")
	}
	want, _ := axtverify.BuiltinFingerprint()
	if fp != want {
		t.Fatalf("fingerprint %s, want the published %s", fp, want)
	}
}
