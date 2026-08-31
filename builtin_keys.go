// Copyright 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package axtverify

import "encoding/base64"

// OriginPrefix is the production log's origin name, the part before the
// organization UUID. It is a constant rather than a setting: a customer
// verifies their own log, and there is only one production deployment of it.
const OriginPrefix = "axt.anthropic.com"

// builtinKeySPKIBase64 is the production log's public signing key, as its DER
// SubjectPublicKeyInfo. Shipping it inside the binary is what makes the common
// case need no key exchange at all: the binary already knows what the log
// signs with, so nothing has to be fetched from the party being verified.
//
// It changes only with a release — a rotation is a new release carrying the
// new key — and TestBuiltinKeys_Production pins its key hash and fingerprint
// so it cannot move or disappear without a test saying so.
//
// Production log, in service since 2026-08-17 (key hash 1dff5fe4).
const builtinKeySPKIBase64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEv+om+waG3qNuK1X6+lE2646npTSO5xKfJOAvmlnfKPjuQEhvVDT387p5U71LWZYzrrBM+gioeaLI56reiD8xjA=="

// Origin is the log origin for an organization: the fixed prefix and the
// organization's UUID, which is exactly the line every checkpoint must carry.
func Origin(orgUUID string) string { return OriginPrefix + "/" + orgUUID }

// BuiltinVerifierKey is the note-verifier string this release verifies an
// organization's log with.
func BuiltinVerifierKey(orgUUID string) (string, bool) {
	der, ok := builtinDER()
	if !ok {
		return "", false
	}
	return VerifierKeyFor(Origin(orgUUID), der), true
}

// BuiltinFingerprint is the published fingerprint of the key this release
// ships, so the tool can name what it is trusting.
func BuiltinFingerprint() (string, bool) {
	der, ok := builtinDER()
	if !ok {
		return "", false
	}
	return Fingerprint(der), true
}

func builtinDER() ([]byte, bool) {
	der, err := base64.StdEncoding.DecodeString(builtinKeySPKIBase64)
	if err != nil {
		return nil, false
	}
	return der, true
}
