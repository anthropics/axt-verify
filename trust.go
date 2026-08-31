// Copyright 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package axtverify

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// VerifierKeyFor builds the note-verifier string for an ECDSA P-256 key, the
// one encoding the log signs under: "<origin>+<8 hex>+base64(0x02 || SPKI)".
// This is the exact encoding the log's published keys use, so any tooling
// that renders a key for this log must produce these bytes.
func VerifierKeyFor(origin string, der []byte) string {
	sum := sha256.Sum256(der)
	return fmt.Sprintf("%s+%08x+%s", origin, binary.BigEndian.Uint32(sum[:4]),
		base64.StdEncoding.EncodeToString(append([]byte{0x02}, der...)))
}

// Fingerprint is the value published for a key and printed in the README, so
// an operator can see that a release ships the key they expect.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// FingerprintOfVerifierKey is the published fingerprint — SHA-256 of the
// key's DER SubjectPublicKeyInfo — of the key a verifier string carries.
//
// It is derivable only from the ECDSA form this log signs with, whose payload
// is 0x02 || SPKI. A standard Ed25519 note key carries 0x01 || the raw
// 32-byte key, and the SPKI cannot be recovered from that, so hashing the
// payload would print a number that matches nothing anyone published. Callers
// that must show something for any key use KeyHash.
func FingerprintOfVerifierKey(vkey string) (string, bool) {
	blob, ok := keyBlob(vkey)
	if !ok || len(blob) < 2 || blob[0] != algECDSAP256SHA256 {
		return "", false
	}
	return Fingerprint(blob[1:]), true
}

// KeyHash is the 8-hex key hash a verifier string carries: the value a note
// signature is matched by, and the one field that is meaningful for every key
// encoding.
func KeyHash(vkey string) (string, bool) {
	hash, _, ok := splitVerifierKey(vkey)
	if !ok || len(hash) != 8 {
		return "", false
	}
	return hash, true
}

// algECDSAP256SHA256 is the note algorithm byte this log's keys carry.
const algECDSAP256SHA256 = 0x02

// splitVerifierKey is the key-hash and base64-payload fields of a
// "<name>+<key hash>+<payload>" verifier string.
func splitVerifierKey(vkey string) (hash, payload string, ok bool) {
	parts := strings.SplitN(strings.TrimSpace(vkey), "+", 3)
	if len(parts) != 3 {
		return "", "", false
	}
	return parts[1], parts[2], true
}

// keyBlob is the decoded payload of a verifier string, algorithm byte and all.
func keyBlob(vkey string) ([]byte, bool) {
	_, payload, ok := splitVerifierKey(vkey)
	if !ok {
		return nil, false
	}
	blob, err := base64.StdEncoding.DecodeString(payload)
	if err != nil || len(blob) < 2 {
		return nil, false
	}
	return blob, true
}
