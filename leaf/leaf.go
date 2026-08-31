// Copyright 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

// Package leaf rebuilds Access Transparency transparency-log leaf entries
// from events exactly as the Compliance API activity feed serves them.
//
// A leaf entry is SchemaVersion followed by RFC 8785 (JCS) canonical JSON
// over field set v1 — eleven keys projected from the served event. Its
// RFC 6962 leaf hash is SHA-256(0x00 || entry). The projection rules are
// the public transparency-log specification's § Leaf canonicalization:
// values are copied byte for byte, a key the served event omits enters as
// null, keys outside the set are ignored, and actor.email_address and
// resource_details.parent are always null under schema version 0x01.
package leaf

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/transparency-dev/merkle/rfc6962"
)

// SchemaVersion is the leaf-entry version byte for field set v1.
const SchemaVersion byte = 0x01

// IndexKey is the served key carrying an event's position in its
// organization's log; null when the event has no leaf.
const IndexKey = "transparency_log_leaf_index"

var types = []string{"anthropic_access", "cmek_preserve"}

// Types returns schema version 0x01's closed event-type list. An event of
// any other type cannot be a 0x01 leaf: new types ship under a new version
// byte and need a newer verifier.
func Types() []string { return slices.Clone(types) }

// TypeOf reads an activity's "type" through the same strict decode Parse
// uses. A caller deciding whether a row is this tool's to check must not be
// told one thing by a lenient parser and another by the canonicalizer: every
// ambiguity Parse refuses — a repeated member, a member differing only in
// case from a projected name, trailing content — is an error here too, and an
// error means the row is ours to fail, never to pass over.
func TypeOf(served []byte) (string, error) {
	top, err := decodeObject(served, topKeys)
	if err != nil {
		return "", fmt.Errorf("served event: %w", err)
	}
	typ, err := optString(top, "type")
	if err != nil {
		return "", err
	}
	if typ == nil {
		return "", ErrUnknownType
	}
	return *typ, nil
}

// ClaimsOurType reports whether a type value is one of ours, or is near
// enough to be claiming to be. Only a type that shares no beginning with one
// of ours is passed over as another product's row; everything else goes to
// Parse and is refused there, because relabelling an event is the cheapest
// way to make it disappear from a verification pass.
func ClaimsOurType(typ string) bool {
	cand := normalizeType(typ)
	for _, t := range types {
		ours := normalizeType(t)
		// Either direction: "anthropic_access_v2" extends ours, and
		// "anthropic_acces" is ours truncated. Both are claiming to be ours.
		if strings.HasPrefix(cand, ours) || strings.HasPrefix(ours, cand) {
			return true
		}
	}
	return false
}

// normalizeType folds a type name to the form its near-misses share:
// separators and punctuation dropped, every rune reduced to the smallest
// member of its Unicode fold orbit. That is the same fold relation
// decodeObject uses to refuse member names differing only in case, so a value
// like "anthropic_acceſs" cannot read as somebody else's type here while
// reading as ours there.
func normalizeType(s string) string {
	var b strings.Builder
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			continue
		}
		b.WriteRune(foldRune(r))
	}
	return b.String()
}

// foldRune is the smallest rune in r's simple-fold orbit, so every case and
// fold variant of a letter maps to one representative.
func foldRune(r rune) rune {
	small := r
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		if f < small {
			small = f
		}
	}
	return small
}

// ErrUnknownType means the served event's type is outside Types.
var ErrUnknownType = errors.New("event type is outside leaf schema version 0x01's type list; a newer axt-verify is required")

// Event is what a verifier needs from one served event.
type Event struct {
	// ID is the served activity id ("" when the record carries none).
	ID string
	// OrganizationUUID is the served organization_uuid ("" when absent).
	OrganizationUUID string
	// Index is the event's leaf index; nil when the event has no leaf
	// (recorded while the organization had no active log).
	Index *uint64
	// Entry is the leaf entry: SchemaVersion || canonical JSON.
	Entry []byte
}

// Hash returns the RFC 6962 leaf hash of the entry.
func (e Event) Hash() []byte { return rfc6962.DefaultHasher.HashLeaf(e.Entry) }

// Parse projects one served event — a JSON object as it appears in the
// activity feed's data array or a SIEM export of it — onto field set v1.
// Served bytes that are ambiguous about a projected value are refused, not
// resolved: a repeated member name, a name differing from a projected one
// only in case, or a string the JSON decoder would repair. Resolving one
// would stamp several distinct served forms as the single leaf the log
// committed, and only the form this verifier happened to read would be the
// verified one.
func Parse(served []byte) (Event, error) {
	top, err := decodeObject(served, topKeys)
	if err != nil {
		return Event{}, fmt.Errorf("served event: %w", err)
	}
	var r record
	if r.typ, err = optString(top, "type"); err != nil {
		return Event{}, err
	}
	if r.typ == nil || !slices.Contains(types, *r.typ) {
		return Event{}, ErrUnknownType
	}
	for key, dst := range map[string]**string{
		"id":                  &r.id,
		"created_at":          &r.createdAt,
		"accessed_at":         &r.accessedAt,
		"organization_id":     &r.organizationID,
		"organization_uuid":   &r.organizationUUID,
		"workspace_id":        &r.workspaceID,
		"accessor_department": &r.accessorDepartment,
		"reason_code":         &r.reasonCode,
	} {
		if *dst, err = optString(top, key); err != nil {
			return Event{}, err
		}
	}
	if raw, ok := present(top, "actor"); ok {
		actor, err := decodeObject(raw, actorKeys)
		if err != nil {
			return Event{}, fmt.Errorf("actor: %w", err)
		}
		r.actor = &actorRecord{}
		if r.actor.typ, err = optString(actor, "type"); err != nil {
			return Event{}, fmt.Errorf("actor.%w", err)
		}
	}
	if raw, ok := present(top, "resource_details"); ok {
		res, err := decodeObject(raw, resourceKeys)
		if err != nil {
			return Event{}, fmt.Errorf("resource_details: %w", err)
		}
		r.resource = &resourceRecord{}
		if r.resource.id, err = optString(res, "id"); err != nil {
			return Event{}, fmt.Errorf("resource_details.%w", err)
		}
		if r.resource.typ, err = optString(res, "type"); err != nil {
			return Event{}, fmt.Errorf("resource_details.%w", err)
		}
	}
	idx, err := index(top)
	if err != nil {
		return Event{}, err
	}
	j := r.render()
	entry := make([]byte, 0, 1+len(j))
	entry = append(entry, SchemaVersion)
	entry = append(entry, j...)
	return Event{ID: deref(r.id), OrganizationUUID: deref(r.organizationUUID), Index: idx, Entry: entry}, nil
}

type record struct {
	id, typ, createdAt, accessedAt   *string
	organizationID, organizationUUID *string
	workspaceID, accessorDepartment  *string
	reasonCode                       *string
	actor                            *actorRecord
	resource                         *resourceRecord
}

type actorRecord struct{ typ *string }

type resourceRecord struct{ id, typ *string }

// render emits field set v1 as RFC 8785 canonical JSON. For this value
// space JCS reduces to: keys in code-point order (hardcoded — the key set
// is fixed), no whitespace, and JCS string serialization; no numbers exist
// anywhere, so number canonicalization never engages.
func (r record) render() []byte {
	var b bytes.Buffer
	b.WriteByte('{')

	writeKey(&b, "accessed_at", false)
	writeOpt(&b, r.accessedAt)

	writeKey(&b, "accessor_department", true)
	writeOpt(&b, r.accessorDepartment)

	// email_address is fixed null under 0x01 whatever the served record
	// shows: the log never commits an email address.
	writeKey(&b, "actor", true)
	if r.actor != nil {
		b.WriteString(`{"email_address":null,"type":`)
		writeOpt(&b, r.actor.typ)
		b.WriteByte('}')
	} else {
		b.WriteString("null")
	}

	writeKey(&b, "created_at", true)
	writeOpt(&b, r.createdAt)

	writeKey(&b, "id", true)
	writeOpt(&b, r.id)

	writeKey(&b, "organization_id", true)
	writeOpt(&b, r.organizationID)

	writeKey(&b, "organization_uuid", true)
	writeOpt(&b, r.organizationUUID)

	writeKey(&b, "reason_code", true)
	writeOpt(&b, r.reasonCode)

	writeKey(&b, "resource_details", true)
	if r.resource != nil {
		b.WriteByte('{')
		writeKey(&b, "id", false)
		writeOpt(&b, r.resource.id)
		// parent is reserved and always null under 0x01.
		writeKey(&b, "parent", true)
		b.WriteString("null")
		writeKey(&b, "type", true)
		writeOpt(&b, r.resource.typ)
		b.WriteByte('}')
	} else {
		b.WriteString("null")
	}

	writeKey(&b, "type", true)
	writeOpt(&b, r.typ)

	writeKey(&b, "workspace_id", true)
	writeOpt(&b, r.workspaceID)

	b.WriteByte('}')
	return b.Bytes()
}

func writeKey(b *bytes.Buffer, key string, comma bool) {
	if comma {
		b.WriteByte(',')
	}
	writeString(b, key)
	b.WriteByte(':')
}

func writeOpt(b *bytes.Buffer, s *string) {
	if s == nil {
		b.WriteString("null")
		return
	}
	writeString(b, *s)
}

// writeString emits an RFC 8785 §3.2.2.2 string literal: two-character
// escapes for the standard set, \u00xx for the remaining C0 controls, and
// every other character as literal UTF-8.
func writeString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// The names each object contributes to the leaf. A served name that folds to
// one of these without being it is refused: this verifier reads names
// exactly, and a consumer that folds (encoding/json's struct decoding, for
// one) would read a value where the leaf commits null.
var (
	topKeys = []string{
		"accessed_at", "accessor_department", "actor", "created_at", "id",
		"organization_id", "organization_uuid", "reason_code", "resource_details",
		"type", "workspace_id", IndexKey,
	}
	actorKeys    = []string{"email_address", "type"}
	resourceKeys = []string{"id", "parent", "type"}
)

// decodeObject decodes one JSON object and refuses a repeated member name.
// encoding/json keeps the last of a repeat, so accepting one would let a
// served record read as this verifier's value on a committed field and as a
// first-wins parser's other value downstream, both under one "verified"
// stamp. Only the three objects the leaf projects from are decoded here,
// which is exactly where a repeat could reach the entry.
func decodeObject(raw []byte, projected []string) (map[string]json.RawMessage, error) {
	if t := bytes.TrimSpace(raw); len(t) == 0 || t[0] != '{' {
		return nil, errors.New("not a JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if _, err := dec.Token(); err != nil { // '{'
		return nil, err
	}
	m := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := tok.(string)
		if !ok {
			return nil, errors.New("not a JSON object")
		}
		if _, dup := m[key]; dup {
			return nil, fmt.Errorf("duplicate member %q", key)
		}
		if !slices.Contains(projected, key) {
			for _, p := range projected {
				if strings.EqualFold(key, p) {
					return nil, fmt.Errorf("member %q differs from %q only in case", key, p)
				}
			}
		}
		var val json.RawMessage
		if err := dec.Decode(&val); err != nil {
			return nil, err
		}
		m[key] = val
	}
	if _, err := dec.Token(); err != nil { // '}'
		return nil, err
	}
	// Token reports the byte after the object; anything but EOF is trailing
	// content, which json.Unmarshal would also refuse.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing content")
	}
	return m, nil
}

// present reports a key that is present and non-null; absent and null are
// the same case for the leaf.
func present(m map[string]json.RawMessage, key string) (json.RawMessage, bool) {
	raw, ok := m[key]
	if !ok || string(bytes.TrimSpace(raw)) == "null" {
		return nil, false
	}
	return raw, true
}

func optString(m map[string]json.RawMessage, key string) (*string, error) {
	raw, ok := present(m, key)
	if !ok {
		return nil, nil //nolint:nilnil // nil is the value: absent and null both enter the leaf as null
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("%s: not a string", key)
	}
	if err := wellFormed(raw); err != nil {
		return nil, fmt.Errorf("%s: %w", key, err)
	}
	return &s, nil
}

// wellFormed refuses a served string literal encoding/json would silently
// repair to U+FFFD — invalid UTF-8, or an unpaired surrogate escape. Both
// render to the same entry as a literal U+FFFD does, so accepting them would
// verify several served forms against one committed leaf; RFC 8785 defines
// canonicalization over valid Unicode only. A JSON encoder emits neither.
func wellFormed(raw []byte) error {
	if !utf8.Valid(raw) {
		return errors.New("not valid UTF-8")
	}
	for i := 0; i < len(raw); {
		if raw[i] != '\\' {
			i++
			continue
		}
		hi, ok := hexEscape(raw[i:])
		if !ok {
			i += 2 // a two-character escape: its second byte is not an escape
			continue
		}
		i += 6
		if hi < 0xD800 || hi > 0xDFFF {
			continue
		}
		lo, ok := hexEscape(raw[i:])
		if hi > 0xDBFF || !ok || lo < 0xDC00 || lo > 0xDFFF {
			return errors.New("unpaired surrogate escape")
		}
		i += 6
	}
	return nil
}

// hexEscape decodes the \uXXXX escape at the start of b.
func hexEscape(b []byte) (rune, bool) {
	if len(b) < 6 || b[0] != '\\' || b[1] != 'u' {
		return 0, false
	}
	v, err := strconv.ParseUint(string(b[2:6]), 16, 32)
	if err != nil {
		return 0, false
	}
	return rune(v), true
}

func index(m map[string]json.RawMessage) (*uint64, error) {
	raw, ok := present(m, IndexKey)
	if !ok {
		return nil, nil //nolint:nilnil // nil is the value: the event has no leaf
	}
	// A JSON integer literal only: no sign, fraction, or exponent.
	s := string(bytes.TrimSpace(raw))
	for _, c := range s {
		if c < '0' || c > '9' {
			return nil, fmt.Errorf("%s: not a non-negative integer", IndexKey)
		}
	}
	v, err := strconv.ParseUint(s, 10, 63)
	if err != nil {
		return nil, fmt.Errorf("%s: out of range", IndexKey)
	}
	return &v, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
