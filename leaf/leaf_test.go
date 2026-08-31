// Copyright 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package leaf

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

// served_vectors.json holds the log implementation's golden parity
// vectors in served form: each "served" value is an event exactly as the
// activity feed serves it, projected onto field set v1 by the real serving
// code, and is byte for byte the canonical JSON the log commits.
// Re-rendering it must therefore be the identity. These vectors are generated
// from the log implementation's own test vectors (the identifiers in them are
// synthetic), which are held to the same bytes.
func TestVectors_RenderIsIdentityOnServedForm(t *testing.T) {
	raw, err := os.ReadFile("testdata/served_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Name         string `json:"name"`
		ExpectedJSON string `json:"served"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) < 40 {
		t.Fatalf("only %d vectors; testdata truncated?", len(vectors))
	}
	seenTypes := map[string]bool{}
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			// Served records carry keys outside the field set; they must
			// drop out.
			served := strings.TrimSuffix(v.ExpectedJSON, "}") +
				`,"workspace_uuid":"b6ce2143-1083-d4a7-247c-17530f55a076","transparency_log_leaf_index":7}`
			ev, err := Parse([]byte(served))
			if err != nil {
				t.Fatal(err)
			}
			if ev.Entry[0] != SchemaVersion {
				t.Fatalf("version byte %#x", ev.Entry[0])
			}
			if got := string(ev.Entry[1:]); got != v.ExpectedJSON {
				t.Fatalf("render mismatch\n got: %s\nwant: %s", got, v.ExpectedJSON)
			}
			if ev.Index == nil || *ev.Index != 7 {
				t.Fatalf("index = %v", ev.Index)
			}
			var typ struct {
				Type string `json:"type"`
			}
			_ = json.Unmarshal([]byte(v.ExpectedJSON), &typ)
			seenTypes[typ.Type] = true
		})
	}
	for _, typ := range Types() {
		if !seenTypes[typ] {
			t.Errorf("no vector covers type %q", typ)
		}
	}
}

// The worked example in Anthropic's Compliance API documentation for the
// transparency log (§ Leaf canonicalization).
func TestSpecWorkedExample(t *testing.T) {
	served := `{
	  "id": "activity_01GPXmAhizavrUuoXNn3tzeA",
	  "type": "anthropic_access",
	  "created_at": "2025-07-08T18:40:00Z",
	  "accessed_at": "2025-07-08T18:39:58Z",
	  "organization_id": "org_015gtSHLz269eTwgrH8NX5yk",
	  "organization_uuid": "25f6429a-3293-49bf-afed-cb312911554b",
	  "workspace_id": "wrkspc_01PaGUP2rbg1XDh7Z9W1CEpd",
	  "workspace_uuid": "b6ce2143-1083-d4a7-247c-17530f55a076",
	  "accessor_department": "Trust & Safety",
	  "reason_code": "safety_review",
	  "actor": {"type": "anthropic_actor", "email_address": null},
	  "resource_details": {"type": "message", "id": "msg_01HXAMPLE12345678"},
	  "transparency_log_leaf_index": 17
	}`
	ev, err := Parse([]byte(served))
	if err != nil {
		t.Fatal(err)
	}
	const wantJSON = `{"accessed_at":"2025-07-08T18:39:58Z","accessor_department":"Trust & Safety","actor":{"email_address":null,"type":"anthropic_actor"},"created_at":"2025-07-08T18:40:00Z","id":"activity_01GPXmAhizavrUuoXNn3tzeA","organization_id":"org_015gtSHLz269eTwgrH8NX5yk","organization_uuid":"25f6429a-3293-49bf-afed-cb312911554b","reason_code":"safety_review","resource_details":{"id":"msg_01HXAMPLE12345678","parent":null,"type":"message"},"type":"anthropic_access","workspace_id":"wrkspc_01PaGUP2rbg1XDh7Z9W1CEpd"}`
	if got := string(ev.Entry[1:]); got != wantJSON {
		t.Fatalf("canonical JSON\n got: %s\nwant: %s", got, wantJSON)
	}
	if got, want := base64.StdEncoding.EncodeToString(ev.Hash()), "6ro7vTcFq+sYDZiiGvZaFetUIoMSLig3DGDrCKK1HFU="; got != want {
		t.Fatalf("leaf hash = %s, want %s", got, want)
	}
	if ev.ID != "activity_01GPXmAhizavrUuoXNn3tzeA" || ev.OrganizationUUID != "25f6429a-3293-49bf-afed-cb312911554b" {
		t.Fatalf("id/org = %q/%q", ev.ID, ev.OrganizationUUID)
	}
	if ev.Index == nil || *ev.Index != 17 {
		t.Fatalf("index = %v", ev.Index)
	}
}

func TestParse_AbsentAndNullEnterAsNull(t *testing.T) {
	for _, served := range []string{
		`{"type":"cmek_preserve"}`,
		`{"type":"cmek_preserve","id":null,"actor":null,"resource_details":null,"transparency_log_leaf_index":null}`,
	} {
		ev, err := Parse([]byte(served))
		if err != nil {
			t.Fatal(err)
		}
		const want = `{"accessed_at":null,"accessor_department":null,"actor":null,"created_at":null,"id":null,"organization_id":null,"organization_uuid":null,"reason_code":null,"resource_details":null,"type":"cmek_preserve","workspace_id":null}`
		if got := string(ev.Entry[1:]); got != want {
			t.Fatalf("got %s", got)
		}
		if ev.Index != nil {
			t.Fatalf("index = %d, want nil", *ev.Index)
		}
	}
	// A served email address never enters the leaf.
	ev, err := Parse([]byte(`{"type":"anthropic_access","actor":{"type":"anthropic_actor","email_address":"x@example.com"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ev.Entry), `"actor":{"email_address":null,"type":"anthropic_actor"}`) {
		t.Fatalf("got %s", ev.Entry[1:])
	}
}

func TestParse_JCSStringEscaping(t *testing.T) {
	// Go's encoding/json would escape <, >, & and U+2028 and pass a served
	// "\u0007" through re-encoded as "\u0007"; JCS emits everything above
	// U+001F literally (solidus included) and lowercase-hex escapes only the
	// C0 controls outside the two-character set.
	served := "{\"type\":\"anthropic_access\",\"accessor_department\":\"q\\\" bs\\\\ nl\\n tab\\t bel\\u0007 vt\\u000B ls\\u2028 <>& \\u00e9 \U0001F600 sl\\/\"}"
	ev, err := Parse([]byte(served))
	if err != nil {
		t.Fatal(err)
	}
	want := "\"accessor_department\":\"q\\\" bs\\\\ nl\\n tab\\t bel\\u0007 vt\\u000b ls\u2028 <>& \u00e9 \U0001F600 sl/\""
	if !strings.Contains(string(ev.Entry), want) {
		t.Fatalf("got %s\nwant substring %s", ev.Entry[1:], want)
	}
}

func TestParse_WellFormedStringsAccepted(t *testing.T) {
	// Only forms the decoder would repair are refused: a surrogate pair, a
	// served literal U+FFFD, and an escaped backslash before "u" all parse.
	served := "{\"type\":\"anthropic_access\",\"accessor_department\":\"\\ud83d\\ude00 \\ufffd \\\\u0041\"}"
	ev, err := Parse([]byte(served))
	if err != nil {
		t.Fatal(err)
	}
	want := "\"accessor_department\":\"\U0001F600 � \\\\u0041\""
	if !strings.Contains(string(ev.Entry), want) {
		t.Fatalf("got %s\nwant substring %s", ev.Entry[1:], want)
	}
}

func TestParse_Rejects(t *testing.T) {
	cases := map[string]string{
		"not object":        `[{"type":"anthropic_access"}]`,
		"unknown type":      `{"type":"user_login"}`,
		"missing type":      `{"id":"activity_x"}`,
		"non-string type":   `{"type":7}`,
		"non-string value":  `{"type":"anthropic_access","reason_code":3}`,
		"actor not object":  `{"type":"anthropic_access","actor":"anthropic_actor"}`,
		"resource id num":   `{"type":"anthropic_access","resource_details":{"id":1}}`,
		"negative index":    `{"type":"anthropic_access","transparency_log_leaf_index":-1}`,
		"fractional index":  `{"type":"anthropic_access","transparency_log_leaf_index":1.5}`,
		"exponent index":    `{"type":"anthropic_access","transparency_log_leaf_index":1e3}`,
		"string index":      `{"type":"anthropic_access","transparency_log_leaf_index":"3"}`,
		"index over 2^63-1": `{"type":"anthropic_access","transparency_log_leaf_index":9223372036854775808}`,
		"trailing garbage":  `{"type":"anthropic_access"} x`,
		// A repeated member name, or a string encoding/json would repair to
		// U+FFFD, makes distinct served bytes render to one entry: the leaf
		// would verify while a downstream reader sees another value.
		"duplicate member": `{"type":"anthropic_access","reason_code":"csae_report","reason_code":"safety_review"}`,
		// The repeat is spelled with an escape: names compare decoded.
		"duplicate escaped member":  "{\"type\":\"anthropic_access\",\"id\":\"activity_a\",\"\\u0069d\":\"activity_b\"}",
		"duplicate actor member":    `{"type":"anthropic_access","actor":{"type":"anthropic_actor","type":"system"}}`,
		"duplicate resource member": `{"type":"anthropic_access","resource_details":{"id":"a","id":"b"}}`,
		"lone high surrogate":       `{"type":"anthropic_access","reason_code":"\ud800ab"}`,
		"lone low surrogate":        `{"type":"anthropic_access","reason_code":"\udc00"}`,
		"reversed surrogate pair":   `{"type":"anthropic_access","reason_code":"\ude00\ud83d"}`,
		"invalid utf-8":             "{\"type\":\"anthropic_access\",\"reason_code\":\"\xff\"}",
		// A name a folding consumer (encoding/json's struct decoding) would
		// read as a committed key, which this verifier would drop as unknown.
		"case-variant member":          `{"type":"anthropic_access","Reason_Code":"csae_report"}`,
		"case-variant actor member":    `{"type":"anthropic_access","actor":{"Type":"anthropic_actor"}}`,
		"case-variant resource member": `{"type":"anthropic_access","resource_details":{"ID":"msg_1"}}`,
		"case-variant index":           `{"type":"anthropic_access","Transparency_Log_Leaf_Index":3}`,
	}
	for name, served := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(served)); err == nil {
				t.Fatal("accepted")
			} else if name == "unknown type" && !errors.Is(err, ErrUnknownType) {
				t.Fatalf("err = %v, want ErrUnknownType", err)
			}
		})
	}
}

// The gate that decides "is this row ours" must not be fooled by a near-miss:
// relabelling an event is the cheapest way to make it vanish from a pass, so
// anything sharing a beginning with one of our types stays ours to refuse.
func TestClaimsOurType(t *testing.T) {
	ours := []string{
		"anthropic_access", "cmek_preserve", // exactly ours
		"Anthropic_Access",    // case variant
		"anthropic-access",    // separator variant
		"anthropic access",    // spacing variant
		"anthropic_acces",     // truncation
		"anthropic_access_v2", // a version this build does not know
		"anthropic_acceſs",    // U+017F folds to s
		"ANTHROPIC_ACCESS",
		"", // nothing recognisable is ours to refuse, not to skip
	}
	for _, typ := range ours {
		if !ClaimsOurType(typ) {
			t.Errorf("%q was treated as another product's type", typ)
		}
	}
	others := []string{"user_login", "api_key_created", "workspace_created", "invoice_paid"}
	for _, typ := range others {
		if ClaimsOurType(typ) {
			t.Errorf("%q was treated as claiming to be ours", typ)
		}
	}
}
