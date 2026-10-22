// Copyright 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package leaf

import (
	"bytes"
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
			// No vector carries a user_profile_id, so each has both entries
			// over the same bytes.
			if got := string(ev.Entry); got != string(SchemaVersionV2)+v.ExpectedJSON {
				t.Fatalf("0x02 entry\n got: %#x %s\nwant: %s", ev.Entry[0], ev.Entry[1:], v.ExpectedJSON)
			}
			if got := string(ev.Legacy); got != string(SchemaVersion)+v.ExpectedJSON {
				t.Fatalf("0x01 entry\n got: %q\nwant: %s", got, v.ExpectedJSON)
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

// served_vectors_v2.json is the same kind of file for field set v2: each "served"
// value is an event as the feed serves it, most with a user_profile_id, and
// "served_v1" is the same event's canonical JSON over the eleven keys.
func TestVectorsV2_BothEntries(t *testing.T) {
	raw, err := os.ReadFile("testdata/served_vectors_v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Name     string `json:"name"`
		Served   string `json:"served"`
		ServedV1 string `json:"served_v1"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) < 12 {
		t.Fatalf("only %d vectors; testdata truncated?", len(vectors))
	}
	withID, withoutID := 0, 0
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			served := strings.TrimSuffix(v.Served, "}") +
				`,"workspace_uuid":"b6ce2143-1083-d4a7-247c-17530f55a076","transparency_log_leaf_index":7}`
			ev, err := Parse([]byte(served))
			if err != nil {
				t.Fatal(err)
			}
			if got := string(ev.Entry); got != string(SchemaVersionV2)+v.Served {
				t.Fatalf("0x02 entry\n got: %#x %s\nwant: %s", ev.Entry[0], ev.Entry[1:], v.Served)
			}
			var doc map[string]json.RawMessage
			if err := json.Unmarshal([]byte(v.Served), &doc); err != nil {
				t.Fatal(err)
			}
			if _, has := doc[UserProfileIDKey]; has {
				withID++
				if ev.Legacy != nil {
					t.Fatalf("an event with a user_profile_id has no 0x01 entry, got %q", ev.Legacy)
				}
				if v.Served == v.ServedV1 {
					t.Fatal("the vector's 0x01 form must lack the member its served form has")
				}
				// What a release that knew only 0x01 would have recorded for this event.
				if got := string(ev.withheld); got != string(SchemaVersion)+v.ServedV1 {
					t.Fatalf("0x01 rendering of an event with a user_profile_id\n got: %q\nwant: %s", got, v.ServedV1)
				}
				return
			}
			withoutID++
			if got := string(ev.Legacy); got != string(SchemaVersion)+v.ServedV1 {
				t.Fatalf("0x01 entry\n got: %q\nwant: %s", got, v.ServedV1)
			}
			if v.Served != v.ServedV1 {
				t.Fatal("without a user_profile_id both versions have the same canonical JSON")
			}
		})
	}
	if withID < 8 || withoutID < 2 {
		t.Fatalf("%d vectors with a user_profile_id and %d without; the file no longer covers both", withID, withoutID)
	}
}

// The documentation's worked example (§ Leaf canonicalization), an event with
// no user_profile_id, rebuilt here under both version bytes; the documentation
// publishes the 0x01 hash only.
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
	if got := string(ev.Entry); got != string(SchemaVersionV2)+wantJSON {
		t.Fatalf("0x02 entry\n got: %#x %s\nwant: %s", ev.Entry[0], ev.Entry[1:], wantJSON)
	}
	if got := string(ev.Legacy); got != string(SchemaVersion)+wantJSON {
		t.Fatalf("0x01 entry\n got: %q\nwant: %s", got, wantJSON)
	}
	want := []string{"1iKC1LbEakcNTfp8OwW4LtItQu4+/K/pzaDDLVIA5XE=", "6ro7vTcFq+sYDZiiGvZaFetUIoMSLig3DGDrCKK1HFU="}
	hashes := ev.Hashes()
	if len(hashes) != len(want) {
		t.Fatalf("%d leaf hashes, want %d", len(hashes), len(want))
	}
	for i := range want {
		if got := base64.StdEncoding.EncodeToString(hashes[i]); got != want[i] {
			t.Fatalf("leaf hash %d = %s, want %s", i, got, want[i])
		}
	}
	if ev.ID != "activity_01GPXmAhizavrUuoXNn3tzeA" || ev.OrganizationUUID != "25f6429a-3293-49bf-afed-cb312911554b" {
		t.Fatalf("id/org = %q/%q", ev.ID, ev.OrganizationUUID)
	}
	if ev.Index == nil || *ev.Index != 17 {
		t.Fatalf("index = %v", ev.Index)
	}
	// The same event served with a user_profile_id: the 0x02 entry alone.
	with, err := Parse([]byte(strings.Replace(served, `"reason_code": "safety_review",`, `"reason_code": "safety_review", "user_profile_id": "uprof_01H7Z9W1CEpdPaGUP2rbg1XD",`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := base64.StdEncoding.EncodeToString(with.Hash()), "onAlpkDfdXmHPvbffiTpHAgBacf/mJCzTfNDibDrYp4="; got != want || with.Legacy != nil {
		t.Fatalf("with a user_profile_id: leaf hash = %s, want %s; 0x01 entry %q", got, want, with.Legacy)
	}
}

// A user_profile_id is one member added before workspace_id to the same
// event's 0x01 entry, written as the other strings are, and the event then has
// no 0x01 entry. The empty string is a value, not an absence.
func TestParse_UserProfileIDIsOneAddedMember(t *testing.T) {
	for _, tc := range []struct{ name, served, member string }{
		{"plain", `"uprof_01H7Z9W1CEpdPaGUP2rbg1XD"`, `"uprof_01H7Z9W1CEpdPaGUP2rbg1XD"`},
		{"empty", `""`, `""`},
		{"escapes", "\"q\\\" bs\\\\ nl\\n bel\\u0007 ls\\u2028 sl\\/\"", "\"q\\\" bs\\\\ nl\\n bel\\u0007 ls\u2028 sl/\""},
		{"beyond the BMP", `"\ud83d\ude00"`, "\"\U0001F600\""},
	} {
		for _, typ := range Types() {
			base := `{"type":"` + typ + `","id":"activity_a","workspace_id":"wrkspc_a"`
			plain, err := Parse([]byte(base + "}"))
			if err != nil {
				t.Fatal(err)
			}
			ev, err := Parse([]byte(base + `,"user_profile_id":` + tc.served + "}"))
			if err != nil {
				t.Fatalf("%s, %s: %v", tc.name, typ, err)
			}
			cut := bytes.LastIndex(plain.Legacy, []byte(`,"workspace_id":`))
			want := "\x02" + string(plain.Legacy[1:cut]) + `,"user_profile_id":` + tc.member + string(plain.Legacy[cut:])
			if string(ev.Entry) != want || ev.Legacy != nil {
				t.Fatalf("%s, %s:\n got: %q / %q\nwant: %q and no 0x01 entry", tc.name, typ, ev.Entry, ev.Legacy, want)
			}
		}
	}
}

// RecordedFrom accepts a serving's own hashes and, for an event with a
// user_profile_id, the 0x01 hash over its eleven keys, which Hashes withholds.
func TestRecordedFrom(t *testing.T) {
	const base = `{"type":"anthropic_access","id":"activity_a"`
	plain, err := Parse([]byte(base + "}"))
	if err != nil {
		t.Fatal(err)
	}
	with, err := Parse([]byte(base + `,"user_profile_id":"uprof_a"}`))
	if err != nil {
		t.Fatal(err)
	}
	olderRelease := plain.Hashes()[1]
	if len(with.Hashes()) != 1 || !with.RecordedFrom(with.Hash()) || !with.RecordedFrom(olderRelease) {
		t.Fatalf("an event with a user_profile_id: hashes %x", with.Hashes())
	}
	if !plain.RecordedFrom(plain.Hash()) || !plain.RecordedFrom(olderRelease) {
		t.Fatal("an event with no user_profile_id: one of its own two hashes was refused")
	}
	if with.RecordedFrom(plain.Hash()) || with.RecordedFrom(nil) || plain.RecordedFrom([]byte{}) {
		t.Fatal("accepted a hash no release records from this serving")
	}
}

func TestParse_AbsentAndNullEnterAsNull(t *testing.T) {
	for _, served := range []string{
		`{"type":"cmek_preserve"}`,
		`{"type":"cmek_preserve","id":null,"actor":null,"resource_details":null,"user_profile_id":null,"transparency_log_leaf_index":null}`,
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

// A member of resource_details outside the field set is ignored, as a
// top-level one is: derived-data reads serve derived_from there, and no field
// set commits it.
func TestParse_IgnoresAnUnknownResourceDetailsMember(t *testing.T) {
	const head = `{"type":"anthropic_access","id":"activity_a","resource_details":{"type":"derived_data","id":""`
	plain, err := Parse([]byte(head + "}}"))
	if err != nil {
		t.Fatal(err)
	}
	extra, err := Parse([]byte(head + `,"derived_from":{"resources":[{"type":"message","id":"msg_a"}],"part_index":0,"part_count":1,"part_group":"pg_a"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(extra.Entry) != string(plain.Entry) || string(extra.Legacy) != string(plain.Legacy) {
		t.Fatalf("derived_from changed the entries:\n got: %q / %q\nwant: %q / %q", extra.Entry, extra.Legacy, plain.Entry, plain.Legacy)
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
		// user_profile_id decides whether a 0x01 entry exists, so it is read
		// as strictly as the rest.
		"profile id number":    `{"type":"anthropic_access","user_profile_id":7}`,
		"profile id repeated":  `{"type":"anthropic_access","user_profile_id":"uprof_a","user_profile_id":"uprof_b"}`,
		"profile id case fold": `{"type":"anthropic_access","User_Profile_ID":"uprof_a"}`,
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

// A row read only for its type is refused for a case-variant of
// user_profile_id too, whatever product the row belongs to.
func TestTypeOf_RefusesACaseVariantUserProfileID(t *testing.T) {
	if typ, err := TypeOf([]byte(`{"type":"user_login","User_Profile_Id":"uprof_a"}`)); err == nil {
		t.Fatalf("accepted, type %q", typ)
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
