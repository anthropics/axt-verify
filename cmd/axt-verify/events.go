// Copyright 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"cmp"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/anthropics/axt-verify"
	"github.com/anthropics/axt-verify/checkpoint"
)

// looksLikePage reports whether an object's members are exactly a feed
// page's: a "data" member and nothing a page does not carry. Inverted on
// purpose: listing the event names instead would have to track the leaf's
// field set, and miss anything spelled around it.
func looksLikePage[V any](members map[string]V) bool {
	if _, ok := members["data"]; !ok {
		return false
	}
	for n := range members {
		switch n {
		case "data", "has_more", "first_id", "last_id":
		default:
			return false
		}
	}
	return true
}

// topLevelNames reports the member names of a JSON object, tolerating the
// defects strictObject refuses — it answers what shape the input is, not
// whether it is well formed.
func topLevelNames(raw []byte) map[string]bool {
	names := map[string]bool{}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if _, err := dec.Token(); err != nil {
		return names
	}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return names
		}
		key, ok := tok.(string)
		if !ok {
			return names
		}
		names[key] = true
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return names
		}
	}
	return names
}

// strictObject decodes one JSON object, refusing a repeated member name:
// Go keeps the last, so a captured page carrying two "data" members would
// classify on one and verify the other. Returns nil for input that is not a
// well-formed object, which the caller reads as a single event or as lines.
func strictObject(raw []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if _, err := dec.Token(); err != nil {
		return nil, nil //nolint:nilnil,nilerr // not an object: the caller has other shapes to try
	}
	m := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, nil //nolint:nilnil,nilerr // malformed: fall through to the other shapes
		}
		key, ok := tok.(string)
		if !ok {
			return nil, nil //nolint:nilnil // not an object
		}
		if _, dup := m[key]; dup {
			return nil, fmt.Errorf("member %q appears twice", key)
		}
		var val json.RawMessage
		if err := dec.Decode(&val); err != nil {
			return nil, nil //nolint:nilnil,nilerr // malformed: fall through
		}
		m[key] = val
	}
	if _, err := dec.Token(); err != nil { // '}'
		return nil, nil //nolint:nilnil,nilerr // malformed: fall through
	}
	// Anything after the object is a second document. One object per line is
	// a shape this tool reads, so leave that to the caller — but a feed page
	// followed by more would otherwise verify only the first page's events
	// and report success, so say so there.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		// A page is an object whose members are exactly a page's, here as
		// everywhere else: a JSONL line that happens to own a field named
		// "data" is an event, and the lines after it are its siblings.
		if looksLikePage(m) {
			return nil, errors.New("input has more than one JSON document after a feed page; verify one page at a time, or feed one event per line")
		}
		return nil, nil //nolint:nilnil // more documents follow: the caller reads them as lines
	}
	return m, nil
}

// scrub renders every server-supplied string in the report printable. It
// runs before either output path: encoding/json escapes C0 but passes C1
// controls (U+0080–U+009F) through, and a terminal acts on those too.
func scrub(rep *axtverify.Report) {
	for i, f := range rep.Events.Failed {
		rep.Events.Failed[i].ID = printable(f.ID)
		rep.Events.Failed[i].Reason = printable(f.Reason)
	}
	for i, id := range rep.Events.NotLogged {
		rep.Events.NotLogged[i] = printable(id)
	}
	for i, id := range rep.Events.Pending {
		rep.Events.Pending[i] = printable(id)
	}
}

// maxInputBytes bounds what `events` will read from a file or a pipe.
const maxInputBytes = 256 << 20

// printReport writes the human-readable report. anchored says whether the
// pass keeps a checkpoint for the next one — `events` does not, so claiming
// a baseline was set (or an append-only check made) would misdescribe it.
func printReport(w io.Writer, rep *axtverify.Report, anchored bool) {
	fmt.Fprintf(w, "origin:      %s\n", rep.Origin)
	fmt.Fprintf(w, "checkpoint:  tree size %d, root hash %s\n", rep.Checkpoint.Size, base64.StdEncoding.EncodeToString(rep.Checkpoint.RootHash))
	switch {
	case rep.PreviousSize != nil:
		fmt.Fprintf(w, "append-only: verified from tree size %d\n", *rep.PreviousSize)
	case anchored:
		fmt.Fprintf(w, "append-only: no earlier checkpoint saved; this one becomes the baseline\n")
	}
	ev := rep.Events
	if ev.Verified+len(ev.NotLogged)+len(ev.Pending)+len(ev.Failed) == 0 {
		// Still say the read was cut short: a pass that tallied nothing
		// because it ran out of pages is the case most worth saying it for.
		if rep.Truncated {
			fmt.Fprintln(w, "feed:        page limit reached; rerun to continue")
		}
		return
	}
	fmt.Fprintf(w, "events:      %d verified", ev.Verified)
	if n := len(ev.Pending); n > 0 {
		fmt.Fprintf(w, ", %d awaiting a covering checkpoint", n)
	}
	if n := len(ev.NotLogged); n > 0 {
		fmt.Fprintf(w, ", %d served without a leaf (recorded while no log was active)", n)
	}
	if n := len(ev.Failed); n > 0 {
		fmt.Fprintf(w, ", %d FAILED", n)
	}
	fmt.Fprintln(w)
	if rep.Truncated {
		fmt.Fprintln(w, "feed:        page limit reached; rerun to continue")
	}
	for _, f := range ev.Failed {
		if f.Index != nil {
			fmt.Fprintf(w, "  FAILED %s (leaf index %d): %s\n", f.ID, *f.Index, f.Reason)
		} else {
			fmt.Fprintf(w, "  FAILED %s: %s\n", f.ID, f.Reason)
		}
	}
}

// readEvents accepts the shapes a customer is likely to have on hand: one
// served event object, a JSON array of them, an activity-feed page
// ({"data": [...]}), or one object per line.
func readEvents(path string, stdin io.Reader) ([]json.RawMessage, error) {
	r := stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close() //nolint:errcheck // read-only
		r = f
	}
	raw, err := io.ReadAll(io.LimitReader(r, maxInputBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxInputBytes {
		return nil, fmt.Errorf("input exceeds %d MiB; split it", maxInputBytes>>20)
	}
	raw = bytes.TrimSpace(raw)
	switch {
	case len(raw) == 0:
		return nil, errors.New("no events in input")
	case raw[0] == '[':
		var arr []json.RawMessage
		if err := json.Unmarshal(raw, &arr); err != nil {
			return nil, fmt.Errorf("input: %w", err)
		}
		return arr, nil
	case raw[0] == '{':
		probe, perr := strictObject(raw)
		if perr != nil {
			// A single object that is malformed as an event is the
			// verifier's to refuse, not the argument parser's: the same
			// bytes inside an array or a page reach `leaf.Parse` and fail
			// verification, and framing must not change the exit code.
			// Only a page wrapper's own defects are input errors, and this
			// is a page only if every member it carries is one a page has:
			// an event that merely owns a field named "data" is still an
			// event, and its defects are the verifier's to refuse.
			if !looksLikePage(topLevelNames(raw)) {
				return []json.RawMessage{raw}, nil
			}
			return nil, fmt.Errorf("input: %w", perr)
		}
		if data, isPage := probe["data"]; isPage {
			if !looksLikePage(probe) {
				return nil, errors.New("input object carries both a \"data\" array and names an event carries: it is neither clearly a feed page nor one event")
			}
			var arr []json.RawMessage
			if err := json.Unmarshal(data, &arr); err != nil {
				return nil, fmt.Errorf("input: \"data\": %w", err)
			}
			return arr, nil
		}
		if json.Valid(raw) {
			return []json.RawMessage{raw}, nil
		}
		var out []json.RawMessage
		sc := bufio.NewScanner(bytes.NewReader(raw))
		sc.Buffer(make([]byte, 0, 64<<10), maxInputBytes)
		for n := 1; sc.Scan(); n++ {
			line := bytes.TrimSpace(sc.Bytes())
			if len(line) == 0 {
				continue
			}
			if !json.Valid(line) {
				return nil, fmt.Errorf("input line %d is not a JSON object", n)
			}
			out = append(out, bytes.Clone(line))
		}
		return out, sc.Err()
	}
	return nil, errors.New("input is not JSON")
}

// readBaselines turns the caller's own records into baselines this pass must
// prove the log still extends.
func readBaselines(from, fromTrusted string, prevSize uint64, prevHash string, cpv *checkpoint.Verifier) ([]axtverify.Baseline, error) {
	if from != "" && fromTrusted != "" {
		return nil, usageError{errors.New("pass --from or --from-trusted, not both")}
	}
	if (prevSize == 0) != (prevHash == "") {
		return nil, usageError{errors.New("--prev-size and --prev-hash go together")}
	}
	if (from != "" || fromTrusted != "") && prevSize != 0 {
		return nil, usageError{errors.New("pass a checkpoint file or a --prev-size/--prev-hash pair, not both")}
	}
	var out []axtverify.Baseline
	if path := cmp.Or(from, fromTrusted); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, usageError{err}
		}
		trusted := fromTrusted != ""
		cp, err := axtverify.ReadBaselineNote(raw, cpv, trusted)
		if err != nil {
			// A note that does not verify is a finding; a file that is not a
			// note at all is a mistake in the invocation. Neither is
			// "rerun and it may work".
			if errors.Is(err, checkpoint.ErrSignature) {
				// Not wrapped as ErrSignature: that is the served-checkpoint
				// case, whose advice (upgrade for a rotation) is the opposite
				// of this one's.
				//nolint:errorlint // deliberately unwrapped; see above
				return nil, fmt.Errorf("%w: %s: %v; an archive signed before a key rotation goes to --from-trusted", axtverify.ErrVerification, path, err)
			}
			if errors.Is(err, checkpoint.ErrOrigin) {
				return nil, fmt.Errorf("%w: %s: %w", axtverify.ErrVerification, path, err)
			}
			return nil, usageError{fmt.Errorf("%s: %w", path, err)}
		}
		label := path
		if trusted {
			label = path + " (trusted without checking signatures)"
		}
		out = append(out, axtverify.Baseline{Checkpoint: cp, Label: label})
	}
	if prevSize != 0 {
		b, err := axtverify.BaselineFromPair(prevSize, prevHash)
		if err != nil {
			return nil, usageError{err}
		}
		out = append(out, b)
	}
	return out, nil
}

// saveNote records the checkpoint this pass verified, so the next pass can be
// asked to prove the log still extends it. The note is public data.
func saveNote(path, note string) error {
	if note == "" {
		return errors.New("this pass verified no checkpoint to save")
	}
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".save*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) //nolint:errcheck // best-effort once the rename has taken it
	if err := f.Chmod(0o644); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.WriteString(note); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
