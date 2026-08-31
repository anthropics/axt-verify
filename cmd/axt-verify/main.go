// Copyright 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

// Command axt-verify checks that Anthropic's Access Transparency log for your
// organization is what it claims to be: correctly signed, append-only, and
// committing to the events the Compliance API serves you.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/anthropics/axt-verify"
	"github.com/anthropics/axt-verify/checkpoint"
)

// version is stamped at build time with -ldflags "-X main.version=vX.Y.Z".
// A `go install …@vX.Y.Z` build has no ldflags, so buildVersion falls back to
// the module version Go records in the binary.
var version = "dev"

// buildVersion is the version this binary reports and sends as its User-Agent.
func buildVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return version
	}
	return resolveVersion(version, info)
}

// resolveVersion prefers the stamped version; when none was stamped it takes
// the module version from the build info, which a `go install` build records
// and a build from a plain checkout leaves as "(devel)".
func resolveVersion(stamped string, info *debug.BuildInfo) string {
	if stamped != "dev" || info == nil {
		return stamped
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	return stamped
}

const (
	// apiKeyEnv is the name the Compliance API documentation uses for the key.
	apiKeyEnv = "ANTHROPIC_COMPLIANCE_ACCESS_KEY"

	exitOK        = 0
	exitFailed    = 1 // a verification failure: a security finding
	exitUsage     = 2
	exitTransient = 3 // could not complete; rerun
)

// usageError marks a mistake in the invocation rather than a finding about
// the log, so the two never share an exit code.
type usageError struct{ error }

// httpClient is nil outside tests, where the default client is used.
var httpClient *http.Client

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := newFlagSet(stderr)
	statePath := fs.String("state", "axt-verify.state", "path to the state file; pass an explicit path from cron")
	jsonOut := fs.Bool("json", false, "print the report as JSON on stdout")
	quiet := fs.Bool("quiet", false, "no progress on stderr")
	maxPages := fs.Int("max-pages", 0, "run: stop after this many feed pages (0 = unbounded); rerun to continue")
	pageSize := fs.Int("page-size", 0, "run: feed page size (default 1000)")
	overlap := fs.Duration("overlap", 0, "run: re-read this far behind the last run's high-water mark (default 168h)")
	grace := fs.Duration("pending-grace", 0, "run: how long an event may await a covering checkpoint before it fails (default 24h)")
	org := fs.String("org", "", "the organization whose log to verify (its UUID)")
	logKey := fs.String("log-key", "", "trust this log verifier key instead of the one built into this release (for an announced rotation before you can upgrade, or a test log); env "+logKeyEnv)
	from := fs.String("from", "", "prove the log still extends this checkpoint file (a signed note, a --json report, or a state file)")
	fromTrusted := fs.String("from-trusted", "", "like --from, but trust the file's (size, root) as your own record without checking its signatures")
	prevSize := fs.Uint64("prev-size", 0, "prove the log still extends this tree size (with --prev-hash)")
	prevHash := fs.String("prev-hash", "", "the root hash at --prev-size, base64 or hex")
	save := fs.String("save", "", "after a successful pass, write the verified checkpoint note to this file")
	fs.Usage = func() {
		fmt.Fprint(stderr, `Usage:
  axt-verify [flags] run           verify the log, then every Access Transparency event on the feed since the last run
  axt-verify [flags] checkpoint    verify the latest checkpoint and the append-only property since the last run
  axt-verify [flags] events FILE   verify served events read from FILE, or "-" for stdin (JSON object, array, {"data":[…]} page, or JSON lines)
  axt-verify version

There is nothing to configure: this release ships the log's verifier key, so
nothing is fetched and nothing is read from disk to decide what to trust.
--log-key overrides it for an announced rotation or a test log, and the state
file defaults to axt-verify.state in the current directory.

To keep your own archive, hand back yesterday's checkpoint and save today's:

  axt-verify --org <uuid> checkpoint --from yesterday.ckpt --save today.ckpt

The Compliance Access Key is read from $`+apiKeyEnv+`.

Exit status: 0 verified · 1 verification FAILED (a security finding) · 2 usage/configuration error · 3 could not complete; rerun

Flags:
`)
		fs.PrintDefaults()
	}
	cmd, positional, code := parseCommandArgs(fs, args)
	if cmd == "" {
		return code
	}
	rest := positional
	if cmd == "version" {
		// Needs no credential and talks to nobody.
		fmt.Fprintln(stdout, "axt-verify", buildVersion())
		return exitOK
	}

	logf := func(format string, args ...any) {
		if !*quiet {
			fmt.Fprintf(stderr, format+"\n", args...)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// The API host is a constant for customers. internalBaseURL is empty in
	// every release build — the file that reads an environment variable into
	// it is compiled only under -tags axtverify_internal — so this is dead
	// code in the binary a customer runs.
	trust := trustOptions{org: *org, baseURL: internalBaseURL, logKey: logKeyFrom(*logKey), stderr: stderr, logf: logf}
	var builtinPrefix string
	// The key this run required a checkpoint to be signed by, for the
	// signature-failure report; nil until the trust policy resolves.
	var trusted *checkpoint.Signature

	rep, err := func() (*axtverify.Report, error) {
		if *overlap < 0 || *grace < 0 {
			return nil, usageError{errors.New("--overlap and --pending-grace must not be negative")}
		}
		if *maxPages < 0 || *pageSize < 0 {
			return nil, usageError{errors.New("--max-pages and --page-size must not be negative")}
		}
		key := os.Getenv(apiKeyEnv)
		if key == "" {
			return nil, usageError{fmt.Errorf("no API key: set $%s to a Compliance Access Key", apiKeyEnv)}
		}
		cpv, client, builtin, err := trust.resolve(key)
		if err != nil {
			return nil, err
		}
		if builtin {
			builtinPrefix = cpv.Origin()[:strings.LastIndex(cpv.Origin(), "/")]
		}
		logKey := cpv.LogKey()
		trusted = &logKey
		baselines, err := readBaselines(*from, *fromTrusted, *prevSize, *prevHash, cpv)
		if err != nil {
			// A report even so: a --json consumer is owed a line for an
			// exit-1 result, and this one names the origin it was for.
			return &axtverify.Report{Origin: cpv.Origin()}, err
		}
		v := &axtverify.Verifier{
			Baselines:    baselines,
			Checkpoints:  cpv,
			Client:       client,
			Overlap:      *overlap,
			PendingGrace: *grace,
			PageSize:     *pageSize,
			MaxPages:     *maxPages,
			Logf:         logf,
		}

		switch cmd {
		case "run", "checkpoint":
			if len(rest) != 0 {
				return nil, usageError{fmt.Errorf("%s takes no arguments", cmd)}
			}
			st, err := axtverify.LoadState(*statePath, cpv.Origin())
			if err != nil {
				return nil, usageError{fmt.Errorf("state: %w", err)}
			}
			var rep axtverify.Report
			if cmd == "run" {
				rep, err = v.Run(ctx, st)
			} else {
				rep, err = v.VerifyCheckpoint(ctx, st)
			}
			if err != nil {
				// The anchor may have advanced before the pass broke off. A
				// checkpoint that verified must not be thrown away, or a log
				// able to force transient failures keeps everything past the
				// last saved size rewritable. A pass that verified nothing has
				// nothing to keep, and must not pin a mistaken invocation's
				// origin to disk.
				if !errors.Is(err, axtverify.ErrVerification) && rep.Checkpoint.RootHash != nil {
					if serr := st.Save(*statePath); serr != nil {
						fmt.Fprintln(stderr, "axt-verify: saving state:", printable(serr.Error()))
					}
				}
				return &rep, err
			}
			// State advances only after a completed pass; failed events
			// stay out of Done and are re-examined next run.
			if err := st.Save(*statePath); err != nil {
				return &rep, fmt.Errorf("saving state: %w", err)
			}
			return &rep, nil
		case "events":
			if len(rest) != 1 {
				return nil, usageError{errors.New("events takes one argument: a file path or -")}
			}
			events, err := readEvents(rest[0], stdin)
			if err != nil {
				return nil, usageError{err}
			}
			logf("read %d events", len(events))
			rep, err := v.VerifyEvents(ctx, nil, events)
			return &rep, err
		default:
			return nil, usageError{fmt.Errorf("unknown command %q", cmd)}
		}
	}()

	if rep != nil {
		scrub(rep)
	}
	// The evidence rides on the report too, so a --json consumer keeps it
	// without having to parse the message.
	if ie, ok := axtverify.AsInconsistency(err); ok && rep != nil {
		rep.Inconsistency = &ie.Evidence
	}
	// A --save that cannot be written still owes the report: the pass
	// verified and the state already advanced, so the JSON line is the only
	// other record of this checkpoint.
	var saveErr error
	if *save != "" {
		switch {
		case err != nil || rep == nil || !rep.OK():
			fmt.Fprintf(stderr, "not saving a checkpoint to %s: this pass did not verify\n", *save)
		default:
			if saveErr = saveNote(*save, rep.Checkpoint.Note); saveErr != nil {
				fmt.Fprintln(stderr, "axt-verify: could not save the checkpoint:", printable(saveErr.Error()))
			}
		}
	}
	if *jsonOut && rep != nil {
		out := struct {
			*axtverify.Report
			OK    bool   `json:"ok"`
			Error string `json:"error,omitempty"`
			// Present only on a signature failure, for the same comparison
			// the stderr report spells out.
			CheckpointSignatures []checkpoint.Signature `json:"checkpoint_signatures,omitempty"`
			TrustedKey           *checkpoint.Signature  `json:"trusted_key,omitempty"`
		}{Report: rep, OK: err == nil && rep.OK()}
		if errors.Is(err, checkpoint.ErrSignature) {
			out.CheckpointSignatures, out.TrustedKey = servedSignatures(err), trusted
		}
		if err != nil {
			out.Error = printable(err.Error())
		} else if saveErr != nil {
			out.Error = printable("saving the checkpoint: " + saveErr.Error())
		}
		// One object per line: the documented cron appends this to a .jsonl
		// that line-oriented readers (this tool's own `events -` included)
		// have to be able to read back.
		if raw, jerr := json.Marshal(out); jerr == nil {
			_, _ = stdout.Write(append(escapeDisplay(raw), '\n'))
		}
	} else if rep != nil && rep.Checkpoint.RootHash != nil {
		printReport(stdout, rep, cmd != "events")
	}

	var ue usageError
	switch {
	case errors.As(err, &ue):
		fmt.Fprintln(stderr, "axt-verify:", err)
		return exitUsage
	case errors.Is(err, axtverify.ErrVerification):
		if ie, ok := axtverify.AsInconsistency(err); ok {
			// Printed in full because the customer has to be able to show
			// this to someone else later, when the log that misbehaved is no
			// longer answering — or is answering differently.
			fmt.Fprintln(stderr, "VERIFICATION FAILED: log inconsistency")
			fmt.Fprintln(stderr, printable(ie.Err.Error()))
			fmt.Fprint(stderr, printableBlock(ie.Details()))
			return exitFailed
		}
		fmt.Fprintln(stderr, "VERIFICATION FAILED:", printable(err.Error()))
		if errors.Is(err, checkpoint.ErrSignature) {
			// Which keys the note claims, against the one this run requires:
			// the published key table is what turns that pair into "upgrade"
			// or "escalate", and the operator cannot look it up without the
			// hashes.
			printSignatures(stderr, err, trusted, builtinPrefix != "")
			// Never re-fetched automatically: a key that fails to verify is
			// exactly when the API's answer is worth least.
			if builtinPrefix != "" {
				fmt.Fprintf(stderr, "the log's signature does not verify under this release's built-in key for %s; if Anthropic announced a key rotation, upgrade axt-verify (or pass --log-key with the new key)\n", builtinPrefix)
			} else {
				fmt.Fprintln(stderr, "if Anthropic announced a key rotation, upgrade axt-verify (or pass --log-key with the new key)")
			}
		}
		return exitFailed
	// Before the transient case: a pass that found something and then could
	// not finish is a finding, and "rerun" would bury it.
	case rep != nil && !rep.OK():
		if err != nil {
			fmt.Fprintln(stderr, "axt-verify: the pass also could not complete:", printable(err.Error()))
		}
		fmt.Fprintf(stderr, "VERIFICATION FAILED: %d event(s) failed verification\n", len(rep.Events.Failed))
		return exitFailed
	// Only before anything verified: once this pass has a verified
	// checkpoint, a credential answer to a later request is the log
	// declining to continue, not the operator's mistake, and "fix your
	// invocation" would be the wrong thing to tell them.
	case permanentRequestError(err) && (rep == nil || rep.Checkpoint.RootHash == nil):
		// "Rerun" would have automation retrying a revoked key forever.
		fmt.Fprintln(stderr, "axt-verify:", printable(err.Error()))
		return exitUsage
	case err != nil:
		fmt.Fprintln(stderr, "axt-verify: could not complete:", printable(err.Error()))
		return exitTransient
	case saveErr != nil:
		return exitTransient
	}
	return exitOK
}

// printable renders a string that came from the API so it can be printed on
// one line. Control characters become \uXXXX escapes (\UXXXXXXXX beyond the
// BMP; \xNN for a byte that is not UTF-8): an id carrying ANSI escapes would
// otherwise be able to erase the FAILED line it is printed on, and that line
// is the tamper evidence. The --json report escapes through escapeDisplay
// instead.
// printSignatures reports the signature lines of the rejected checkpoint
// and the key this run trusts. Names come off an unverified note, so they
// are escaped; a line that did not parse is named rather than shown.
func printSignatures(w io.Writer, err error, trusted *checkpoint.Signature, builtin bool) {
	if sigs := servedSignatures(err); len(sigs) > 0 {
		fmt.Fprintln(w, "signatures on the served checkpoint:")
		for _, sig := range sigs {
			if !sig.OK {
				fmt.Fprintln(w, "  (unparseable signature line)")
				continue
			}
			fmt.Fprintf(w, "  %s  key hash %s\n", sig.Name, sig.KeyHash)
		}
	}
	if trusted == nil {
		return
	}
	source := "supplied via --log-key"
	if builtin {
		source = "built-in"
	}
	fmt.Fprintln(w, "key this run trusts:")
	fmt.Fprintf(w, "  %s  key hash %s   (%s)\n", printable(trusted.Name), trusted.KeyHash, source)
}

// servedSignatures reads the rejected note off a signature failure and
// escapes the names it carried, which is where every consumer gets them
// from. Escaping here rather than at each printer is what the JSON report
// needs: its own escaping is reversible, so a name left raw comes back as
// live terminal sequences the first time someone pipes the field through
// `jq -r`. Any other error, or a failure raised without the note, reports
// nothing.
func servedSignatures(err error) []checkpoint.Signature {
	var se *checkpoint.SignatureError
	if !errors.As(err, &se) {
		return nil
	}
	sigs := checkpoint.Signatures(se.Note)
	for i := range sigs {
		sigs[i].Name = printable(sigs[i].Name)
	}
	return sigs
}

func printable(s string) string {
	var b strings.Builder
	for i, r := range s {
		switch {
		case r == 0x5c: // a literal backslash
			// Escaped so the encoding stays injective: without this, a
			// served string that spells out an escape sequence is
			// indistinguishable from one that carries it, and the
			// forwardable evidence stops being evidence.
			b.WriteString(`\\`)
		case r == utf8.RuneError:
			// Either a real U+FFFD or a byte that decodes to none: escape
			// the byte itself so the two do not print alike.
			if _, n := utf8.DecodeRuneInString(s[i:]); n == 1 {
				fmt.Fprintf(&b, `\x%02x`, s[i])
				continue
			}
			b.WriteRune(r)
		case isControl(r), r == '\n', r == '\t':
			// Newlines and tabs included: a served message is one line, and
			// letting it break lines would forge entries in whatever log
			// this output is appended to. Astral runes get the 8-digit form,
			// so a reader can tell U+E0001 from U+E000 followed by "1".
			if r > 0xffff {
				fmt.Fprintf(&b, `\U%08x`, r)
				continue
			}
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// escapeDisplay rewrites, as JSON \u escapes, every character a served string
// could use to rewrite the terminal this report is eventually read in. It
// escapes into the JSON string rather than altering the value: \u001b decodes
// to the same rune, so the archived checkpoint still reads back
// byte-identically through --from, and --save writes the raw served note.
func escapeDisplay(raw []byte) []byte {
	if bytes.IndexFunc(raw, isControl) < 0 {
		return raw
	}
	var b bytes.Buffer
	for _, r := range string(raw) {
		// The same predicate the stderr path uses, so one served note cannot
		// be dangerous in the log and safe on the terminal: C1, the line and
		// paragraph separators, every Cf format character (bidi overrides
		// and isolates, zero-width marks, tag characters) and the variation
		// selectors. Go's encoder already escapes C0.
		if isControl(r) {
			writeJSONEscape(&b, r)
			continue
		}
		b.WriteRune(r)
	}
	return b.Bytes()
}

// writeJSONEscape writes r as JSON \u escapes. JSON escapes are UTF-16 code
// units, so anything outside the BMP needs a surrogate pair — `\u%04x` on an
// astral rune emits five hex digits, of which a decoder consumes four and
// leaves the fifth as literal text, which would silently corrupt the archived
// note this escaping exists to keep intact.
func writeJSONEscape(b *bytes.Buffer, r rune) {
	if r > 0xffff {
		r1, r2 := utf16.EncodeRune(r)
		fmt.Fprintf(b, `\u%04x\u%04x`, r1, r2)
		return
	}
	fmt.Fprintf(b, `\u%04x`, r)
}

func printableBlock(s string) string {
	lines := strings.Split(s, "\n")
	for i, ln := range lines {
		lines[i] = printable(ln)
	}
	return strings.Join(lines, "\n")
}

func isControl(r rune) bool {
	switch {
	case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f:
		return true
	case r == 0x2028 || r == 0x2029:
		return true
	// Cf covers the bidi embeddings/overrides/isolates and zero-width marks;
	// the variation selectors are Mn.
	case unicode.Is(unicode.Cf, r), unicode.Is(unicode.Variation_Selector, r):
		// Invisible by construction: zero-width joiners, marks, tag
		// characters, byte-order marks. They can hide or reshape what a
		// FAILED line says without showing anything.
		return true
	}
	return false
}
