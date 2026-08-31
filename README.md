# axt-verify

`axt-verify` lets an organization enrolled in Anthropic **Access Transparency**
check, on its own machines and without trusting Anthropic's serving path, that:

1. the transparency log Anthropic serves for the organization is signed by the
   key this release carries and has only ever been appended to; and
2. every Access Transparency event the Compliance API serves — each record of
   Anthropic personnel accessing or preserving the organization's data — is
   committed in that log, byte for byte.

If Anthropic (or anyone in between) rewrote or back-dated an event it serves,
re-served one it had already shown you with different content or at a
different position in the log — for as long as the feed keeps listing that
event, plus the overlap window — or served the organization a rolled-back or
forked history, a run fails. What the tool cannot do is prove the feed showed
you every leaf your log holds: it checks what you are served against what the
log committed, so an event simply left out of the feed is not something an
inclusion proof can speak for.

The log format is the open [C2SP tlog-tiles](https://c2sp.org/tlog-tiles)
standard; this tool adds the Access Transparency specifics — the event
canonicalization and the Compliance API transport — on top of the standard
`golang.org/x/mod/sumdb/note` and `github.com/transparency-dev/{formats,merkle}`
libraries. See *How verification works* below and the Transparency Log section
of the Compliance API reference.

> **Maintenance status:** actively maintained. We triage issues and review pull requests; see `CONTRIBUTING.md`.

## Install

Requires Go 1.26 or newer.

```sh
go install github.com/anthropics/axt-verify/cmd/axt-verify@latest
```

or build from a checkout with `go build ./cmd/axt-verify`. The binary has no
runtime dependencies.

## Setup

Two inputs, both supplied on the command line or in the environment:

| Input | What it is |
|---|---|
| `ANTHROPIC_COMPLIANCE_ACCESS_KEY` | A **Compliance Access Key** with the `read:compliance_activities` scope — the same key you use for the Compliance API Activity Feed (see "Set up the Compliance API" in the Claude docs). Read from the environment only, never from a file or a flag. |
| `--org` | Your organization's UUID — the value the Activity Feed serves as `organization_uuid` (not the `org_…` tagged id). |

```sh
export ANTHROPIC_COMPLIANCE_ACCESS_KEY=…
axt-verify --org 25f6429a-3293-49bf-afed-cb312911554b checkpoint
```

The log's public key ships inside this release, so nothing is fetched and
nothing is read from disk to decide what to trust. (The tool does write: `run`
and `checkpoint` keep their progress in a state file, and `--save` writes a
checkpoint archive — see `--state` below.)

The table below is the key this release carries, and it doubles as the
published record to check a build against. Your log's origin is
`axt.anthropic.com/<your org uuid>`, and every checkpoint must carry exactly
that line:

| Origin prefix | SHA-256 of the public key |
|---|---|
| `axt.anthropic.com` | `1dff5fe420d49743fe444a04fc17f818eea856699dec2ebbc24df15602c74a58` |

### Overrides

| Flag | Meaning |
|---|---|
| `--log-key` | Trust this note-verifier key instead of the one built into this release — for an announced key rotation before you can upgrade. The key's own name is the origin every checkpoint must then carry, and it has to end in `/<your org uuid>`, so the key and the log it verifies cannot disagree. Also read from `$AXT_VERIFY_LOG_KEY`; the flag wins. |
| `--state` | Where to keep the state file. Defaults to `axt-verify.state` in the current directory — pass an explicit path from cron. |

**Keys rotate by release.** A checkpoint that does not verify under the shipped
key is a hard failure, never an occasion to go and fetch a different key: if
Anthropic announces a rotation, upgrade `axt-verify`, or pass the new key with
`--log-key` until you can. Such a failure prints the key hashes the served
checkpoint claims, alongside the hash of the key this run trusts. The
signatures did not verify, so those are claims rather than proof: a claimed
hash that is not in Anthropic's published key table is a security finding, and
one that is in the table points at a rotation you have not upgraded to —
upgrade, or pass `--log-key`, and run again. If it still fails, treat it as a
security finding, because anyone who can serve you a checkpoint that does not
verify can also put a published key's hash on it.

**Only the newest key is needed.** A checkpoint commits to the whole history,
so once one checkpoint signed by the new key verifies, and a consistency proof
from the checkpoint you last saved leads to it, that proof re-establishes every
entry before the rotation as well — the old key is not needed to verify what it
once signed. The one exception is an archived checkpoint you hold that the old
key signed: `--from` verifies its signature and would refuse it under the new
key, so pass such a file with `--from-trusted`, which takes its tree size and
root hash as your own record without checking the signature. The origin is
still enforced.

## Commands

| Command | What it does |
|---|---|
| `run` | The one to put in cron: verify the latest checkpoint, prove the log only appended since your last run, then page through your Access Transparency events and prove each is committed in the log. |
| `checkpoint` | Verify the latest checkpoint and the append-only property, without reading the event feed. Cheap enough for a tighter schedule than the full run; give it its own `--state` file. |
| `events FILE` | Verify events you already hold, read from a file or `-` for stdin — a JSON object, an array, a `{"data":[…]}` page, or one JSON object per line. Proves each against the log without touching the feed. Rows that are not Access Transparency records — other activity types in the same page or export — are ignored and counted, not failed. Each object is otherwise verified as given: unlike `run`, this does not collapse two copies of one event id, so a page captured while the log was first stamping indexes can list the same id twice — once as *not logged* and once verified. |
| `version` | Print the version. Needs no credential and makes no request. |

`--from`, `--from-trusted`, `--prev-size`/`--prev-hash` and `--save` work with
`run` and `checkpoint`; see *Keeping your own checkpoint archive*.

## Run

```sh
axt-verify run
```

does, in order:

1. fetches the latest checkpoint and verifies the log signature and the origin
   line;
2. proves the log is an append-only extension of the checkpoint saved by the
   previous run (the *consistency proof*);
3. pages through your Access Transparency events on `GET /v1/compliance/activities`
   since the previous run (plus a seven-day overlap for late-arriving events),
   rebuilds each event's leaf from the served JSON, and verifies an *inclusion
   proof* for it against the checkpoint;
4. saves the new checkpoint and its progress to `axt-verify.state` (in the
   current directory; override with `--state`, and do from cron).

Schedule it — hourly is reasonable — and alert on the exit status:

| Exit | Meaning | Action |
|---|---|---|
| **0** | Nothing failed. Events served with no leaf, and — under `run` — events still awaiting a checkpoint, are reported rather than verified — see *Event outcomes*. | — |
| **1** | **Verification failed**: a bad signature, wrong origin, a log that shrank or forked, an invalid proof, or an event whose served content is not what the log committed. | Treat as a security finding. Keep the state file and the output; contact Anthropic. |
| **2** | Usage error. | Fix the invocation. |
| **3** | Could not complete: network failure, API errors, rate limiting after retries, or an `events` file holding an index the log has published no checkpoint for, or no proof for one it published while the check waited. | Rerun; page only if it persists. |

```cron
17 * * * *  ANTHROPIC_COMPLIANCE_ACCESS_KEY=$(cat /etc/axt-verify/key) axt-verify --org <uuid> --state /var/lib/axt-verify/state --json run >>/var/log/axt-verify.jsonl || alert "axt-verify exit $?"
```

Sample output:

```
origin:      axt.anthropic.com/25f6429a-3293-49bf-afed-cb312911554b
checkpoint:  tree size 1207, root hash nB9mUdyOWMp0zXI0k1S…=
append-only: verified from tree size 1188
events:      19 verified
```

`--json` prints the same report as one JSON object, one per line. The complete
field list:

| Field | Meaning |
|---|---|
| `ok` | True when nothing this pass examined failed. |
| `origin` | The origin every checkpoint had to carry. |
| `checkpoint.size`, `checkpoint.root_hash` | The tree this pass verified. |
| `checkpoint.note` | The signed checkpoint verbatim — valid input to `--from`, so a line of this log is an archive of what the log said. |
| `previous_size` | Tree size the append-only check started from; null on a first run. |
| `events.verified` | Count of events proven present in the log. |
| `events.not_logged`, `events.pending` | Event ids in those outcomes (see *Event outcomes*). |
| `events.failed[].id`, `.leaf_index`, `.reason` | Each finding: which event, where it claimed to sit, and what was wrong. |
| `events.skipped_other_types` | Rows that are not Access Transparency records, passed over rather than checked. |
| `truncated` | True when `--max-pages` stopped the feed read early. |
| `inconsistency.older`, `.newer`, `.proof` | Present only on an append-only failure: both checkpoint notes and the proof hashes the log served between them, so the evidence stands on its own. |
| `error` | The failure message, when there was one. |

### Other commands

- `axt-verify checkpoint` — steps 1, 2 and 4 only. Cheap; suitable for a
  tighter schedule than the full run. Give it its own `--state` file: two
  invocations that overlap on one file would each verify a different honest
  extension of the same anchor, so a save refuses a file that changed while
  the pass ran (exit 3) rather than discard the other's checkpoint.
- `axt-verify events FILE` — verify events you already hold (a SIEM export, an
  auditor's sample) instead of reading the feed. It checks each event against a
  freshly fetched checkpoint and keeps no anchor, so it cannot tell you the log
  is the same one it was yesterday; the scheduled `run` is what does that.
  `FILE` (or `-` for stdin) may be one served event object, a JSON array of
  them, a raw `/v1/compliance/activities` page, or one object per line. Does
  not touch the state file.

### Event outcomes

- **verified** — the leaf rebuilt from the served event is provably at the
  event's `transparency_log_leaf_index` in the signed tree.
- **pending** — the event's index is beyond the latest published checkpoint.
  Normal for a few minutes after an event appears; `run` remembers it and
  verifies it once covered, and fails it if that takes longer than
  `--pending-grace` (24h). `events` remembers nothing, so it waits up to a
  minute for the log to publish a checkpoint that covers the file and
  verifies against that. Anything still uncovered, and anything the log
  published while it waited but serves no proof for yet, is reported pending
  and exits 3: run the file again once the log has caught up, and treat an
  event that never settles as a finding. An index the log had already
  published before the check began is held to the stricter rule: the check
  re-reads the proof endpoint for the rest of its minute, and only a proof
  still missing when that runs out is a failure — see exit status 1.
- **not logged** — the event was served with a null index: it was recorded
  while your organization had no active log (before enrollment, or between
  disenrollment and re-enrollment), and is expected for those periods. The
  tool reports these and does not judge them: an event's `created_at` and the
  absence of an index are served, not committed, so there is nothing to check
  them against.
- **FAILED** — see exit status 1.

### Flags worth knowing

`--max-pages N` bounds one run's feed read for a very large backlog; the run
reports `truncated` and the next run resumes. Set too low to get past where
the previous run stopped, the run fails (exit 3) rather than quietly re-read
the same events forever. `--overlap` widens the re-read
window if your events are subject to unusually long delivery delays.

## Keeping your own checkpoint archive

The strongest thing you can hold is your own record of what the log said
yesterday. Hand it back tomorrow and the log has to prove it still extends it:

```sh
axt-verify --org <uuid> --state /var/lib/axt-verify/archive.state checkpoint --from yesterday.ckpt --save today.ckpt
mv today.ckpt yesterday.ckpt
```

`--save` writes the verified checkpoint note verbatim, and only after a pass
that verified. `--from` accepts that file, a `--json` report line, or a state
file. For an archive signed by a key that has since rotated out, `--from-trusted`
takes the file's tree size and root hash as your own record without checking
its signatures; `--prev-size` and `--prev-hash` do the same for a pair you kept
somewhere else. If the log cannot prove it extends what you kept, the failure
prints both checkpoints and the proof in full, so the evidence does not depend
on that log staying reachable.

## How verification works

- **Checkpoint.** A [signed note](https://c2sp.org/signed-note): origin line,
  tree size, root hash, then signatures. Accepted only if the log key signed it
  and the origin line equals your origin exactly. All organizations' logs are
  signed by the same key, so the origin comparison — not the signature — is
  what makes a checkpoint yours.
- **Append-only.** The previous run's checkpoint is kept in the state file. A
  tree smaller than the saved one is a rollback unless the log can still show
  a head covering the saved size and prove the saved checkpoint is a prefix of
  it — a read served from behind recovers, a log that has lost the tree does
  not; an equal tree must have the same root; a larger tree must come with an
  RFC 6962 consistency proof
  (`GET …/transparency_log/consistency?from=N`). Checkpoints that arrive
  embedded in proof responses mid-run are linked into the same history the same
  way before anything is verified against them.
- **Inclusion.** Each served event is projected onto leaf field set v1 —
  eleven keys, RFC 8785 canonical JSON, prefixed with the version byte `0x01` —
  exactly as the Compliance API reference's *Leaf canonicalization* section
  specifies; `leaf/` is that specification in code and is tested against the
  log's own golden vectors. The leaf hash and the audit path from
  `GET …/transparency_log/inclusion?leaf_index=N` must reproduce the signed
  root. An event type outside v1's list (`anthropic_access`, `cmek_preserve`)
  is refused: new types ship under a new version byte and need a newer
  `axt-verify`.
- **Nothing from the API is trusted** until it verifies against the key this
  release carries: not the checkpoint, not the proofs, not the leaf index.

## Limits

- The tool proves that what you are served matches what the log committed,
  and that the log's history only grows. It cannot prove the feed showed you
  every leaf your log holds; see the introduction above.
- Without an independent timestamping party, a targeted replay of a stale
  checkpoint together with a frozen feed is not detectable from the client
  side: every proof still verifies against the old tree. Archive verified
  checkpoints with `--save`, compare them across runs and machines, and raise a
  checkpoint that stops growing for an unexpectedly long time with Anthropic.

## Security considerations

- The trust anchor can be overridden from the environment: `--log-key` and
  `$AXT_VERIFY_LOG_KEY` replace the built-in key. The tool names the key it
  trusts on stderr, and a supplied key is announced even with `--quiet`.
  Protect the environment your cron line runs in, and watch that line.
- `--from-trusted` and `--prev-size`/`--prev-hash` are baselines taken on your
  word, with no signature check. Protect the files and values you pass them.
- Deleting the state file re-baselines the next run: it starts from whatever
  checkpoint the log serves (exit 0) and can detect no rollback that run. Keep
  an archived note (`--save`, handed back with `--from`) as the durable anchor.
- The Compliance Access Key is read from `$ANTHROPIC_COMPLIANCE_ACCESS_KEY` and
  grants read access to all of your organization's compliance activities. A
  process running as the same user can read the cron's environment; scope that
  user and the key file accordingly.
- Build releases without build tags. A build made with
  `-tags axtverify_internal` honours an API-host override from the
  environment; a release build has no such override.
- Library users: `compliance.Client.AllowInsecure` permits a plain-http base
  URL and is for tests only.

## Library use

The packages under this module (`leaf`, `checkpoint`, `compliance`, and the
top-level `axtverify`) are importable for pipelines that would rather embed
verification than shell out. The command is a thin wrapper over them.

## License

This project is licensed under the Apache License 2.0.
See the `LICENSE` file at the repository root for the full text.

Copyright 2026 Anthropic PBC
