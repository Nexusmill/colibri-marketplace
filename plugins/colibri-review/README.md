# Colibri Review

A rigorous, context-aware protocol for **code review and debugging** — in any repo, any language.

Most review tools skim a file and emit a list. Colibri Review is a discipline: it reviews **one
file at a time**, assembles **repo context before judging**, and **adversarially verifies every
finding** before it ships. A finding that can't be traced end-to-end is deleted, not shipped.

## What it does

When you ask Claude to review code, audit a file, hunt bugs, check quality, propose features for a
module, check code against a spec or stated expectations, plan the remediation of known findings,
debug a failure, investigate an error, or fix a reported defect, this plugin's skill kicks
in and runs the protocol:

1. **Scope & freshness** — pick the file, read its *current* bytes, record a sha, and load
   anything already reviewed at that sha as **context**: every pass hunts only NEW findings
   beyond what the record already contains.
2. **Context pack** — map the file's symbols and call sites (via whatever code-intelligence tooling
   you have), pull relevant project docs/decisions, and check what changed recently.
3. **Review pass** — one of five modes, each with a strict output contract and
   exact line numbers: `bug` (real defects, no style padding), `quality` (long-term health),
   `feature` (grounded add-on ideas), `spec` (conformance against the maintainer's stated
   expectations — divergences only, quiet clauses checked hardest, cross-file clauses named as
   UNJUDGEABLE HERE instead of guessed), and `plan` (test-first remediation plans that are never
   executed by their author).
4. **Adversarial verification** — every draft finding must be traced through the real code path and
   marked CONFIRMED or PLAUSIBLE, or it's dropped.
5. **Persist & close** — write the review to `.colibri_reviews/`, update the sha-keyed cache, and
   (for fixes) log the remediation in the same commit.

There's also a **debug ladder** (reproduce → context → hypothesis ledger → one-variable fix →
verify by re-running the reproducer) for when you're chasing a specific failure rather than
reviewing.

## Triggering

The skill loads automatically on review/debug requests. You can also invoke it by name, e.g.
"use colibri-review on this file" or "review `path/to/file.py` in bug mode".

## Conventions it introduces

- **`.colibri_reviews/`** — a folder of per-file review notes plus a `_manifest.json` cache.
  A prior review is never skipped: it loads as context and the next pass hunts only new
  findings, recorded as `pass2`/`passN` lineage. When **three different model types** each
  come back empty at the same sha, the file+mode is **LOCKED** — no further scans of that
  mode until the file's bytes change (feature mode never locks: its space is infinite).
  Commit it or gitignore it, your call.
- If your project keeps a **remediation log** (a record of fixed defects), the skill reads it before
  reviewing so it never re-flags or re-"fixes" already-closed issues, and appends to it when it
  lands a fix.

## License

MIT — see [LICENSE](./LICENSE).
