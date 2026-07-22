# Colibri Review

A rigorous, context-aware protocol for **code review and debugging** — in any repo, any language.

Most review tools skim a file and emit a list. Colibri Review is a discipline: it reviews **one
file at a time**, assembles **repo context before judging**, and **adversarially verifies every
finding** before it ships. A finding that can't be traced end-to-end is deleted, not shipped.

## What it does

When you ask Claude to review code, audit a file, hunt bugs, check quality, propose features for a
module, debug a failure, investigate an error, or fix a reported defect, this plugin's skill kicks
in and runs the protocol:

1. **Scope & freshness** — pick the file, read its *current* bytes, record a sha, and skip anything
   already reviewed at that sha or already fixed in your remediation log.
2. **Context pack** — map the file's symbols and call sites (via whatever code-intelligence tooling
   you have), pull relevant project docs/decisions, and check what changed recently.
3. **Review pass** — `bug`, `quality`, or `feature` mode, each with a strict output contract and
   exact line numbers.
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

- **`.colibri_reviews/`** — a folder of per-file review notes plus a `_manifest.json` cache so
  unchanged files are never re-reviewed. Commit it or gitignore it, your call.
- If your project keeps a **remediation log** (a record of fixed defects), the skill reads it before
  reviewing so it never re-flags or re-"fixes" already-closed issues, and appends to it when it
  lands a fix.

## License

MIT — see [LICENSE](./LICENSE).
