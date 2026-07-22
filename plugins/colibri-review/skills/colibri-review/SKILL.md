---
name: colibri-review
description: A rigorous, context-aware protocol for ALL code review and debugging. Use whenever asked to review code, audit a file, hunt bugs, check code quality, propose features for a module, debug a failure, investigate an error, or fix a reported defect — in any repo, any language. Reviews one file at a time, assembles repo context before judging, and adversarially verifies every finding before it ships. Never review or debug ad hoc: load this skill first and follow it to the letter.
---

# Colibri Review — a context-aware code review & debug protocol

Lineage: a one-file-per-review console proved the method — one file per unit, severity-ranked
findings with exact line numbers, and sha-keyed caching so unchanged files are never re-reviewed.
In practice a capable model with full repo context matches or beats a paid blind single-file
reviewer, so the blind external call is demoted to an optional second opinion. What replaces it is
this: the same discipline, PLUS everything a blind single-file reviewer can never have — repo
context, project records, and a verification pass.

**The three laws** (violating any one voids the review):
1. **One file per review unit.** Depth beats breadth. A multi-file task is a sequence of
   single-file reviews plus one cross-file synthesis at the end — never one shallow pass.
2. **Context before code.** Assemble the context pack (Phase 1) before forming ANY opinion.
3. **No finding ships unverified.** Every finding survives the adversarial pass (Phase 3) or it
   is deleted. History demands this: external reviewers have flagged live code as "abandoned" and
   misread deliberate patterns as bugs. Confidence is not evidence.

## Phase 0 — Scope & freshness gate
- Identify the unit(s): explicit file(s), or for a folder/repo rank candidates core-first (shallow
  paths, `__init__` / `app` / `main` / `core` / `cli` / `server`), deny-list vendored/scratch trees
  (`.git venv node_modules build dist vendor __pycache__ *.min.* site-packages` and any
  scratch/output dirs), skip files > 2 MB.
- **Freshness:** read the CURRENT on-disk file at dispatch time — never a snapshot, never memory of
  an earlier read. Record `sha256` of the exact bytes reviewed.
- **Cache check:** if a prior review for this file+mode at the same sha exists (see the review store
  in Phase 4), do NOT re-review — report the existing one unless explicitly forced.
- **Remediation check:** if the project keeps a remediation log / fixed-issues record, load it.
  Findings already closed there are excluded up front; a finding that turns out to target
  already-fixed code is recorded `verified-stale` with evidence, never "re-fixed" (fabricating a fix
  for already-fixed code is a defect, not diligence).

## Phase 1 — Context pack (the edge a blind reviewer can't have)
Assemble BEFORE reading the file body, and summarize it in the review header:
- **Symbol map:** use a code-intelligence tool (symbol search / find-references / file outline — a
  language server, ctags, an indexer, or your editor's index) to see who calls into this file and
  what the call sites actually pass. Prefer these over ad-hoc text search — they're cheaper and more
  precise. If your project isn't indexed yet, index it first, then query.
- **Contract sources:** docstrings/comments in the file are CLAIMS to audit, not truth. Pull any
  project records touching this file (feature/design docs, decision log, remediation log) and the
  relevant project invariants (e.g. byte-parity between mirrored files, secrets handling, platform
  constraints, security/compliance rules).
- **Recent history:** recent commits and change-log entries touching the file — what changed lately
  is where bugs live.
- Cap the pack at what fits comfortably; prefer call-site EVIDENCE over more breadth.

## Phase 2 — The review pass (per mode; run `bug` unless told otherwise)
Read the file end to end with line numbers. Then produce the mode's exact contract:

**bug** — persona: rigorous senior staff engineer + appsec reviewer. Hunt REAL defects only, no
style padding: logic/correctness, off-by-one, None/undefined, unhandled error paths, boundaries,
races/concurrency, resource leaks, missing validation, injection / traversal / SSRF /
deserialization, auth & secret handling, overflow, wrong API usage, silent failures. Output:
```
## Verdict            (1-2 sentences: shippable? single biggest risk?)
## Bugs & vulnerabilities   (worst first)
**[CRITICAL|HIGH|MEDIUM|LOW] title** - `line N`
- What / Trigger / Impact / Fix    (exact defect, exact condition, what breaks, concrete change)
## Missing safeguards (bullets)
```

**quality** — persona: principal engineer, long-term code health; never invent bugs. Output:
`## Health score` X/10 + one line; `## Improvements` ([HIGH|MEDIUM|LOW], line/symbol, Issue → Better
with short before/after); `## Quick wins`; `## What's done well`.

**feature** — persona: pragmatic product-minded staff engineer, grounded in what the code does.
Output: `## What this module does`; `## Suggested add-ons` (Value High/Med/Low · Effort S/M/L,
What/Why/How with hook points); `## Nice-to-haves`.

**Context-aware checks (mandatory additions in every mode — the reason this beats a blind review):**
- Cross-file contract breaks: caller passes X, this file assumes Y (cite BOTH sites).
- Duplication of logic that already exists elsewhere in the repo (name the twin).
- Violations of recorded decisions/invariants (project docs, decision log, style/design guide).
- Staleness: does the docstring/comment still match the behavior?
- For fixes proposed: would they break any call site found in Phase 1?

## Phase 3 — Adversarial verification (mandatory, separate pass)
For EVERY draft finding: re-open the cited lines fresh and try to REFUTE it. Trace the trigger
condition through the actual code path, checking guards upstream and call-site reality from Phase 1.
Then mark it:
- **CONFIRMED** — the trigger path traced end to end; keep it.
- **PLAUSIBLE** — could not fully trace (needs runtime/hardware); keep ONLY with an explicit
  "unverified because ..." note. Never present as confirmed.
- Refuted → DELETE (silently; a deleted wrong finding is a success, not a loss).
Static-analysis inputs (linters etc.) are hints, never findings, until traced.

## Phase D — Debug modality (when hunting a specific failure, not reviewing)
Same laws + the debug ladder, in order, no skipping:
1. **Reproduce or capture** the failure signal first (error text, log, failing input). No fix is
   proposed for a failure that hasn't been observed or precisely characterized.
2. **Context pack** on the implicated file(s) (Phase 1) — one file at a time.
3. **Hypothesis ledger:** list ranked hypotheses; for each, the observation that would confirm/kill
   it. Check them against SOURCE (and cheap instrumentation) — top-down.
4. **One variable at a time.** Minimal fix at the root cause, never at the symptom.
5. **Verify by re-running the reproducer** (or the closest harness/battery). Evidence before "fixed".
6. **Log the fix** in the project's remediation log in the SAME commit; consult it first so closed
   findings aren't re-fixed.

## Phase 4 — Persist & close (every review/debug, no exceptions)
- Write the review to `.colibri_reviews/<rel path with separators as __>__<mode>__<sha8>.md` with a
  header: source path · reviewer (model/tool id) · sha256 · date · mode · one-line context-pack
  summary (what was consulted).
- Update `.colibri_reviews/_manifest.json` (per file → per mode → `{sha, output, reviewed_at,
  tokens_in/out if known, cost}`). This is the sha-keyed cache Phase 0 checks.
- Multi-file jobs end with ONE synthesis section (cross-file findings, ranked) after all per-file
  units — never instead of them.
- Repo work → commit per your project's convention (e.g. `review(scope):` or `fix(scope):`), with
  the remediation-log entry in the SAME commit as the fix.

## External second opinions (demoted, optional)
A paid external reviewer (another model / API) is permitted ONLY as a second opinion after the
in-session review exists, sending the CURRENT on-disk bytes, and disclosing the cost BEFORE the
call. Its findings enter the report only after passing Phase 3 verification. It is never the
primary reviewer.

## Non-negotiables recap
One file at a time · context pack first · code-intelligence tooling over ad-hoc text search ·
current bytes + sha recorded · project records consulted before and updated after · every finding
CONFIRMED or labeled PLAUSIBLE · debug = reproduce → hypothesize → verify → log · commit at close.
