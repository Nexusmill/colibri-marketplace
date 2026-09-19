---
name: colibri-review
description: A rigorous, context-aware protocol for ALL code review and debugging. Use whenever asked to review code, audit a file, hunt bugs, check code quality, propose features for a module, check code against a spec or stated expectations, plan the remediation of known findings, debug a failure, investigate an error, or fix a reported defect — in any repo, any language. Reviews one file at a time, assembles repo context before judging, and adversarially verifies every finding before it ships. Never review or debug ad hoc: load this skill first and follow it to the letter.
---

# Colibri Review — a context-aware code review & debug protocol

Lineage: a one-file-per-review console proved the method — one file per unit, severity-ranked
findings with exact line numbers, and sha-keyed caching so unchanged files are never re-reviewed.
In practice a capable model with full repo context matches or beats a paid blind single-file
reviewer, so the blind external call is demoted to an optional second opinion. What replaces it is
this: the same discipline, PLUS everything a blind single-file reviewer can never have — repo
context, project records, and a verification pass. v0.2.0 imports the console's two newer review
types — **Spec Conformance** (code vs the maintainer's stated expectations) and **Remediation
Plan** (plans only, never executes) — plus the commit-gate discipline learned running them in
production.

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
- **Tests are units, not filler:** `tests/`, `test_*`, `*_test.*`, `*.test.*`, harness probes and
  fixtures are review units in their own right — "core-first" is an ORDER, never an exclusion, and
  errors live in tests too. A test unit's contract source is the code it claims to test: pull that
  symbol's source into the context pack and audit the assertion against it. Hunt the test-specific
  classes: assertions that cannot fail (tautologies, a value compared to itself, `assert True`,
  exceptions swallowed before the assert); a stale or wrong target (regex/path-extracted source, a
  stub or fixture shadowing the real symbol, a mock that mocks away the behavior under test);
  runners that report PASS on exception or exit 0 on failure; silent skips masquerading as passes;
  order or shared-state coupling; fixture and environment leaks (temp dirs, env vars, monkeypatches
  never restored); hard-coded machine paths; non-deterministic inputs without a seed.
- **Every code extension counts:** ES-module and typed JavaScript (`.mjs .cjs .mts .cts`) stand on
  the same footing as `.js`/`.ts`; a scan that skips them is incomplete.
- **Freshness:** read the CURRENT on-disk file at dispatch time — never a snapshot, never memory of
  an earlier read. Record `sha256` of the exact bytes reviewed.
- **Cache check — a prior review is CONTEXT, never a skip (all five modes):** if a prior
  review for this file+mode at the same sha exists (see the review store in Phase 4), do
  NOT re-review from scratch and do NOT report-and-walk-away: load the prior review(s) as
  CONTEXT and hunt ONLY what they do not already contain — new defects (bug), new
  improvements (quality), new add-ons (feature), new divergences (spec), new
  plan-relevant defects (plan). A pass that restates recorded findings has failed the
  hunt; every pass must surface new material or HONESTLY record that it found none
  (`new: 0`). Record later passes as lineage (a `pass2`/`passN` sub-entry beside the
  row's original `output`, each carrying `model`, `reviewed_at`, `output`, and `new` —
  the count of new findings), never by overwriting the prior artifact's pointer — the
  prior review IS the context the next pass needs, and the committed record must keep
  naming it.
- **THE THREE-MODEL LOCK:** bug / quality / spec / plan can LOCK (feature mode is
  EXEMPT — features are infinite; it hunts forever and never locks). When THREE DIFFERENT
  model types — distinct model families (e.g. the in-session model and two external
  reviewers; two versions of one family count as ONE type) — have each run an additional
  context-loaded pass at the SAME sha and NONE surfaced new material, the file is LOCKED
  for that mode at that sha: no further scans of that mode until the file's bytes change —
  not a force flag, not a fourth model. Prefer dispatching a pass to a model type that has
  not already recorded an empty pass at this sha (a repeat of an emptied type cannot
  advance the lock). A pass that DOES surface new material RESETS the exhaustion count —
  the context grew, so three fresh empty passes by three distinct types are needed again.
  A changed sha dissolves the lock and the stale-file DELTA flow below takes over.
- **Lock bookkeeping:** on the third empty type, write `locked: {"sha": "<sha>",
  "models": ["<type>", "<type>", "<type>"], "at": "YYYY-MM-DD HH:MM"}` beside the mode's
  `output` (same sub-object spot as the pass lineage), atomically with the manifest
  write. A cache hit on a locked row REFUSES the scan and answers with the lock card:
  which three model types tried, when the row locked, and where the last full review
  lives — the file's bytes changing is the only key.
- **Stale-file DELTA (file changed since its last review):** load the prior review and review
  AGAINST it — report ONLY findings that are new or changed, and close the loop on the old ones
  under a `## Fixed since last review` heading (fixed, still-open, or verified-stale). Never
  restate an unchanged finding as if it were new; convergence rounds must get cheaper each
  pass, not re-litigate the last one.
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

**spec — Spec Conformance** — persona: conformance reviewer judging the file against the
maintainer's AUTHORITATIVE feature expectations; the contract travels in the review itself. Report
ONLY divergences between the code and the stated expectations. Quote the violated clause for every
finding. Never critique the expectations themselves, and never report unrelated generic bugs (bug
mode owns those). Check the quiet clauses hardest — disabled/greyed states, error paths, sentinels,
cost disclosure before spend, side effects, wrap/boundary behavior, "changes nothing else"
guarantees. A clause the code satisfies gets silence. Output:
```
## Verdict
## Divergences        (worst first: quoted Expectation · Trigger · actual Behavior · Fix)
## UNJUDGEABLE HERE   (one line per clause whose behavior lives outside this file, naming where it likely lives)
```
- **No contract, no spec review.** Without expectations the correct output is a request for them,
  not a guess. If asked to establish the spec: author a DRAFT registry (plain contract text, or
  JSON rows — `id`, `label`, `contract` groups such as expected / error_paths / side_effects /
  disabled_state / cost) marked PROVISIONAL for the maintainer's ruling — never judge against a
  contract you silently invented.
- **Clause craft:** one observable behavior per clause; state trigger → observable outcome (output
  text, exit code, file bytes, UI state — if you can't name the observable, it's an intention, not
  a spec); write the quiet clauses deliberately; spec the outcome, not the mechanism (mechanisms
  refactor, contracts persist); scope each registry to one surface and dispatch per-file packs;
  when behavior deliberately changes, update the stale clause in the SAME commit as the change — a
  stale "changes nothing else" clause produces false CONFIRMED divergences.

**plan — Remediation Plan** — persona: senior staff engineer who PLANS ONLY and never executes;
someone else carries the plan out later under strict TDD. Scope: the few most load-bearing real
defects — or, when a prior review is supplied, EXACTLY its still-open findings (no re-litigating, no
expanding, no dropping). Every item carries: Objective · Root cause (line/symbol) · Fix design
(smallest change, the exact edit sketched) · **Test first** (the failing test to write BEFORE the
fix) · Steps · Verification (commands + expected outcomes) · Risk & rollback. End with
`## Execution order & batching` in commit-sized tranches. House law: the plan is archived and
executed in a SEPARATE tranche — a plan is never treated as a fix, and no fix is ever claimed from
having written one.

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
Spec findings are candidates, not verdicts — same adversarial pass, cross-checked against the
remediation log — and an `UNJUDGEABLE HERE` row (the clause's behavior lives in another file) is a
CORRECT answer that routes the clause to its owner, not a failure to judge.

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
- Update `.colibri_reviews/_manifest.json` in the EXACT canonical row shape — both consumers
  (colibri store.py and repo-memory's indexer) iterate `entry["modes"]` and anything else is
  SILENTLY INVISIBLE: `"<ABSOLUTE file path>": {"rel": "<repo-relative path>", "modes":
  {"<mode>": {"sha": "<full sha256>", "output": ".colibri_reviews/<review file>",
  "reviewed_at": "YYYY-MM-DD HH:MM", "cost": <number>}}}`. Pinned 2026-09-10, after four
  formats had grown in the wild: `reviewed_at` is that minute-resolution local string (store.py's
  own format) — never ISO/microseconds, never a bare date; `cost` is a number, 0 for an
  in-session review, never null; `output` is repo-relative; `tokens_in`/`tokens_out` only when
  known. Never mode keys at the entry's top level, never a relative-path key, never a second
  entry for a file that already has one (fold into its `modes`). A manifest that is not already
  in this shape (a `files` wrapper, 8-hex shas, relative-keyed or wrapperless rows) is migrated
  WHOLE before any row is added — `python -m repo_memory.colibri --repo <root> --migrate`
  rewrites it in place — because a legacy file has nothing canonical to fold into and a row
  appended beside it fragments the record. This is the
  sha-keyed cache Phase 0 checks. Pass lineage (`pass2..passN: {"model", "reviewed_at",
  "output", "new": <count>}`) and the lock marker (`locked: {"sha", "models", "at"}`) live
  BESIDE `output` INSIDE the mode object — never at the entry top level, never replacing
  the original `sha`/`output` (the pointer the lineage extends). Write it ATOMICALLY
  (tmp → os.replace): a corrupted manifest silently resets the whole project's review
  cache and every file re-reviews as "new".
- Multi-file jobs end with ONE synthesis section (cross-file findings, ranked) after all per-file
  units — never instead of them.
- Repo work → commit per your project's convention (e.g. `review(scope):` or `fix(scope):`), with
  the remediation-log entry in the SAME commit as the fix.
- If the repo's commits run through a mandatory adversarial review gate (armed `.githooks/`), the
  closing commit goes through it — the gate's findings are review to address, never an obstacle to
  route around (`--no-verify` and plumbing commits are not options).

## External second opinions (demoted, optional)
A paid external reviewer (another model / API) is permitted ONLY as a second opinion after the
in-session review exists, sending the CURRENT on-disk bytes, and disclosing the cost BEFORE the
call. Its findings enter the report only after passing Phase 3 verification. It is never the
primary reviewer. (The colibri console and the grok-review / hy4-review headless CLIs speak all
five modes, including spec with `--spec` and plan with `--findings`.)

## Non-negotiables recap
One file at a time · context pack first · code-intelligence tooling over ad-hoc text search ·
tests and every code extension (`.mjs` included) are units · current bytes + sha recorded · a prior review is CONTEXT, never a skip · three empty model
types = LOCKED until the bytes change (feature never locks) · project records consulted
before and updated after · five modes — bug / quality /
feature / spec / plan · every finding CONFIRMED or labeled PLAUSIBLE · spec =
contract in, divergences only, unjudgeable named, never a self-invented contract · plan =
test-first and never executed by its author · debug = reproduce → hypothesize → verify → log ·
commit at close, through any armed gate.
