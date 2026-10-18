---
name: colibri-review
description: MANDATORY protocol (Nexusmill hard rule G37) for ALL code review and debugging. Use whenever asked to review code, audit a file, hunt bugs, check quality, propose features for a module, debug a failure, investigate an error, or fix a reported defect — in any repo, any language. Descended from the Colibri review console; runs in-session, one file at a time, context-aware. Never review or debug ad hoc: load this skill first and follow it to the letter.
---

# Colibri Review — the in-session code review & debug protocol

Lineage: the Colibri review console (junk/colibri_src) proved the method — one file per
review, severity-ranked findings with exact lines, sha-keyed caching so unchanged files
are never re-reviewed. Benchmarks (2026-07-22, Damien) showed the in-session model equals
or beats the paid external reviewers (Kimi K3), so the paid blind-file call is retired as
the primary. What replaces it is this: the same discipline, PLUS everything a blind
single-file reviewer can never have — repo context, manifests, and a verification pass.

**The three laws** (violating any one voids the review):
1. **One file per review unit.** Depth beats breadth. A multi-file task is a sequence of
   single-file reviews plus one cross-file synthesis at the end — never one shallow pass.
2. **Context before code.** Assemble the context pack (Phase 1) before forming ANY opinion.
3. **No finding ships unverified.** Every finding survives the adversarial pass (Phase 3)
   or it is deleted. History demands this: K3 once reported live code "abandoned"; GLM
   once misread deliberate unregistration as a bug. Confidence is not evidence (G2).

## Phase 0 — Scope & freshness gate
- Identify the unit(s): explicit file(s), or for a folder/repo rank candidates the Colibri
  way — core files first (shallow paths, `__init__/app/main/core/cli/server`), deny-list
  vendored/scratch trees (`.git venv node_modules build dist junk media .secrets legal
  __pycache__ *.min.* site-packages`), skip files > 2 MB.
- **Tests are units, not filler (owner ruling 2026-09-19):** `tests/`, `test_*`, `*_test.*`,
  `*.test.*`, harness probes and fixtures are review units in their own right — "core files
  first" is an ORDER, never an exclusion, and errors live in tests too (found across repos).
  A test unit's contract source is the code it claims to test: pull that symbol's source into
  the context pack and audit the assertion against it. Hunt the test-specific classes:
  assertions that cannot fail (tautologies, a value compared to itself, `assert True`,
  exceptions swallowed before the assert); a stale or wrong target (regex/path-extracted
  source, a stub or fixture shadowing the real symbol, a mock that mocks away the behavior
  under test); runners that report PASS on exception or exit 0 on failure; silent skips
  masquerading as passes; order or shared-state coupling; fixture and environment leaks
  (temp dirs, env vars, monkeypatches never restored); hard-coded machine paths;
  non-deterministic inputs without a seed.
- **Every code extension counts (same ruling):** ES-module and typed JavaScript (`.mjs .cjs
  .mts .cts`) stand on the same footing as `.js`/`.ts`; a scan that skips them is incomplete.
  (The console scanner's `CODE_EXT` in colibri-code-review `scanner.py` still lacks them —
  owed there; a hand-ranked scan includes them regardless.)
- **G36 freshness:** read the CURRENT on-disk file at dispatch time — never a snapshot,
  never memory of an earlier read. Record `sha256` of the exact bytes reviewed.
- **Cache check — a prior review is CONTEXT, never a skip (owner rulings
  2026-09-14 + 2026-09-15, ALL modes):** if `.colibri_reviews/_manifest.json`
  shows this file+mode at the same sha, do NOT re-review from scratch and do
  NOT report-and-walk-away: load the prior review(s) as CONTEXT and hunt ONLY
  what they do not already contain — new defects (bug), new improvements
  (quality), new add-ons (feature), new divergences (spec), new
  plan-relevant defects (plan). A pass that restates recorded findings has
  failed the hunt; every pass must surface new material or HONESTLY record
  that it found none (`new: 0`). Record later passes as lineage (a
  `pass2`/`passN` sub-entry beside the row's original `output`, each carrying
  `model`, `reviewed_at`, `output`, and `new` — the count of new findings),
  never by overwriting the prior artifact's pointer — the prior review IS the
  context the next pass needs, and the committed record must keep naming it.
- **THE THREE-MODEL LOCK (owner ruling 2026-09-15):** bug / quality / spec /
  plan can LOCK (feature mode is EXEMPT — features are infinite, owner
  2026-09-14; it hunts forever and never locks). When THREE DIFFERENT model
  types — distinct model families (the in-session model [the standing reviewer],
  deepseek-v4.1-flash [gate tier 1 AND tier 2 at effort high, optional external;
  ladder order 2026-10-12], qwen3.8-omni-flash [gate tier-2 fallback, optional
  external] are the three houses — hy4/kimi are retired; two versions of one
  family count as ONE
  type) — have each run an additional context-loaded pass at the SAME sha
  and NONE surfaced new material, the file is LOCKED for that mode at that
  sha: no further scans of that mode until the file's bytes change — not a
  force flag, not a fourth model. Prefer dispatching a pass to a model type
  that has not already recorded an empty pass at this sha (a repeat of an
  emptied type cannot advance the lock). A pass that DOES surface new
  material RESETS the exhaustion count — the context grew, so three fresh
  empty passes by three distinct types are needed again. A changed sha
  dissolves the lock and the stale-file DELTA flow below takes over.
- **Lock bookkeeping:** on the third empty type, write `locked:
  {"sha": "<sha>", "models": ["<type>", "<type>", "<type>"], "at":
  "YYYY-MM-DD HH:MM"}` beside the mode's `output` (same sub-object spot as
  the pass lineage), atomically with the manifest write. A cache hit on a
  locked row REFUSES the scan and answers with the lock card: which three
  model types tried, when the row locked, and where the last full review
  lives — the file's bytes changing is the only key.
- **Stale-file DELTA (file changed since its last review):** load the prior review and
  review AGAINST it — report ONLY findings that are new or changed, and close the loop on
  the old ones under a `## Fixed since last review` heading (fixed, still-open, or
  verified-stale). Never restate an unchanged finding as if it were new; convergence
  rounds must get cheaper each pass, not re-litigate the last one. (Folded 2026-07-23
  from the console's delta mode.)
- **G35 remediation check:** load `docs/remediation_manifest.json` (or the repo's
  equivalent). Findings already closed there are excluded up front; a finding that turns
  out to target already-fixed code is recorded `verified-stale` with evidence, never
  "re-fixed".

## Phase 1 — Context pack (the edge; blind Colibri could not do this)
Assemble BEFORE reading the file body, and summarize it in the review header:
- **Symbol map:** jCodemunch `get_file_outline` of the target; `find_importers` /
  `find_references` for its public symbols — who calls into this file, and what do the
  call sites actually pass? (`search_symbols`/`get_symbol_source` on demand.) jCodemunch is
  MANDATORY for ALL code search — grep/Read-scanning is token-expensive and jCodemunch replaces
  it, PERIOD. If the repo isn't loadable, `index_folder` it FIRST, then query; resolve the id
  with `resolve_repo`/`list_repos` (this repo is `Nexusmill/nexusmill`, NOT `local/Nexusmill`).
  Never fall back to grep to locate code.
- **Contract sources:** docstrings/comments in the file are CLAIMS to audit, not truth.
  Pull the manifests (features/deferred/remediation) entries touching this file; pull the
  relevant doctrine constraints (for Nexusmill: sentinel containment, secrets handling,
  GPL/commercial hard rules, twin-build byte-parity G23, EEVEE-only, mount-truncation G8).
- **Recent history:** last AGENT_STATE / session-log entries and recent commits touching
  the file — what changed lately is where bugs live.
- **Applicable RSI rules (enjoined 2026-10-18):** query the machine-curated prevention
  ruleset for this file's language and load it into the pack:
  `python C:\Users\User\source\repos\Nexusmill\tools\rsi\cli.py rules --lang <py|ts|...> --file <repo-relative path>`
  (returns ACTIVE rules only — budget-capped, externally cleared; an empty list is a valid
  answer and costs one line). Audit the file AGAINST each returned rule: violating an active
  rule is a defect-level finding and SHOULD cite the rule id (`RSI-nnnn`) in its title so
  recurrence is trackable. Rules sit BELOW the G-canon; on any conflict the canon wins.
  Rules never gate the review — they sharpen it.
- Cap the pack at what fits comfortably; prefer call-site EVIDENCE over more breadth.
- **Producing-caller evidence (owner order 2026-10-10, local-gate experiment #10):** for every
  candidate finding, the pack carries WHO CAN PRODUCE the trigger — `find_references` on the
  function that would pass the breaking input. A trigger no repo caller can produce (only an
  external process, tool, or human does) makes the observation a hardening note, never a
  defect-level finding.

## Phase 2 — The review pass (per mode; run `bug` unless told otherwise)
Read the file end to end with line numbers. Then produce the mode's exact contract:

**Prompt posture from the store (owner order 2026-10-13):** before the pass,
resolve the standing posture from the prompt store:
`python C:\Users\User\source\repos\Tools\prompt-layer\prompt_layer.py get colibri/local-reviewer --source colibri-skill`
(line 1 = meta JSON, the remaining lines = the posture text; exit 1 = unresolved).
Fail-open: unresolved, THIS document is the posture; resolved, its
`name@version(origin)` is stamped on the artifact header (Phase 4) and the fetch
lands in the layer's usage ledger. The per-mode EXTERNAL-pass prompts
(`colibri/bug`, `colibri/feature` = the SUGGEST pass - a "feature run" ALWAYS
means suggested add-ons, owner standing order 2026-10-13 - `colibri/expectation-audit`
= the two-phase conformance audit of a landed change, `colibri/spec`,
`colibri/quality`, `colibri/plan`, `colibri/security`, `colibri/billing`) are
consumed by the external CLIs (hy4-review and grok-review resolve `colibri/<mode>`
fail-open to their builtins) - the local run keeps this document's Phase-2 mode
contracts as its own posture.

**bug** — persona: rigorous senior staff engineer + appsec reviewer. Hunt REAL defects
only, no style padding: logic/correctness, off-by-one, None/undefined, unhandled error
paths, boundaries, races/concurrency, resource leaks, missing validation, injection /
traversal / SSRF / deserialization, auth & secret handling, overflow, wrong API usage,
silent failures. Output:
```
## Verdict            (1-2 sentences: shippable? single biggest risk?)
## Bugs & vulnerabilities   (worst first)
**[CRITICAL|HIGH|MEDIUM|LOW] title** - `line N`
- What / Trigger / Impact / Fix    (exact defect, exact condition, what breaks, concrete change)
## Missing safeguards (bullets)
```

**quality** — persona: principal engineer, long-term code health; never invent bugs.
Output: `## Health score` X/10 + one line; `## Improvements` ([HIGH|MEDIUM|LOW], line/
symbol, Issue → Better with short before/after); `## Quick wins`; `## What's done well`.

**feature** — persona: pragmatic product-minded staff engineer, grounded in what the code
does. Output: `## What this module does`; `## Suggested add-ons` (Value High/Med/Low ·
Effort S/M/L, What/Why/How with hook points); `## Nice-to-haves`.

**spec** — persona: rigorous conformance reviewer against the maintainer's feature
expectations. PREREQUISITE: an expectations document — the spec-harness registry rows
(`tests/harness/specs/<product>/<surface>.json`, the per-control contracts) or hand-written
section contracts describing expected behavior/outcomes in fine detail; NO spec, NO review.
Report ONLY divergences between the code and the stated expectations — quote the violated
clause per finding (severity, line, trigger, actual-vs-expected, fix); press the quiet
clauses hardest (disabled states, error paths, sentinels, cost disclosure, side effects,
boundaries); clauses unjudgeable from the unit go under `## UNJUDGEABLE HERE` (say where
they live) — feed those rows to that file next. Never critique the expectations, never
report unrelated bugs (bug mode owns those). Confirmed divergences are the in-session twin
of the harness's DRIFT verdict; the OPTIONAL paid external twin is the hy4-review CLI
with the gate-ladder `--model` pin (tier 1 quick, tier 2 escalation; grok-review is
OFF-ladder since 2026-10-09 and its passes do not count toward the lock)
`--mode spec` (same registry input). Only the as-a-user rig lane catches what a user SEES.

**plan** — persona: senior staff engineer writing a REMEDIATION PLAN, never executing.
Input: the unit + (preferred) the GATED findings from a prior review; without findings it
identifies the load-bearing defects itself first. Per item: Objective, Root cause
(line/symbol), Fix design (smallest edit, sketched), TEST FIRST (failing test + asserts),
ordered Steps, Verification (commands + expected outcomes), Risk & rollback; ends with
commit-sized tranche batching. The plan lands in the same review area (`.colibri_reviews/`
/ the console archive) named `__plan__`; EXECUTION is always a separate tranche under TDD
with same-commit manifest rows (G35). Optional external twin: the hy4-review CLI
with the gate-ladder `--model` pin
`--mode plan [--findings PATH]`; the console's Remediation Plan mode.

**Context-aware checks (mandatory additions in every mode — the reason this beats K3):**
- Cross-file contract breaks: caller passes X, this file assumes Y (cite BOTH sites).
- Duplication of logic that already exists elsewhere in the repo (name the twin).
- Violations of recorded decisions/invariants (manifests, doctrine, design bible).
- Staleness: does the docstring/comment still match the behavior?
- For fixes proposed: would they break any call site found in Phase 1?

## Phase 3 — Adversarial verification (mandatory, separate pass)
For EVERY draft finding: re-open the cited lines fresh and try to REFUTE it. Trace the
trigger condition through the actual code path, checking guards upstream and call-site
reality from Phase 1. Then mark it:
- **CONFIRMED** — the trigger path traced end to end; keep it.
- **PLAUSIBLE** — could not fully trace (needs runtime/hardware); keep ONLY with an
  explicit "unverified because ..." note. Never present as confirmed.
- Refuted → DELETE (silently; a deleted wrong finding is a success, not a loss).
Static-analysis inputs (pyflakes etc.) are hints, never findings, until traced.

**The finding contract for CONFIRMED (owner order 2026-10-10, from local-gate
experiment #10 — anchored findings measured 0 false positives over 15 clean replay
rounds while every anchored true mutation was confirmed; near-miss file citations
ran 30-50% of model findings):** every CONFIRMED finding carries the anchor quad,
each field checkable against the current bytes —
- **verbatim snippet**: code quoted EXACTLY from the file. A snippet that does not
  appear verbatim in the current bytes means the finding is not anchored: PLAUSIBLE
  at best, or invented — resolve cited paths against the ACTUAL file list before
  citing (near-miss names corrected or the finding is unanchored).
- **concrete trigger input**: the input/state that fires the mechanism. "None" =
  hardening note, not a defect finding.
- **producing caller**: the repo function that produces the trigger at runtime.
- **broken behavior**: the observable outcome (exception, wrong value, wrong side
  effect).
**Execute instead of re-reason (same order):** when the target is pure Python and
the trigger is concrete, materialize old/new versions (`git show` + the diff hunks)
and RUN the trigger in a sandboxed child process — a behavior difference between
old and new at the same input is proof; identical output refutes the claimed
trigger. This settles wrong-value claims in seconds where re-reasoning has
repeatedly failed. The gate's `adversary-gate/finding_adjudicator.py` is the
production form; keep purity/nondeterminism guards around any execution.

## Phase D — Debug modality (when hunting a specific failure, not reviewing)
Same laws + the debug ladder, in order, no skipping:
1. **Reproduce or capture** the failure signal first (error text, log, failing input).
   No fix is proposed for a failure that hasn't been observed or precisely characterized.
2. **Context pack** on the implicated file(s) (Phase 1) — one file at a time.
3. **Hypothesis ledger:** list ranked hypotheses; for each, the observation that would
   confirm/kill it. Check them against SOURCE (and cheap instrumentation) — top-down.
4. **One variable at a time.** Minimal fix at the root cause, never at the symptom.
5. **Verify by re-running the reproducer** (or the closest harness/battery). Evidence
   before "fixed" — G10/verification-before-completion.
6. **G35:** log the fix in the remediation manifest in the SAME commit; consult it first
   so closed findings aren't re-fixed.

## Phase 4 — Persist & close (every review/debug, no exceptions)
- Write the review to `.colibri_reviews/<rel path with separators as __>__<mode>__
  <sha8>.md` with a header: source path · model (in-session id) · sha256 · date ·
  mode · one-line context-pack summary (what was consulted) · prompt
  name@version(origin) when the store posture resolved (fail-open: omit when it
  did not).
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
  appended beside it fragments the record (Blink and Caliper, 2026-09-10). This is the
  sha-keyed cache Phase 0 checks. Pass lineage (`pass2..passN: {"model", "reviewed_at",
  "output", "new": <count>}`) and the lock marker (`locked: {"sha", "models", "at"}`) live
  BESIDE `output` INSIDE the mode object — never at the entry top level, never replacing
  the original `sha`/`output` (the pointer the lineage extends). Write it ATOMICALLY
  (tmp → os.replace): a corrupted manifest silently resets the whole project's review
  cache and every file re-reviews as "new".
- Multi-file jobs end with ONE synthesis section (cross-file findings, ranked) after all
  per-file units — never instead of them.
- Repo work → commit per G4 (`review(scope):` or `fix(scope):` + manifest in same commit).

## The review ladder — local agent reviews; external passes optional (owner order 2026-10-09, superseding the standing ladder of 2026-09-19)

Gate clearance is DIFF clearance for the staged bytes — it is not a file review.
THE colibri reviewer is the LOCAL agent — the in-session model (GLM) running
this skill: it performs every mode's file-by-file review, the verification
pass, and the synthesis. That is the standing protocol; it fires automatically,
with no owner reminder and no paid call.

External passes are OPTIONAL second opinions, never automatic and never
required to close a run (the standing M2/M3 ladder of 2026-09-19 is retired by
this order). When the owner asks for one — or a run's findings make one worth
PROPOSING (say so and disclose the batch cost, G19, before the first call) —
the pass runs on the GATE'S pinned ladder, exactly as etched in G37 (LADDER
ORDER 2026-10-12): tier 1 `deepseek/deepseek-v4.1-flash@baidu/fp8` →
`deepseek/deepseek-v4.1-flash@deepinfra/fp8` at default effort; tier 2 the SAME
flash base AT REASONING EFFORT HIGH → `qwen/qwen3.8-omni-flash` fallback when a
HIGH/CRITICAL deserves a stronger second look — prior review(s) loaded as
context, hunting NEW findings only; hy4-preview and kimi-k2.7-code are RETIRED
from the ladder (owner cost ruling 2026-10-12); a pass
that surfaces nothing records `new: 0` honestly.

Deliberate NON-unification is the point of this order: the LOCAL agent reviews
code; the GATE is ALWAYS EXTERNAL (its paid pinned ladder clears commits; the
local rung stays measurement-only per ruling D2 until the owner rules). Two
different model families therefore see every change — a blind spot one family
has does not pass both sides.

1. **Findings are verified before they count** (Phase 3 against current
   bytes); confirmed defects are remediated and logged in the same session;
   every optional external pass lands as manifest pass lineage and counts
   toward the three-model lock like any other pass.
2. **New test files are first-class review members** — the gate takes them on
   commit (automatic) and the local agent reviews them like any source file;
   a test file is never "just a test" (see Phase 0).

Routing table (owner order 2026-10-09, etched in GLOBAL_RULES G37):
**STANDING** — the in-session model (GLM) reviews every changed file in every
mode; it is THE reviewer, not merely an orchestrator; no paid call is owed.
**OPTIONAL EXTERNAL** — the gate's pinned ladder above, via the hy4-review
headless CLI with explicit `--model` pins (it accepts any OpenRouter id);
substitute DOWN THE CHAIN exactly like the gate's fallback semantics — never
the same rung twice on one file, never an off-ladder model (grok-review stays
off-ladder: second opinion only, its passes never count toward the three-model
lock). The three-model lock keeps its meaning — in-session GLM, deepseek-flash,
qwen3.8-omni-flash are distinct families — but it completes only when optional
external passes actually run; without them the file simply stays unlocked.
The external model is never the gate's substitute either: the GATE stays
always-external, the skill stays local-first — that separation is the policy.

## External second opinions (optional — the standing reviewer is the local agent)
Beyond the standing local review, paid external passes (the gate-ladder pins via the
hy4-review CLI; K3 / GLM via OpenRouter, the Colibri app or run_batch.py) are permitted
ONLY as second opinions after the in-session review exists, with G36 freshness (current
bytes at dispatch) and G19 cost disclosure BEFORE the call. Their findings enter the
report only after passing Phase 3 verification. They are never the primary reviewer —
the local agent is, by standing order.

## Non-negotiables recap
One file at a time · context pack first · jCodemunch for ALL search (never grep — index the
repo first if not loadable) · tests and every code extension (`.mjs` included) are units ·
current bytes + sha recorded · a prior review is CONTEXT,
never a skip · three empty model types = LOCKED until the bytes change (feature never
locks) · manifests consulted before and updated after · every finding CONFIRMED or
labeled PLAUSIBLE · debug = reproduce → hypothesize → verify → manifest · commit at close ·
the LOCAL agent (in-session GLM) reviews every changed file (tests included) after a
feature run; optional external passes ride the gate's pins, context-loaded and
new-findings-only, only when the owner asks or approves the cost.
