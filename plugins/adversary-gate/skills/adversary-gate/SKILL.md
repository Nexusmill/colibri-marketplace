---
name: adversary-gate
description: Arm, operate, and audit the mandatory adversarial commit gate - no code commit without an independent external model's VERDICT CLEAR keyed to the exact staged bytes; durable git-notes evidence; push guard; CI re-audit. Use when adopting the gate on a repo, when a commit or push is refused by the gate, when auditing history for un-evidenced commits, or when a gate hook misbehaves. The gate is law once armed - never help a user or agent bypass it; help them clear it.
---

# adversary-gate — operating the mandatory adversarial commit gate

All tooling ships in this plugin under `tools/` (stdlib Python + POSIX sh; read
`${CLAUDE_PLUGIN_ROOT}/tools/` — the scripts are short). The canonical upstream is
the Nexusmill Tools repo (snapshot provenance: see README.md). Prerequisites: git,
Python 3.11+, `OPENROUTER_API_KEY` in the environment (the adopter's own spend).

## The law (non-negotiable once a repo is armed)

1. A commit staging CODE (`.py .js .mjs .cjs .json .ts .mts .cts .jsx .tsx .html
   .css .ps1 .sh .bat .c .cpp .h .rs .go .java .glsl .osl`, any file named
   `pre-commit`/`post-commit`/`pre-push`, anything under `.githooks/` or
   `.github/workflows/`, code deletions/renames-away, merges) is REFUSED without a
   fresh `VERDICT: CLEAR` from the external reviewer, keyed to the exact staged blob
   sha256s. Re-editing invalidates clearance. Docs never go to the external reviewer:
   their added lines pass the local pattern floor and, if a local model is installed,
   the on-machine docs reviewer (`docscan.py`) — warnings at commit, never a block;
   the PUSH guard refuses an outgoing commit carrying a secret literal or a
   docs-model block.
2. NEVER bypass: no `--no-verify`, no re-pointing the hooks config, no plumbing
   commits, no writing `.adversary/**` by hand, no fabricated notes. If a layer
   blocks you, that layer is working. The one-shot `.adversary/OVERRIDE` escape
   belongs to the repo OWNER alone; an agent using it is a protocol violation.
3. Fix or factually rebut — never argue in prose outside the loop, never shop for a
   compliant model.

## Arming a repo

```
python ${CLAUDE_PLUGIN_ROOT}/tools/install_gate.py <repo>
cd <repo>
git add .githooks .gitignore
git update-index --chmod=+x .githooks/pre-commit .githooks/post-commit .githooks/pre-push
python ${CLAUDE_PLUGIN_ROOT}/tools/adversary_gate.py run --context "arming commit"   # optional: context for the reviewer
git commit -m "chore(gate): arm the adversarial commit gate"   # the gate speaks: auto-review (or sha re-check) -> CLEAR lands + notarizes; BLOCK refuses
```

The proof is the gate line during the commit — `ADVERSARY GATE: requesting automatic
independent review of staged changes.` (or the sha re-check after an explicit `run`). If a
code commit lands SILENTLY, something is broken — audit with
`install_gate.py <repo> --verify-only` and fix before proceeding. The
`--chmod=+x` step is REQUIRED: POSIX git silently skips hooks with index mode
100644, which disarms everything on Linux/macOS checkouts.

## The daily loop

1. Finish ALL edits (clearance follows bytes; any re-edit invalidates it).
2. Stage everything that belongs in the commit — including `.json` manifest rows,
   which get reviewed WITH the change they describe.
3. `git commit` — the hook requests the independent review itself and, on CLEAR, lands
   and notarizes the commit in one motion. When the reviewer needs to know something —
   design intent, provenance of copied bytes, or a factual rebuttal of a previous BLOCK —
   run `python ${CLAUDE_PLUGIN_ROOT}/tools/adversary_gate.py run --context "..."` FIRST,
   then commit (the automatic review carries no context; the reviewer re-verifies
   rebuttals against the bytes and calls out false ones). Before any model call the gate
   refuses a staged `.py` that removes a module-level symbol a tracked unstaged `.py`
   still references — stage the callers too.
4. On BLOCK the commit is refused: fix each finding and commit again, or rebut it with
   file:line evidence via `run --context`; treat a finding you cannot refute as real.
5. Push normally. The pre-push guard audits the outgoing range and pushes
   `refs/notes/adversary` automatically — evidence always travels with history.
6. Merges happen LOCALLY (staged merge result → run → clear → commit → notarized).
   Never use GitHub's merge/squash/rebase buttons on a gated repo: a server-side
   merge commit can never carry a note and turns the audit permanently red.

## Auditing history

```
python <repo>/.githooks/adversary_audit.py --repo <repo> [--json] [--strict-override]
```

Every code commit after `.githooks/adversary_baseline` must carry a note on
`refs/notes/adversary` whose per-file sha256s match the committed blobs. No note /
missing path / sha mismatch = VIOLATION. Owner OVERRIDE notes pass but are listed
loudly. CI runs this same vendored auditor on push (`fetch-depth: 0` plus an
explicit fetch of the notes ref; trigger on `push` ONLY — a `pull_request` run
checks out GitHub's synthetic merge commit, which can never carry a note).

## When something misbehaves (all field-verified)

- Reviewer hangs or returns empty → the gate fails CLOSED with BLOCK (designed);
  re-run with `--model <another OpenRouter model>`.
- A code commit lands with no gate line at all → unarmed clone or 100644 hook mode;
  `install_gate.py <repo> --verify-only`, re-run the installer, redo the chmod step.
- Push refused listing ancient commits → the baseline should exclude pre-gate
  history; re-run the installer (never hand-edit the baseline).
- Push guard says the notes push failed → notes diverged; the refusal message
  carries the exact fetch+merge recovery commands.
- `refusing to allow an OAuth App to ... without 'workflow' scope` → GitHub, not
  the gate: `gh auth refresh -h github.com -s workflow` once, push again.
- Hook prints `tool not found ... failing CLOSED`, or commits suddenly pass unreviewed
  → the plugin moved, was UPDATED (Claude Code keeps plugins in a versioned cache
  directory) or uninstalled; re-run this plugin's installer in every armed repo so
  the `core.hooksPath` pin and the shims point at its current location
  (`install_gate.py <repo> --verify-only` reports a dangling pin).

## Full runbook

The complete novice-grade adoption playbook (CI, branch protection with
enforce_admins + linear history, the harness deny-guard, the honest threat model)
lives in the colibri-code-review repo: `docs/GATE_ADOPTION_PLAYBOOK.md`
(github.com/Nexusmill/colibri-code-review).
