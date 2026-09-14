---
name: adversary-gate
description: Arm, operate, and audit the mandatory adversarial commit gate - no code commit without an independent external model's VERDICT CLEAR keyed to the exact staged bytes; durable git-notes evidence; push guard; CI re-audit. Use when adopting the gate on a repo, when a commit or push is refused by the gate, when auditing history for un-evidenced commits, or when a gate hook misbehaves. The gate is law once armed - never help a user or agent bypass it; help them clear it.
---

# adversary-gate — operating the mandatory adversarial commit gate

All tooling ships in this plugin under `tools/` (stdlib Python + POSIX sh; read
`${CLAUDE_PLUGIN_ROOT}/tools/` — the scripts are short). The canonical upstream is
the Nexusmill Tools repo (snapshot provenance: see README.md). Prerequisites: git,
Python 3.11+, `OPENROUTER_API_KEY` in the environment (the adopter's own spend,
~a cent per commit).

## The law (non-negotiable once a repo is armed)

1. A commit staging CODE (`.py .js .json .ts .jsx .tsx .html .css .ps1 .sh .bat .c
   .cpp .h .rs .go .java .glsl .osl`, anything under `.githooks/` or
   `.github/workflows/`, code deletions/renames-away, merges) is REFUSED without a
   fresh `VERDICT: CLEAR` from the external reviewer, keyed to the exact staged blob
   sha256s. Re-editing invalidates clearance. Plain `.md` passes free.
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
git commit -m "chore(gate): arm the adversarial commit gate"   # MUST be refused - that is the proof
python ${CLAUDE_PLUGIN_ROOT}/tools/adversary_gate.py run   # default model chain; --model overrides
git commit -m "chore(gate): arm the adversarial commit gate"   # now passes; post-commit notarizes it
```

If the first commit SUCCEEDS, something is broken — audit with
`install_gate.py <repo> --verify-only` and fix before proceeding. The
`--chmod=+x` step is REQUIRED: POSIX git silently skips hooks with index mode
100644, which disarms everything on Linux/macOS checkouts.

## The daily loop

1. Finish ALL edits (clearance follows bytes; any re-edit invalidates it).
2. Stage everything that belongs in the commit — including `.json` manifest rows,
   which get reviewed WITH the change they describe.
3. `python ${CLAUDE_PLUGIN_ROOT}/tools/adversary_gate.py run`
   (add `--context "..."` for design intent, provenance of copied bytes, or a
   factual rebuttal of a previous BLOCK — the reviewer re-verifies rebuttals
   against the bytes and calls out false ones).
4. On CLEAR: commit immediately. On BLOCK: fix each finding or rebut it with
   file:line evidence; treat a finding you cannot refute as real.
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
- Commit passes when it should be refused → unarmed clone or 100644 hook mode;
  `install_gate.py <repo> --verify-only`, re-run the installer, redo the chmod step.
- Push refused listing ancient commits → the baseline should exclude pre-gate
  history; re-run the installer (never hand-edit the baseline).
- Push guard says the notes push failed → notes diverged; the refusal message
  carries the exact fetch+merge recovery commands.
- `refusing to allow an OAuth App to ... without 'workflow' scope` → GitHub, not
  the gate: `gh auth refresh -h github.com -s workflow` once, push again.
- Hook prints `tool not found ... failing CLOSED` → the plugin moved or was
  uninstalled; re-run this plugin's installer so the shims point at its current
  location (the installer substitutes its own path at install time).

## Full runbook

The complete novice-grade adoption playbook (CI, branch protection with
enforce_admins + linear history, the harness deny-guard, the honest threat model)
lives in the colibri-code-review repo: `docs/GATE_ADOPTION_PLAYBOOK.md`
(github.com/Nexusmill/colibri-code-review).
