# adversary-gate — the mandatory adversarial commit gate

No commit that stages code lands unless an INDEPENDENT external model has read the
exact staged bytes and issued `VERDICT: CLEAR` — and every landed commit carries a
durable, machine-verifiable record of that clearance which travels with the history
and is re-checked on every push.

Born from a documented failure: authors — AI agents included — confidently defend
invented claims about code they have not actually read. Self-review is structurally
untrustworthy; this gate is structural distrust of exactly that, applied to every
commit.

## The four layers

| Layer | Mechanism | Stops |
|---|---|---|
| 0 (the wall) | `pre-commit` hook → `adversary_gate.py check` | ungated commits |
| 1 (optional) | your commit driver calls `check`/`record` directly | disarmed-clone commits via the driver |
| 2 (optional) | Claude Code PreToolUse deny-guard (`harness_guard.py`) | agent-reachable bypasses AND clearance forgery |
| 3 (the catch-all) | post-commit notarization into git notes (`refs/notes/adversary`) + `pre-push` guard + self-contained auditor | everything, after the fact — it reads immutable output, not process |
| 4 | CI re-audit on push + branch protection | bypass reaching the shared remote |

## Trust model — read this before installing

- **The hooks exec code from this plugin's install path.** `install_gate.py` writes
  hook shims into your repo whose `GATE=` line points at THIS plugin's
  `tools/adversary_gate.py` (substituted at install time). You are trusting these
  scripts with every commit; read them — they are short, stdlib-only Python and
  POSIX sh.
- **A fresh clone is UNARMED.** Git cannot ship config; every clone must run the
  installer (or `git config core.hooksPath .githooks`) once. The push guard and CI
  audit exist precisely because client-side hooks are advisory.
- **The reviewer costs money — yours.** Reviews run on OpenRouter with YOUR
  `OPENROUTER_API_KEY` (the shipped default chain is GLM-5.3-Flash via OpenRouter,
  falling back to xAI Grok-4.6 on your `XAI_API_KEY` — the exact ids are the
  `DEFAULT_MODEL` line in `tools/adversary_gate.py`; override with `--model` or
  `ADVERSARY_MODEL`). No key, no clearances, no code commits: the gate fails
  closed by design.
- **The OVERRIDE escape belongs to the repo OWNER.** A file `.adversary/OVERRIDE`
  lets exactly one commit through, loudly, and is auditable forever (it becomes a
  provenance-carrying OVERRIDE note). An agent using it is a protocol violation
  equivalent to disabling the gate.
- **The honest contract (never oversold):** a human at a shell can always bypass
  client-side enforcement, and that is fine — the layers only need to be airtight
  against agents operating through a harness, plus detection for everything else.
  Layer 3 detects; layer 4 makes bypass fail at the remote. **Detection is the
  guarantee. Prevention is not claimed.** A determined fraudster could forge a note
  with correct sha256s and fabricated verdict text; the embedded reviewer artifact
  makes that checkable (re-run a review against the same bytes), not impossible.

## Quickstart

```
# 1. arm a repo (idempotent; writes hooks, vendored auditor, baseline, notes config)
python <plugin-root>/tools/install_gate.py <path-to-repo>

# 2. stage the arming files, record the exec bit (POSIX git SKIPS 100644 hooks)
cd <repo>
git add .githooks .gitignore
git update-index --chmod=+x .githooks/pre-commit .githooks/post-commit .githooks/pre-push

# 3. attempt the commit - it MUST be refused (that refusal is your end-to-end proof)
git commit -m "chore(gate): arm the adversarial commit gate"

# 4. obtain the clearance, then commit for real
python <plugin-root>/tools/adversary_gate.py run   # default model chain; --model overrides
git commit -m "chore(gate): arm the adversarial commit gate"

# 5. verify the durable evidence
git notes --ref refs/notes/adversary show HEAD
python <repo>/.githooks/adversary_audit.py --repo <repo>
```

Daily loop: finish ALL edits → stage → `adversary_gate.py run` → fix or factually
rebut BLOCK findings (`--context`; the reviewer re-verifies rebuttals against the
bytes) → on CLEAR, commit immediately. Pushes audit themselves and carry the notes
ref automatically. Full runbook including CI, branch protection, merges (do them
locally — a GitHub server-side merge commit can never carry a note) and a
troubleshooting chapter where every entry actually happened:
`docs/GATE_ADOPTION_PLAYBOOK.md` in the
[colibri-code-review repo](https://github.com/Nexusmill/colibri-code-review).

## Selftests (no network; the model is stubbed)

```
python <plugin-root>/tools/gate_selftest.py      # 30 checks - gate, notary, push guard
python <plugin-root>/tools/install_selftest.py   # 38 checks - installer claims incl. relocation
python <plugin-root>/tools/audit_selftest.py     # 15 checks - bypass/forgery/override detection
python <plugin-root>/tools/guard_selftest.py     # 34 checks - the harness deny-guard matrix
```

## Provenance

This plugin is a versioned snapshot of the canonical suite in the Nexusmill Tools
repo at commit `5cd90e7` (2026-09-04). The canonical source of truth remains that
repo; the snapshot is updated deliberately, with the same adversarial review this
tool enforces — every commit of this marketplace passes its own gate.

MIT licensed. The gate's own birth reviews caught 16+ real findings and two false
rebuttals from the agent that built it; the push guard's first live run caught a
range bug the same hour it shipped. It works because it assumes its authors are
wrong — you included.
