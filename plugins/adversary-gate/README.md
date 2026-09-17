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

- **The hooks exec code from this plugin's install path.** `install_gate.py` pins
  your repo's `core.hooksPath` to THIS plugin's `tools/hooks/` dispatchers (an
  absolute path, so worktrees are armed too) and writes `.githooks/` shims whose
  `GATE=` line points at THIS plugin's `tools/adversary_gate.py` (substituted at
  install time; those travel with the repo for CI and other machines). You are
  trusting these scripts with every commit; read them — they are short, stdlib-only
  Python and POSIX sh. Claude Code keeps plugins in a versioned cache directory, so
  after a plugin UPDATE re-run the installer in every armed repo (`--verify-only`
  reports a dangling pin).
- **A fresh clone is UNARMED.** Git cannot ship config; every clone must run the
  installer (or `git config core.hooksPath .githooks`) once. The push guard and CI
  audit exist precisely because client-side hooks are advisory.
- **The reviewer costs money — yours.** Reviews run on OpenRouter with YOUR
  `OPENROUTER_API_KEY` (the shipped default chain is GLM-5.3-Flash via OpenRouter,
  then DeepSeek-V4-Flash pinned to two named OpenRouter endpoints, then xAI Grok-4.6
  on your `XAI_API_KEY` — the exact ids are the `DEFAULT_CHAIN` line in
  `tools/adversary_gate.py`; override with `--model` or `ADVERSARY_MODEL`). A chain
  entry `model@tag1+tag2` pins the OpenRouter providers that may serve it, in that
  order, fallbacks off; every review header records the provider that served it.
  No key, no clearances, no code commits: the gate fails closed by design.
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

# 3. (optional) give the reviewer context and obtain the clearance up front - the commit
#    below requests the review by itself, but with NO context
python <plugin-root>/tools/adversary_gate.py run --context "arming commit"

# 4. commit - EXPECT the gate to speak: "ADVERSARY GATE: requesting automatic independent
#    review of staged changes." (or a re-check of the shas after step 3), then CLEAR -> it
#    lands and is notarized, or BLOCK -> refused with findings. A code commit that lands
#    SILENTLY means the hook did not run: python <plugin-root>/tools/install_gate.py <repo> --verify-only
git commit -m "chore(gate): arm the adversarial commit gate"

# 5. verify the durable evidence
git notes --ref refs/notes/adversary show HEAD
python <repo>/.githooks/adversary_audit.py --repo <repo>
```

Daily loop: finish ALL edits → stage → `git commit` (the hook requests the review
itself; on CLEAR the commit lands and is notarized) → on BLOCK fix, or factually rebut
with `adversary_gate.py run --context "..."` and commit again (the reviewer re-verifies
rebuttals against the bytes; the automatic review carries no context, so `run --context`
FIRST whenever the reviewer needs intent or provenance). Pushes audit themselves and carry the notes
ref automatically. Full runbook including CI, branch protection, merges (do them
locally — a GitHub server-side merge commit can never carry a note) and a
troubleshooting chapter where every entry actually happened:
`docs/GATE_ADOPTION_PLAYBOOK.md` in the
[colibri-code-review repo](https://github.com/Nexusmill/colibri-code-review).

## Selftests (no network; the external model is stubbed)

```
python <plugin-root>/tools/gate_selftest.py      # 129 checks - gate, notary, push guard, secret floor, removed-symbol refusal, the pinned chain
python <plugin-root>/tools/install_selftest.py   # 73 checks - installer claims incl. relocation
python <plugin-root>/tools/audit_selftest.py     # 50 checks - bypass/forgery/override detection
python <plugin-root>/tools/guard_selftest.py     # 231 checks - the harness deny-guard matrix
python <plugin-root>/tools/docscan_selftest.py   # 14 checks - the local docs reviewer (needs the model)
```

## The docs lane (optional local model)

Documentation is never sent to the external reviewer. Its added lines pass the local
pattern floor at commit time and, when a local model is present, `docscan.py` — an
on-machine semantic scan for prose secrets the floor cannot see ("the wifi password
is ..."). Without a model the gate says so on every docs commit (`docs SEMANTIC review
SKIPPED`) and `gate_selftest.py` reports the gap; nothing is blocked. To enable it:
llama.cpp's `llama-cli` on PATH (or `NEXUSMILL_LLAMA_CLI=<path>`) and the GGUF at
`~/.nexusmill/docscan/Qwen_Qwen3-4B-Instruct-2507-Q4_K_M.gguf` (or
`NEXUSMILL_DOCSCAN_MODEL=<path>` plus `NEXUSMILL_DOCSCAN_MODEL_SHA` to pin it);
`NEXUSMILL_DOCSCAN_NGL=0` for CPU-only. Secret-shaped hits WARN at commit and are
scrubbed from the review payload; the PUSH guard refuses an outgoing commit that
carries a secret literal or a docs-model block. A docs-model BLOCK stands only when
its REASON quotes a value: a variable name, a placeholder, a describing verb, a
vendor/model slug or a one-character literal withdraws it, loudly, on stderr.

## The removed-symbol refusal (deterministic, before any model call)

A staged `.py` that removes a module-level `def`/`class` while a tracked, unstaged `.py`
still references the name is refused with the callers listed - the external reviewer
never sees unstaged files, so only arithmetic over the index can. Exactly two things
shadow a name: the bystander's own module-level definition, and a `from X import name`
whose X is a tracked, unstaged root-level module, the only path with that suffix in the
tree, whose index blob defines the name and binds it nowhere else in module scope (a
module-level star import disqualifies every def). Everything unprovable refuses - a bare use, a
plain `import X`, an import from the definer, a staged/deleted/untracked source, a
duplicate module name, a re-exporter, or a module the resolver cannot find at all.

## Provenance

This plugin is a versioned snapshot of the canonical suite in the Nexusmill Tools
repo at commit `c15e8ba` (2026-09-16). The canonical source of truth remains that
repo; the snapshot is updated deliberately, with the same adversarial review this
tool enforces — every commit of this marketplace passes its own gate.

MIT licensed. The gate's own birth reviews caught 16+ real findings and two false
rebuttals from the agent that built it; the push guard's first live run caught a
range bug the same hour it shipped. It works because it assumes its authors are
wrong — you included.
