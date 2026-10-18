# AGENTS.md — colibri-marketplace state file

> STATE FILE (G5): decisions land here the moment they happen. The global-memory stub at the
> bottom points at the single source of truth (Nexusmill docs/GLOBAL_MEMORY.md) - Read it
> before any mutating work (G-MEM gate). The rules canon (G1-G44) arrives via the global
> ~/.zcode/AGENTS.md injection and governs every task.

## What this repo is
The plugin MARKETPLACE (ZCode + Claude Code) that ships:
- `plugins/colibri-review/` — the colibri-review skill/plugin (THE review + debug modality, G37)
- `plugins/adversary-gate/` — the adversarial commit gate tooling (G39)

## Release discipline (the one hard invariant)
A skill/plugin release rotates THREE copies TOGETHER — the canonical source
(colibri-code-review repo for the skill / Tools repo for the gate), THIS marketplace copy,
and the installed plugin cache (`~/.zcode/cli/plugins/cache/...`). Never let them drift;
a ladder-pin change (G37/G39) applies to canonical copy + marketplace release + installed
plugin in the same owner order.

## Commit discipline
Commits are plain git here and EVERY commit fires the adversarial config-hook gate (G39) —
external review CLEAR keyed to staged blob sha256s. Never `--no-verify`; stage EXPLICIT
paths only (never `git add -A`). On a fresh clone (other machines) arm the gate via
`python plugins/adversary-gate/tools/install_gate.py <repo>`.

## ZCode twin (armed 2026-10-18)
`.zcode/config.json` mounts five hooks (SessionStart grounding / PreToolUse G6 jcm guard /
PreToolUse G42+G43 repo guards / PostToolUse jcm mark / Stop gate); scripts live in
`zcode/`; regression suite `python tests/test_zcode_twin.py -v` (28 tests; run from the
repo root). Health: `python zcode/session_health.py
assess` (writes ~/.zcode/health/colibri_marketplace_ledger.json - the G42 fail-arm key).
Store: E:/repo-memory/colibri_marketplace (colibri_marketplace-memory MCP via the
machine-wide repo-memory plugin). jCodemunch repo id: Nexusmill/colibri-marketplace.

## Session notes
- 2026-10-18: ZCode twin armed (zcode/ six scripts, .zcode/config.json 5 mounts,
  tests/test_zcode_twin.py, this file + stub, .mcp.json/.repo-memory.json pair);
  jcm index refreshed; verified (assess PASS, grounding ASCII-JSON contract, unittest
  suite green). Gate census confirmed ARMED (config-hook era, machine-wide).

# Global memory (thin stub - single source of truth lives outside this repo)
<!-- STUBIFIED: managed by Tools/arm-repo/arm_repo.py - edit the imported file, not this stub -->

@C:\Users\User\source\repos\Nexusmill\docs\GLOBAL_MEMORY.md

<!-- The inherited global memory above is the owner's cross-repo context
     (machine, business hard rules, protocols). If your harness did not
     inline it, READ that file now - the ZCode skill gate (G-MEM) will deny
     the first mutating work in this repo until the Read is on record. -->

- 2026-10-18: colibri-review 0.7.1 released - the RSI enjoinder sync (canonical Phase-1 pack
  queries the RSI prevention ruleset; findings may cite RSI-nnnn; rules sharpen, never gate)
  plus posture-step parity. BOTH SKILL.md copies rotated to canonical bytes - the 0.7.0
  release had updated only the root copy, leaving skills/ at 0.4.1-era bytes (drift
  repaired); marketplace.json colibri-review re-aligned 0.4.1 -> 0.7.1; installed cache
  0.7.1 rotated. OWNER NOTE: the plugin now ships two SKILL.md copies (root + skills/)
  - consider collapsing to skills/ only in a future release.
