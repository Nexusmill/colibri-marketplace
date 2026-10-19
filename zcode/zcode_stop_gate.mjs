#!/usr/bin/env node
/* zcode_stop_gate.mjs - the ZCode Stop-event twin of the Claude skill-gate stop gate.
   Repo-by-repo port of Nexusmill/tools/zcode_stop_gate.mjs (via the Tools twin 65eb0c7;
   owner order 2026-10-18) - verbatim, repo identity comes from the cwd .git walk, which
   resolves to THIS repo in its sessions.
   Closes the one G38 gap the universal-tools plugin mount left open: on Claude, a turn that
   edited source cannot END until verification-before-completion ran (skill_gate.py cmd_stop,
   exit 2 + stderr); on ZCode only G-COMMIT blocked the commit itself. Wired in the repo's
   .zcode/config.json under hooks.events.Stop (no matcher - Stop matches the response preview).
   Contract: exit 2 + a stderr reason asks ZCode to continue the turn (the runner caps this at
   three continuations, which replaces Claude's stop_hook_active loop guard).

   Reads the SAME per-repo ledger the plugin's skill-gate.mjs writes
   (<tmpdir>/zskill-gate/<sha1(repoRoot)>.json: lastSrcEditTs, skills), so the two mounts share
   one truth and this gate needs no recorder of its own. Overrides honor the same escapes:
   <STATE_DIR>/OVERRIDE (one-shot, consumed) and ZSKILL_GATE_OFF=1. Fail-open on any error. */
import { readFileSync, writeSync, existsSync, statSync, unlinkSync } from "node:fs"
import { dirname, join, isAbsolute } from "node:path"
import { tmpdir } from "node:os"
import { createHash } from "node:crypto"

const STATE_DIR = process.env.ZSKILL_GATE_STATE_DIR ?? join(tmpdir(), "zskill-gate")
const VERIFY_RE = /verification-before-completion/

if (process.env.ZSKILL_GATE_OFF === "1") process.exit(0)

function repoRoot(start) {
  let d = start ?? process.cwd()
  if (!isAbsolute(d)) d = join(process.cwd(), d)
  for (let i = 0; i < 8; i++) {
    if (existsSync(join(d, ".git"))) return d
    const up = dirname(d)
    if (up === d) return null
    d = up
  }
  return null
}

const root = repoRoot()
if (!root) process.exit(0)

const p = join(STATE_DIR, createHash("sha1").update(root).digest("hex") + ".json")
let s = {}
try { s = JSON.parse(readFileSync(p, "utf8")) } catch { process.exit(0) }
/* a ledger that parses to null or a scalar (corrupt partial write) is no ledger: fail open
 * (adversary gate finding 2, gate_20260920-013316 - Object.entries(null) would exit 1) */
if (!s || typeof s !== "object") process.exit(0)

const lastVerify = Object.entries(s.skills ?? {})
  .filter(([n]) => VERIFY_RE.test(n)).map(([, t]) => t).sort((a, b) => b - a)[0] ?? 0

if (typeof s.lastSrcEditTs === "number" && s.lastSrcEditTs > lastVerify) {
  // the owner's one-shot escape burns ONLY on an actual block, and only if it is a REGULAR
  // FILE that actually unlinks - an OVERRIDE that is a directory or undeletable must NOT
  // fail the gate open (M2 stop-gate finding 1)
  const ov = join(STATE_DIR, "OVERRIDE")
  try {
    if (statSync(ov).isFile()) { unlinkSync(ov); process.exit(0) }
  } catch {}
  // synchronous fd-2 write: process.stderr is async on pipes and exit(2) can drop the
  // reason the contract requires (M2 stop-gate finding 2)
  writeSync(2, "SKILL GATE (ZCode stop): source was edited after the last verification-before-completion. " +
    "Invoke Skill(superpowers:verification-before-completion), RUN the proving commands fresh, " +
    "then stop. (The runner caps stop continuations, so this cannot loop forever.)\n")
  process.exit(2)
}
process.exit(0)
