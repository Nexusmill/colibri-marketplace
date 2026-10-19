# colibri-marketplace ZCode SessionStart grounding hook (2026-10-18).
# Repo-by-repo twin of Nexusmill/tools/zcode_grounding.ps1 (via the Tools port 65eb0c7 +
# ea14805 and the colibri-code-review twin f407328, which carries the EV-229/EV-230
# hardening; owner order 2026-10-18: cross-repo twin work runs from the NEXUSMILL session).
# Re-injects the grounding directive + the marketplace-keyed health verdict + the G44 forced
# HIGH summaries + the AGENTS.md snapshot into context at every session start (startup /
# resume / clear / compact) so a compaction cannot leave the agent a blank slate.
# Registered in .zcode/config.json under hooks.events.SessionStart. PORT DIVERGENCES
# (all load-bearing):
#   (1) repo identity comes from $PSScriptRoot, and the health verdict is marketplace-keyed
#       (~/.zcode/health/colibri_marketplace_ledger.json via zcode/session_health.py assess)
#       because the canonical multi-repo ledger resolves "current repo" via the single
#       `current` flag in repos.json - which belongs to the NEXUSMILL twin's session. The
#       canonical ledger still runs below it for DISPLAY ONLY.
#   (2) HIGH-summary ingestion (G44) targets the colibri-marketplace store directly
#       (zcode/session_health.py ingest; tool colibri_marketplace_memory_search).
#   (3) every subprocess runs inside a WALL-CLOCK budget (a slow child is killed and
#       degrades to a fallback note - fail-open must cover LATENCY, not just errors, or
#       the 75s hook window kills the script and the session gets ZERO grounding), and the
#       display blocks share a budget derived from the 10000-char payload cap with the
#       snapshot RESERVED FIRST - the final guard may shrink the display section but never
#       the snapshot (the blank-slate guard is the one block that must survive).
# The additionalContext payload keeps the Claude-compatible hookSpecificOutput shape the ZCode
# hook runner accepts, and is \uXXXX-escaped to pure ASCII (Windows PowerShell 5.1 writes
# stdout in the OEM console code page and a non-ASCII payload can arrive JSON-illegal,
# HOOK-JSON-CODEPAGE 2026-09-03). MARKETPLACE_AGENT_STATE overrides the state path (tests).
# Regression test: tests/test_zcode_twin.py (runs the real hook under powershell.exe).

$ErrorActionPreference = 'SilentlyContinue'
$repo  = Split-Path $PSScriptRoot -Parent
$state = Join-Path $repo 'AGENTS.md'
if ($env:MARKETPLACE_AGENT_STATE) { $state = $env:MARKETPLACE_AGENT_STATE }

# Bounded subprocess: run $exe with a wall-clock budget; a slow or hung child is KILLED and
# the caller gets the fallback text. Latency fail-open - the `&` call operator cannot be
# timed out, so this is the only latency bound in the hook.
function Invoke-Bounded([string]$exe, [string]$argLine, [int]$seconds, [string]$fallback) {
    $tmp = [IO.Path]::GetTempFileName()
    $err = $tmp + '.err'
    try {
        $p = Start-Process -FilePath $exe -ArgumentList $argLine -NoNewWindow -PassThru `
             -RedirectStandardOutput $tmp -RedirectStandardError $err -ErrorAction Stop
        if (-not $p.WaitForExit($seconds * 1000)) {
            # .NET Framework Kill() has no tree overload - the python child spawns git
            # grandchildren that would outlive the budget holding the redirected temp
            # handles; taskkill /T fells the whole tree, then a short grace lets the
            # handles drop so the finally cleanup can delete the temp pair.
            Start-Process -FilePath 'taskkill' -ArgumentList ('/PID ' + $p.Id + ' /T /F') -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
            try { if (-not $p.HasExited) { $p.Kill() } } catch { }
            $p.WaitForExit(2000) | Out-Null
            return $fallback
        }
        # -Encoding UTF8 matches the child's forced UTF-8 stdout (PS 5.1 -Raw default is
        # ANSI - the mismatch turned non-ASCII summaries into mojibake)
        $out = Get-Content -LiteralPath $tmp -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
        if (-not $out) { $out = '' }
        if ($out -eq '') { return $fallback }
        return $out
    } catch {
        return $fallback
    }
    finally {
        Remove-Item -LiteralPath $tmp, $err -Force -ErrorAction SilentlyContinue
    }
}

$directive = @"
COLIBRI-MARKETPLACE SESSION GROUNDING (auto-injected by .zcode/config.json SessionStart hook).
You are in the colibri-marketplace repo ($repo) on ZCode - the plugin MARKETPLACE that ships
colibri-review and adversary-gate to ZCode/Claude installs. Release discipline is THE hard
invariant here: a skill/plugin release rotates the canonical source (colibri-code-review /
Tools repo), THIS marketplace copy, and the installed plugin cache TOGETHER (G37/G39 ladder
pins) - never let them drift. Do NOT act as a blank slate or re-derive known facts.
HARD RULES: (1) AGENTS.md (repo root) is the state file; the universal canon lives in the
Nexusmill repo (docs/GLOBAL_RULES.md, docs/GLOBAL_MEMORY.md) - Read GLOBAL_MEMORY.md before
any mutating work (the G-MEM skill gate enforces the Read and records it). (2) The numbered
rules canon (G1-G44) arrives via the global ~/.zcode/AGENTS.md injection - it governs every
task. (3) Commits are plain git here and EVERY commit fires the adversarial config-hook gate
(G39: external review CLEAR keyed to staged blob sha256s); never --no-verify; stage EXPLICIT
paths only. (4) jCodemunch FIRST for code search (G6): repo id Nexusmill/colibri-marketplace
(resolve_repo to confirm; index_folder if stale); Read only right before editing a located
file. (5) The G38 skill gate is LIVE: harness Edit/Write on tracked code files is denied - use
mcp__plugin_universal-tools_universal-tools__safe_write / safe_replace (G8); first source
edit needs a process entry skill; after a failure signal, systematic-debugging or
colibri-review; commits need verification-before-completion after the last source edit.
(6) Memory: the semantic store is PRIMARY (colibri_marketplace-memory MCP via the machine-wide
repo-memory plugin / E:/repo-memory/colibri_marketplace; CLI via the repo-memory venv -m
repo_memory.cli --repo <root>); .md memory files are the offline backup (G40). (7) Paid
reviewers are pinned by the gate ladder - never pick a reviewer from a skill routing table
or memory prose; read the pin file (Tools/adversary-gate) before dispatching ANY paid review.
colibri-marketplace health + forced HIGH summaries follow (the marketplace-keyed verdict is
authoritative; the multi-repo ledger below it is display-only - its 'current' flag belongs to
the Nexusmill twin's session); the AGENTS.md snapshot is LAST.
"@

# ---- budget math: the snapshot is RESERVED before the display blocks get their caps, so
# their sum can never push the snapshot out of the payload ----
$snapHeader = 'Current START-HERE snapshot from AGENTS.md follows:'
$rawSnap = ''
if (Test-Path $state) {
    $rawSnap = Get-Content -Path $state -Raw -Encoding UTF8
    if (-not $rawSnap) { $rawSnap = '' }   # PS 5.1: -Raw returns $null on a zero-byte file
}
$totalBudget  = 10000
$snapReserve  = [Math]::Min(1400, [Math]::Max(200, $rawSnap.Length)) + $snapHeader.Length + 90
$displayBudget = $totalBudget - $directive.Length - $snapReserve - 240   # separators + truncation markers
if ($displayBudget -lt 900) { $displayBudget = 900 }
$blockCap = [int][Math]::Floor($displayBudget / 3)

$ctx = $directive

# ---- marketplace-keyed health (G42; authoritative for this repo's fail-arm) ----
# zcode/session_health.py assess assesses THIS repo (existence, git, state file, store) and
# persists ~/.zcode/health/colibri_marketplace_ledger.json, which zcode_repo_guards.ps1 enforces.
$healthPy = Join-Path $repo 'zcode\session_health.py'
if (Test-Path $healthPy) {
    $health = Invoke-Bounded 'python' ('-B "' + $healthPy + '" assess') 12 '(colibri-marketplace health unavailable - budget exceeded; run zcode/session_health.py assess directly)'
    if ($health.Length -gt $blockCap) {
        $health = $health.Substring(0, $blockCap)
        # never end the slice on a lone high surrogate (the ASCII emitter escapes each
        # UTF-16 unit alone - an unpaired \udXXX would break the JSON payload)
        $lastCode = [int][char]$health[$health.Length - 1]
        if ($lastCode -ge 0xD800 -and $lastCode -le 0xDBFF) { $health = $health.Substring(0, $health.Length - 1) }
        $health = $health + "`n...(colibri-marketplace health truncated - run zcode/session_health.py assess directly)"
    }
    $ctx = $ctx + "`n`n" + $health
}

# ---- Canonical multi-repo ledger (DISPLAY ONLY) ----
# Its "current" row names the Nexusmill twin's session (the shared repos.json flag) - here it
# is informational cross-repo context, never the marketplace verdict (that is the block above).
$ledgerTool = 'C:\Users\User\source\repos\Nexusmill\tools\repo_health\health_ledger.py'
if (Test-Path $ledgerTool) {
    $led = Invoke-Bounded 'python' ('-B "' + $ledgerTool + '"') 12 '(multi-repo ledger unavailable - budget exceeded; run the canonical health_ledger.py directly)'
    $led = "Multi-repo ledger (display-only - its 'current' row names the Nexusmill twin's session):`n" + $led
    if ($led.Length -gt $blockCap) {
        $led = $led.Substring(0, $blockCap)
        $lastCode = [int][char]$led[$led.Length - 1]
        if ($lastCode -ge 0xD800 -and $lastCode -le 0xDBFF) { $led = $led.Substring(0, $led.Length - 1) }
        $led = $led + "`n...(ledger truncated - run the canonical health_ledger.py directly)"
    }
    $ctx = $ctx + "`n`n" + $led
}

# ---- Forced HIGH-summary ingestion (G44, colibri-marketplace store) ----
# Every [HIGH]-rated work summary in THIS repo's store is injected into the payload so the
# agent ingests it at session start - enforced by wiring, not habit.
if (Test-Path $healthPy) {
    $ing = Invoke-Bounded 'python' ('-B "' + $healthPy + '" ingest') 35 '(FORCED INGESTION (G44): unavailable (budget exceeded).)'
    if ($ing.Length -gt $blockCap) {
        $ing = $ing.Substring(0, $blockCap)
        # same lone-high-surrogate hazard + fix as the slices above
        $lastCode = [int][char]$ing[$ing.Length - 1]
        if ($lastCode -ge 0xD800 -and $lastCode -le 0xDBFF) { $ing = $ing.Substring(0, $ing.Length - 1) }
        $ing = $ing + "`n...(ingestion truncated)"
    }
    $ctx = $ctx + "`n`n" + $ing
}

# ---- AGENTS.md snapshot LAST, inside the total-payload budget ----
# The display blocks above were capped against the snapshot reserve, so the snapshot keeps
# its budget by construction; the slicing below still bounds a grown state file (newest
# blocks sit at the top, so trimming the tail loses the OLDEST state - the least lossy cut).
$cap = $totalBudget - $ctx.Length - $snapHeader.Length - 6
if ($cap -lt 200) { $cap = 200 }
$snapshot = ''
if ($rawSnap -ne '') {
    $take = [Math]::Min($cap, $rawSnap.Length)
    $willMark = $rawSnap.Length -gt $take
    if ($willMark) { $take = [Math]::Max(200, $take - 74) }  # room for the marker line below
    $snapshot = $rawSnap.Substring(0, $take)
    # never end the slice on a lone high surrogate (an astral char straddling the boundary):
    # the escape would emit an unpaired \udXXX that breaks UTF-8 consumers downstream
    if ($snapshot.Length -gt 0) {
        $lastCode = [int][char]$snapshot[$snapshot.Length - 1]
        if ($lastCode -ge 0xD800 -and $lastCode -le 0xDBFF) { $snapshot = $snapshot.Substring(0, $snapshot.Length - 1) }
    }
    $snapshot = $snapshot.TrimEnd()
    if ($willMark) {
        $snapshot += "`n...[snapshot truncated - read AGENTS.md for the full state]"
    }
} else {
    $snapshot = '(AGENTS.md not found - read it directly.)'
}
$ctx = $ctx + "`n`n" + $snapHeader + "`n`n" + $snapshot

# Final total-budget guard: the DISPLAY section is sacrificed before the snapshot ever is -
# the blank-slate guard is the one block that must survive, loudly marked, never silently
# dropped.
if ($ctx.Length -gt $totalBudget) {
    $snapBlock = "`n`n" + $snapHeader + "`n`n" + $snapshot
    $keep = $totalBudget - $snapBlock.Length - 120
    if ($keep -lt $directive.Length) { $keep = $directive.Length }
    if ($keep -lt $ctx.Length) {
        $disp = $ctx.Substring(0, $keep)
        # text is APPENDED after this cut, so a trailing high surrogate here is no longer at
        # string end when the later end-guard runs - trim it now, or the emitter emits an
        # unpaired \udXXX mid-payload
        $lastCode = [int][char]$disp[$disp.Length - 1]
        if ($lastCode -ge 0xD800 -and $lastCode -le 0xDBFF) { $disp = $disp.Substring(0, $disp.Length - 1) }
        $ctx = $disp + "`n...(display blocks truncated - run the health tools directly)" + $snapBlock
    }
    if ($ctx.Length -gt $totalBudget) {
        $ctx = $ctx.Substring(0, $totalBudget)
        $lastCode = [int][char]$ctx[$ctx.Length - 1]
        if ($lastCode -ge 0xD800 -and $lastCode -le 0xDBFF) { $ctx = $ctx.Substring(0, $ctx.Length - 1) }
    }
}

$payload = [ordered]@{
    hookSpecificOutput = [ordered]@{
        hookEventName     = 'SessionStart'
        additionalContext = $ctx
    }
}
$json = $payload | ConvertTo-Json -Depth 5 -Compress

# Pure-ASCII emission: \uXXXX-escape every UTF-16 code unit outside printable ASCII (each half of
# a surrogate pair separately - valid JSON), so no console code page can corrupt the payload.
$ascii = [regex]::Replace($json, '[^\x20-\x7E]', [System.Text.RegularExpressions.MatchEvaluator]{
    param($m) '\u{0:x4}' -f [int][char]$m.Value })
Write-Output $ascii
