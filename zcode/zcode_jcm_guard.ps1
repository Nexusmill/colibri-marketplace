# zcode_jcm_guard.ps1 - ZCode PreToolUse hook enforcing the jCodemunch-first rule (G6).
# Repo-by-repo port of Nexusmill/tools/zcode_jcm_guard.ps1 (via the Tools twin 65eb0c7 and
# the colibri-code-review twin f407328, which carries the EV-229/EV-230 hardening; owner
# order 2026-10-18), scoped to the colibri-marketplace repo. Registered in .zcode/config.json,
# hooks.events.PreToolUse, matcher Read|Bash.
# ZCode has no Grep/Glob tools - code search goes through Bash - so the Bash arm judges the
# classic search verbs (grep / rg / findstr / Select-String / find / fd / Get-ChildItem|gci|dir
# with a recursive flag) aimed at this repo's code, in addition to the Claude-style Read arm.
# The session marker is written by zcode_jcm_mark.ps1 on any jCodemunch MCP call; ZCode
# payloads carry no session_id, so the id arrives as the -SessionId argument expanded from
# ${CLAUDE_SESSION_ID} by the hook runner (an unexpanded literal falls back to a shared
# "nosession" marker - documented residual).
#
# PORT NOTE (generic name fragment): 'colibri' alone is ambiguous on this machine
# (colibri-marketplace / colibri-code-review / a bare colibri dir), so every scope test the
# reference keys on the bare repo name is keyed on the ANCHORED spelling
# 'repos\colibri-marketplace' / 'source/repos/colibri-marketplace' here - another repo's
# colibri\ directory must never classify as in-repo, and an in-repo path must never read as
# outside.
#
# Command-position rule: a search VERB is the FIRST token of a segment split on | ; & and
# NEWLINE, so running e.g. zcode/run_probe.py is not a search while "echo x\nrg foo zcode/"
# is. Subshell parsing ($( ) indirection) is a DOCUMENTED residual, the same class the
# universal-tools plugin gates document.
#
# Target rule (one classification pass over the command tokens): the doc exemption needs
# EVERY path-like target to be a doc; the outside-repo exemption needs EVERY path-like target
# to be an absolute path outside this repo. A single mixed token keeps the command gated.
# Relative Read file_paths resolve against the hook cwd before repo scoping.
#
# WHY CONDITIONAL RATHER THAN A FLAT DENY: Edit/Write require a prior Read of the file. The
# real rule is "only fall back to Read/Bash-search immediately before editing a LOCATED file".
# One jCodemunch call releases the guard for the session.
#
# Escapes (owner's alone, same contract as the plugin gates): ZSKILL_GATE_OFF=1, and the
# one-shot <TEMP>\zskill-gate\OVERRIDE which burns ONLY on a call that would be denied.
#
# FAIL-OPEN BY DESIGN: any error, missing input, or unparseable payload exits 0 (allow).
# A broken guard must never block work.

param([string]$SessionId = "")
$ErrorActionPreference = "Stop"
try {
    $raw = [Console]::In.ReadToEnd()
    if (-not $raw) { exit 0 }
    $payload = $raw | ConvertFrom-Json

    $tool = [string]$payload.tool_name
    if ($tool -notin @("Read", "Bash")) { exit 0 }

    if ($env:ZSKILL_GATE_OFF -eq '1') { exit 0 }

    $sourceExt = @(".py", ".js", ".ts", ".tsx", ".jsx", ".cs", ".c", ".cpp", ".h", ".hpp", ".rs", ".go", ".rb", ".java", ".ps1", ".mjs")
    $cwd = (Get-Location).Path

    if ($tool -eq "Read") {
        $path = [string]$payload.tool_input.file_path
        if (-not $path) { exit 0 }

        # Only guard SOURCE files. Docs, JSON, config, logs and scratch stay freely readable.
        $ext = [System.IO.Path]::GetExtension($path).ToLower()
        if ($sourceExt -notcontains $ext) { exit 0 }

        # A relative file_path resolves against the hook cwd before repo scoping;
        # absolute means drive-letter, UNC, or POSIX root; GetFullPath collapses
        # any .. traversal so "junk/../zcode/foo.ps1" cannot ride a lexical junk exemption.
        $isAbs = ($path -match '^[a-zA-Z]:[\\/]') -or ($path -match '^\\\\') -or ($path -match '^//') -or ($path -match '^/')
        if (-not $isAbs) { $path = Join-Path $cwd $path }
        try { $path = [IO.Path]::GetFullPath($path) } catch { }

        # Only guard files inside the colibri-marketplace repo; junk/ is scratch by convention.
        if ($path -notlike "*\source\repos\colibri-marketplace\*" -and $path -notlike "*/source/repos/colibri-marketplace/*") { exit 0 }
        if ($path -like "*\junk\*" -or $path -like "*/junk/*") { exit 0 }
        if ($path -like "*\legacy\*" -or $path -like "*/legacy/*") { exit 0 }
    }
    else {
        $cmd = [string]$payload.tool_input.command
        if (-not $cmd) { exit 0 }
        $blob = $cmd.ToLower()

        $verbs = @('grep', 'rg', 'findstr', 'select-string', 'sls', 'find', 'fd', 'gci', 'get-childitem', 'dir', 'ls')
        $patternVerbs = @('grep', 'rg', 'findstr', 'select-string', 'sls', 'fd')
        $valueFlags = @('-e', '--regexp', '-g', '--glob', '--include', '--exclude', '-name', '-path')
        $isSearch = $false
        $sawTarget = $false; $allNonCode = $true; $allOutside = $true
        # segments keep ORIGINAL CASE: the recursive-flag test is case-sensitive (-R recurse
        # vs -r reverse) and the blob was lowercased
        foreach ($seg in ($cmd -split '[|;&\r\n]+')) {
            # @() forces an array: a pipeline assignment collapses a one-token result to a
            # scalar String, [0] then yields a Char and .Trim throws into the fail-open catch
            $segTokens = @((($seg.Trim()) -split '\s+') | Where-Object { $_ })
            if (-not $segTokens) { continue }
            # the VERB token is excluded from target classification later -
            # "/usr/bin/rg allocate" is a search, not an outside target. A dotted
            # basename (zcode/find.py) is NOT a verb - only .exe/.cmd/.bat or no extension
            # count
            $rawFirst = $segTokens[0].Trim('"', "'")
            $bn = $rawFirst -replace '^.*[\\/]'
            if ($bn -match '\.(exe|cmd|bat)$') { $bn = $bn -replace '\.(exe|cmd|bat)$', '' }
            elseif ($bn -match '\.') { $bn = '' }
            $verb = $bn.ToLower()
            if (-not $verb -or $verbs -notcontains $verb) { continue }
            if ($verb -in @('ls', 'dir', 'gci', 'get-childitem')) {
                # genuinely recursive flags only: -R clusters (-Ra), lone -r/-Recurse/-Depth
                # (case-insensitive - PowerShell binding), --recursive, /s /S - reverse-sort
                # clusters like -rt/-rh must not gate
                if ($seg -cmatch '\s(--recursive\b|(?i:-[a-z0-9]*ecurse)\b|-R[a-zA-Z]*\b|-r\b|(?i:-depth)\b|/[sS]\b)') { $isSearch = $true }
            } else { $isSearch = $true }

            # operand classification INSIDE the segment: for pattern-verbs the FIRST non-flag
            # token is the PATTERN (never a target), and a value-carrying flag's next token is
            # a value, not a target - so "rg -e junk/ -e allocate" has NO targets and stays
            # gated as a cwd search
            $patternTaken = $false
            $expectValue = $false
            foreach ($tk in ($segTokens | Select-Object -Skip 1)) {
                $tl = $tk.Trim('"', "'").ToLower()
                if ($expectValue) { $expectValue = $false; continue }
                if ($tl -match '^-' -or $tl -match '^/[a-z]{1,2}$') {
                    # -name/-path are find's pattern flags but gci PARAMETERS - the value rule
                    # is scoped to find alone so "gci -Path docs/ -Recurse" keeps its target
                    if (($valueFlags -contains $tl) -and ($verb -eq 'find' -or $tl -notin @('-name', '-path'))) { $expectValue = $true }
                    continue
                }
                if ((-not $patternTaken) -and ($patternVerbs -contains $verb)) { $patternTaken = $true; continue }
                $t = $tk.Trim('"', "'")
                $isPath = ($t -match '[\\/]') -or ($t -match '\.(md|txt|rst|py|js|ts|tsx|jsx|cs|c|cpp|h|hpp|rs|go|rb|java|ps1|mjs)$')
                if (-not $isPath) { continue }
                $sawTarget = $true
                # EVERY non-POSIX token resolves (absolute included - an absolute junk/../
                # stays lexical otherwise). A POSIX-slash token naming THIS repo
                # ('repos/colibri-marketplace' in the token) also resolves so junk/../
                # collapses in that spelling too; other POSIX tokens stay LEXICAL: .NET
                # GetFullPath ('/todo/') fabricates 'C:\todo\', which would read as
                # legitimately outside. A token GetFullPath cannot resolve (glob metachars
                # throw on .NET Framework) classifies as CODE - fail-closed, never exempt.
                # DOCUMENTED RESIDUAL: an 8.3 short name ('COLIBR~1' class) evades the
                # anchored spelling and classifies outside - deliberate evasion, the
                # subshell/indirection class.
                $rt = $null
                if ($t -match '^/' -and $t -notmatch 'repos/colibri-marketplace') { $rt = $t }
                else { try { $rt = [IO.Path]::GetFullPath($t) } catch { } }
                if ($null -eq $rt) { $allNonCode = $false; $allOutside = $false; continue }
                $rtL = $rt.ToLower()
                $nonCode = ($rtL -match '\.(md|txt|rst)$') -or ($rtL -match '(^|[\\/])docs([\\/]|$)') -or ($rtL -match '(^|[\\/])junk([\\/]|$)') -or ($rtL -match '(^|[\\/])legacy([\\/]|$)')
                if (-not $nonCode) { $allNonCode = $false }
                # PORT NOTE: the outside test is anchored on 'repos\colibri-marketplace' (not
                # the bare repo name) - colibri-code-review and the bare colibri dir must
                # classify outside, this repo must not.
                $absOutside = (($rtL -match '^[a-z]:[\\/]') -or ($rtL -match '^\\\\') -or ($rtL -match '^//') -or ($rtL -match '^/[^/]+/.')) -and ($rtL -notmatch 'repos[\\/]colibri-marketplace([\\/]|$)')
                if (-not $absOutside) { $allOutside = $false }
            }
        }
        if (-not $isSearch) { exit 0 }
        if ($sawTarget -and $allNonCode) { exit 0 }

        $inRepo = ($cwd -like "*\source\repos\colibri-marketplace*") -or ($cwd -like "*/source/repos/colibri-marketplace*") -or ($blob -match 'source/repos/colibri-marketplace')
        if (-not $inRepo) { exit 0 }
        if ($sawTarget -and $allOutside) { exit 0 }
    }

    # Session marker, written by zcode_jcm_mark.ps1 on any jCodemunch tool call.
    $sid = if ($SessionId) { $SessionId } else { [string]$payload.session_id }
    if (-not $sid -or $sid -eq '${CLAUDE_SESSION_ID}') { $sid = "nosession" }
    $marker = Join-Path $env:TEMP ("jcmz_used_" + ($sid -replace '[^A-Za-z0-9_\-]', '_') + ".flag")
    if (Test-Path -LiteralPath $marker) { exit 0 }   # already complied this session

    # The one-shot escape burns ONLY here, at a call that would actually be denied, and
    # ONLY if the OVERRIDE is a REGULAR FILE that is actually deleted (gate round 2
    # finding 1 - the stop gate's M2 class): a directory or undeletable OVERRIDE must NOT
    # fail the guard open; the guard keeps denying instead.
    $ov = Join-Path $env:TEMP 'zskill-gate\OVERRIDE'
    try {
        if ((Get-Item -LiteralPath $ov -Force -ErrorAction Stop) -is [IO.FileInfo]) {
            Remove-Item -LiteralPath $ov -Force -ErrorAction Stop
            exit 0
        }
    } catch { }

    $reason = @"
BLOCKED by rule G6 (jCodemunch-first). You have not used jCodemunch yet this session.

Do NOT read or grep source files to find things. Use the index - it costs a fraction of the tokens:
  mcp__plugin_jcodemunch_jcodemunch__resolve_repo    - confirm the repo (Nexusmill/colibri-marketplace)
  mcp__plugin_jcodemunch_jcodemunch__search_symbols  - find a function/class by name or signature
  mcp__plugin_jcodemunch_jcodemunch__search_text     - find a string, comment or config value
  mcp__plugin_jcodemunch_jcodemunch__get_symbol_source - read JUST the symbol, not the whole file
  mcp__plugin_jcodemunch_jcodemunch__get_file_outline  - see a file's structure without reading it

Read/Bash-search is permitted only as the LAST step, immediately before editing a file you have
already located via jCodemunch. Make one jCodemunch call and this guard stops blocking for the session.
"@

    $out = @{
        hookSpecificOutput = @{
            hookEventName            = "PreToolUse"
            permissionDecision       = "deny"
            permissionDecisionReason = $reason
        }
    }
    $out | ConvertTo-Json -Depth 6 -Compress
    exit 0
}
catch {
    exit 0   # fail open - never block on a guard bug
}
