# zcode_repo_guards.ps1 - ZCode PreToolUse hook: G42 fail-arm + G43 cross-repo ledger.
# Repo-by-repo port of Nexusmill/tools/zcode_repo_guards.ps1 (via the Tools twin 65eb0c7
# and the colibri-code-review twin f407328, which carries the EV-229/EV-230 hardening;
# owner order 2026-10-18; the Nexusmill reference was remediated through gate rounds r1-r71 -
# the scanning logic below is kept byte-identical to it, with ONLY the enumerated marketplace
# adaptations; do not refactor casually). Registered in .zcode/config.json PreToolUse, matcher
#   Write|Edit|Bash|mcp__plugin_universal-tools_universal-tools__(safe_write|safe_replace)
#
# PORT DIVERGENCES (each load-bearing):
#   1. Repo identity = $PSScriptRoot's parent (NOT the shared repos.json `current` flag -
#      that flag belongs to the Nexusmill twin's session; a marketplace session must not
#      inherit it, and a script location cannot be spoofed by payload content).
#   2. The G42 verdict is marketplace-keyed: ~/.zcode/health/colibri_marketplace_ledger.json,
#      written by zcode/session_health.py assess (MARKETPLACE_HEALTH_STATE overrides; keys
#      current_fail/failings).
#   3. 'colibri' is an ambiguous fragment on this machine (colibri-marketplace /
#      colibri-code-review / a bare colibri dir): every scope test keys on the ANCHORED
#      spelling 'colibri-marketplace', never the bare fragment.
#   4. The canonical repo_health tooling lives in the NEXUSMILL repo: it is exemptPath-carved
#      for sanctioned invocations (it writes only harness state) and blocklisted from direct
#      writes mid-FAIL, exactly as the reference treats its own copy.
#
# Arm 1 (G42 - session health protocol): when zcode/session_health.py marks the CURRENT repo
#   failing (colibri_marketplace_ledger.json current_fail=true), mutating calls are denied UNLESS
#   remediation-shaped, LOCATION-KEYED on NORMALIZED paths: Write/Edit/MCP-edit only
#   inside the current repo; Bash only with repo_health / git-commit markers AND no
#   outside-repo target. Harness surfaces (repo-memory, .zcode, the ledger) are reachable
#   mid-FAIL only through those auditable chains - never a direct Write, on ANY tool surface
#   including the MCP edit tools.
#
# Arm 2 (G43 - cross-repo adjustment ledger): a MUTATION of an OUTSIDE repo (path under
#   source\repos\<other> or E:\AI\<other>, resolved per TOKEN/PATH - a harness reference
#   elsewhere in the command does not launder an outside target) is denied until the
#   chain declares the adjustment log:
#   - Bash: pre-execution the hook can only verify INTENT - the chain must contain a
#     log_external.py invocation (a success marker is unobservable before execution
#     and free-text forgeable; the POST-HOC AUDIT is the store row - detection, not
#     prevention, same honesty class as G39).
#   - Write/Edit/MCP-edit: payloads cannot carry intent, so a ONE-SHOT unlock: the deny
#     plants %TEMP%\zskill-gate\repo_mem_pending_<sid>_<pathhash>.flag; log via
#     log_external.py, then retry - the flag is consumed by exactly one allowed call.
#     OUTSIDE is the inverted predicate (not-current AND not-harness AND not-temp), so
#     traversals resolving outside the policed trees still deny.
#   Exemptions are path-context scoped (harness repo roots, stores, and temp scratch).
#
# FAIL-OPEN BY DESIGN (same contract as zcode_jcm_guard.ps1): any error, missing input, or
# unparseable payload exits 0 - a broken guard must never block work.
# Escapes (owner's alone): ZSKILL_GATE_OFF=1.

param([string]$SessionId = "")
$ErrorActionPreference = "Stop"
try {
    $raw = [Console]::In.ReadToEnd()
    if (-not $raw) { exit 0 }
    $payload = $raw | ConvertFrom-Json

    $tool = [string]$payload.tool_name
    if ($env:ZSKILL_GATE_OFF -eq '1') { exit 0 }
    $isMcpEdit = ($tool -match 'safe_write$') -or ($tool -match 'safe_replace$')
    if ($tool -notin @("Write", "Edit", "Bash") -and -not $isMcpEdit) { exit 0 }

    $cwd = (Get-Location).Path

    # Current repo root = THIS script's repo (port divergence 1; fail-open default below is
    # the same repo, so a PSScriptRoot quirk degrades to the correct scope, never the wrong one).
    $curRoot = 'C:\Users\User\source\repos\colibri-marketplace'
    try {
        $curRoot = (Split-Path $PSScriptRoot -Parent)
    } catch { }
    $curRootL = $curRoot.Replace('/', '\').ToLower().TrimEnd('\')

    # ---- ledger state (G42, marketplace-keyed - divergence 2) ----
    $fail = $false; $failings = ''
    $ledgerPath = if ($env:MARKETPLACE_HEALTH_STATE) { $env:MARKETPLACE_HEALTH_STATE } else { Join-Path $env:USERPROFILE '.zcode\health\colibri_marketplace_ledger.json' }
    if (Test-Path -LiteralPath $ledgerPath) {
        try {
            $led = Get-Content -LiteralPath $ledgerPath -Raw | ConvertFrom-Json
            if ($led.current_fail) { $fail = $true; $failings = [string]($led.failings -join '; ') }
        } catch { }
    }

    # ---- classification ----
    $isMutating = $false; $outside = $false; $inCurrent = $false; $paths = ''
    # Path-CONTEXT exemptions: harness repo roots and stores only - a bare substring
    # anywhere in a path/command does not exempt. The .zcode exemption is ANCHORED to the
    # harness home so another repo's .zcode subtree is not silently exempt; every
    # alternative is ^-anchored (harness-home-prefixed or drive-rooted) so a nested path
    # that merely CONTAINS a harness substring cannot exempt. The canonical repo_health
    # tree (Nexusmill) is carved for sanctioned invocations (divergence 4).
    $homeL = $env:USERPROFILE.Replace('/', '\').TrimEnd('\').ToLower()
    $exemptPath = ('^' + [regex]::Escape($homeL) + '[\\/]source[\\/]repos[\\/]repo-memory([\\/]|$)|^e:[\\/]repo-memory([\\/]|$)|' +
                   '^' + [regex]::Escape($homeL) + '[\\/]\.zcode([\\/]|$)' +
                   '|^c:[\\/]users[\\/]user[\\/]source[\\/]repos[\\/]nexusmill[\\/]tools[\\/]repo_health([\\/]|$)')
    # Win32-canonical form for MATCHING only (never execution): strip
    # segment-trailing dot/space runs. The run must follow a non-dot, non-separator
    # char - '..' traversal and leading dots are path SYNTAX, not decoration.
    function Get-CanonicalPathText([string]$s) { return ($s -replace '([^.\s\\/])[. ]+([\\/]|$)', '$1$2') }
    if ($tool -ne 'Bash') {
        $isMutating = $true
        $inp = $payload.tool_input
        $p = [string]$inp.file_path
        if (-not $p -and $inp.arguments) { $p = [string]$inp.arguments.file_path }
        if (-not $p) { exit 0 }
        $isAbs = ($p -match '^[a-zA-Z]:[\\/]') -or ($p -match '^\\\\') -or ($p -match '^//') -or ($p -match '^/')
        if (-not $isAbs) { $p = Join-Path $cwd $p }
        try { $p = [IO.Path]::GetFullPath($p) } catch { }
        $pl = $p.ToLower().Replace('/', '\')
        # strip Win32-canonicalized trailing dots/spaces BEFORE any comparison (the Write
        # dotdir trigger canonicalizes inside GetFullPath on this machine)
        $pl = Get-CanonicalPathText $pl
        $inCurrent = $pl.StartsWith($curRootL + '\')
        # OUTSIDE := not current repo AND not harness-exempt AND not scratch-temp. The inverted
        # predicate polices every non-current, non-exempt path; Bash keeps the token-scan form.
        $tempExempt = ($pl -match '\\appdata\\local\\temp\\') -or ($pl -match '\\windows\\temp\\')
        if (-not $inCurrent -and ($pl -notmatch $exemptPath) -and (-not $tempExempt)) {
            $outside = $true; $paths = $p
        }
    }
    else {
        $cmd = [string]$payload.tool_input.command
        if (-not $cmd) { exit 0 }
        $blob = $cmd.ToLower()
        # Write-shape detection (enumerated verbs, redirects, interpreter forms, git
        # state-changers, wrappers - kept identical to the reference rounds r6/r13/r23/r43/r50).
        $writeMarkers = '_safe_edit|_git_do|\bgit\b[^|;&\r\n]*\s(commit|clean|checkout|reset|stash|apply|restore|rebase|merge|push|pull|add|branch|switch|worktree|config|replace|revert|cherry-pick|gc|prune|notes|tag|update-ref|symbolic-ref|reflog|fast-import|filter-branch|filter-repo|clone|init)\b|(^|[\s;&])(cp|mv|rm|del|copy|move|cpi|mi|ni|ri|rd|rmdir|erase|md|mkdir|ac|xcopy|robocopy|ren|rni)\b|remove-item|copy-item|move-item|rename-item|set-content|add-content|out-file|new-item|\btee\b|\bsed\b[^|;&\r\n]*-i|\bpython[0-9.]*\b[^|;&\r\n]*\s+-(c|m)\b|\bpy\b[^|;&\r\n]*\s+-c\b|\bpython[0-9.]*\b[^|;&\r\n]*\s-(\s|$)|\b(node|deno|bun)\b[^|;&\r\n]*\s+(-e|--eval)\b|\b(perl|ruby)\b[^|;&\r\n]*\s+(-e)\b|\b(curl|wget)\b[^|;&\r\n]*\s+(-o|--output|-O\b)|\b(bash|sh|pwsh|powershell)\b[^|;&\r\n]*\s+-(c|lc|command|file)\b|\b(pwsh|powershell)\b[^|;&\r\n]*\s+-(enc|encoded|encodedcommand)\b|\bcmd\b[^|;&\r\n]*\s+/[ck]\b|(^|[\s;&])(python[0-9.]*|py)\b[^|;&\r\n]*\.py\b|(^|[\s;&])(node|deno|bun)\b[^|;&\r\n]*\.(js|mjs|cjs)\b|(^|[\s;&])(bash|sh)\b[^|;&\r\n]*\.(sh|bash)\b|(^|[\s;&])(powershell|pwsh)\b[^|;&\r\n]*\.ps1\b|(^|[\s;&])(tar|unzip|7z|rsync)\b|\bdd\b[^|;&\r\n]*\bof=|(^|[\s;&])(python[0-9.]*|py|bash|sh|node|deno|bun|powershell|pwsh)\s+[^\s;|&-]|>{1,2}\s*[^&\s|]|2>{1,2}\s*[^&\s|]|\$\(|`'
        # marker matching runs on a QUOTE-STRIPPED command where each quoted span becomes the
        # placeholder word _QD_ (quoted spans are DATA; every real write signal lives in
        # UNQUOTED code); shell wrappers are markers AND all-targets - the quoted/external
        # script they execute cannot be localized, so every outside token in the chain is a target.
        $blobStripped = [regex]::Replace([regex]::Replace($blob, '"[^"]*"', ' _QD_ '), "'[^']*'", ' _QD_ ')
        # #-to-EOL comment spans strip from the DECLARATION surface - marker texts inside a
        # trailing comment or an echo argument must never satisfy an intent check.
        $intentText = [regex]::Replace($blobStripped, '(^|\s)#[^\r\n]*', ' ')
        $isMutating = ($blobStripped -match $writeMarkers)
        if ($isMutating) {
            # Token-scoped outside detection: an outside token counts as a MUTATION TARGET
            # only when it is a write DESTINATION - a redirect operand, the trailing path of
            # a copy-class segment - or the command carries an all-targets marker (deletion,
            # move-class verbs, git state changers, safe_write/_safe_edit/_git_do/
            # python -c/sed -i/dir-create) whose target cannot be localized. Marker words
            # appearing as DATA (a grep pattern) with only read operands must not deny or
            # demand a fabricated log row - G43 logs ALTERATIONS, not reads.
            $hasInterp = ($blobStripped -match '(^|[\s;&])(python[0-9.]*|py|bash|sh|node|deno|bun|powershell|pwsh)\b')
            $allTargets = ($blobStripped -match '(^|[\s;&])(rm|del|ri|rd|rmdir|erase|mkdir|ac|ni|new-item|remove-item|mv|move|cpi|mi|move-item|robocopy|set-content|add-content|out-file|ren|rni|rename-item)\b|(^|[\s;&])md\b|\bgit\b[^|;&\r\n]*\s(commit|clean|checkout|reset|stash|apply|restore|rebase|merge|push|pull|add|branch|switch|worktree|config|replace|revert|cherry-pick|gc|prune|notes|tag|update-ref|symbolic-ref|reflog|fast-import|filter-branch|filter-repo|clone|init)\b|_safe_edit|_git_do|\bpython[0-9.]*\b[^|;&\r\n]*\s+-(c|m)\b|\bpy\b[^|;&\r\n]*\s+-c\b|\bpython[0-9.]*\b[^|;&\r\n]*\s-(\s|$)|\b(node|deno|bun)\b[^|;&\r\n]*\s+(-e|--eval)\b|\b(perl|ruby)\b[^|;&\r\n]*\s+(-e)\b|\b(curl|wget)\b[^|;&\r\n]*\s+(-o|--output|-O\b)|\b(bash|sh|pwsh|powershell)\b[^|;&\r\n]*\s+-(c|lc|command|file)\b|\b(pwsh|powershell)\b[^|;&\r\n]*\s+-(enc|encoded|encodedcommand)\b|\bcmd\b[^|;&\r\n]*\s+/[ck]\b|(^|[\s;&])(tar|unzip|7z|rsync)\b|\bdd\b[^|;&\r\n]*\bof=|\bsed\b[^|;&\r\n]*-i|\$\(|`')
            $destRaw = @{}
            foreach ($d in [regex]::Matches($cmd, '(?:>{1,2}|2>{1,2})\s*("[^"]+"|''[^'']+''|[a-zA-Z]:[\\/][^\s;|&"''<>]+|[^\s;|&]+)')) {
                $destRaw[(Get-CanonicalPathText $d.Groups[1].Value.Trim('"').Trim(''''))] = $true
            }
            $copyVerb = '(?:\bcp\b|\bcopy\b|\btee\b|copy-item|\brobocopy\b|\bxcopy\b|\bclone\b)'
            foreach ($seg in ($cmd -split '[#|;&\r\n]+')) {
                # '#' starts a comment in the shell - words after it are not operands.
                $segStripped = [regex]::Replace([regex]::Replace($seg, '"[^"]*"', ' _QD_ '), "'[^']*'", ' _QD_ ')
                if ($segStripped -match $copyVerb) {
                    # destination = the LAST non-flag word of the segment (quote-aware
                    # tokenization; Windows /switches are flags too).
                    $words = @([regex]::Matches($seg, '"[^"]+"|''[^'']+''|[^\s]+') | ForEach-Object { $_.Value } |
                               Where-Object { $_ -ne '' -and -not $_.StartsWith('-') -and -not $_.StartsWith('/') })
                    if ($words.Count -ge 2) { $destRaw[(Get-CanonicalPathText $words[$words.Count - 1].Trim('"').Trim(''''))] = $true }
                }
            }
            $toks = @([regex]::Matches($cmd, '[a-zA-Z]:[\\/][^\s;|&"''<>#]+'))
            # quoted absolute paths are whole tokens (a space inside the quotes truncated
            # the token at the space, so the destRaw key never matched).
            $toks += [regex]::Matches($cmd, '"[a-zA-Z]:[\\/][^"]+"')
            # work_summary's --repos operands are READ-ONLY lookup keys (which stores to write
            # the summary to), not mutation targets - scoped to segments naming work_summary.py
            # so the flag cannot launder an unrelated command's target.
            $lookupKeys = @()
            foreach ($ws in [regex]::Matches($cmd, '(?i)work_summary\.py[^|;&\r\n]*')) {
                foreach ($lk in [regex]::Matches($ws.Value, '(?i)--repos[= ]?("[^"]+"|''[^'']+''|[^\s;|&]+)')) {
                    $lookupKeys += [pscustomobject]@{ Index = $ws.Index + $lk.Groups[1].Index; Length = $lk.Groups[1].Length }
                }
            }
            # relative dot-dot tokens are WHOLE whitespace-delimited tokens containing a ..
            # SEGMENT (an unanchored match discarded the prefix and fabricated a phantom
            # outside target inside the repos tree).
            foreach ($m2 in [regex]::Matches($cmd, '[^\s;|&"''<>#]+')) {
                if ($m2.Value -match '^[a-zA-Z]:') { continue }  # absolute tokens handled above
                if ($m2.Value -match '(^|[\\/])\.\.([\\/]|$)') { $toks += $m2 }
            }
            # quoted spans are DATA here too - a commit message citing another repo's
            # absolute path must not become an outside TARGET. Spans that are write
            # destinations or executed code are exempt from the exemption (real targets).
            $quoteSpans = [regex]::Matches($cmd, '"[^"]*"|''[^'']*''')
            $codeSpans = @()
            foreach ($cs in [regex]::Matches($cmd, '(?i)(python|py|bash|sh|pwsh|powershell|node|deno|bun|perl|ruby|cmd)[^|;&\r\n]*\s+(-c|-e|--eval|-lc|-command|-file|/[ck])\s+("[^"]*"|''[^'']*'')')) {
                $codeSpans += $cs.Groups[3]
            }
            # double-quoted command-substitution spans are EXECUTED CODE here too - their
            # tokens are targets, not data; single quotes do not expand.
            foreach ($ss in $quoteSpans) {
                if ($ss.Value.StartsWith('"') -and ($ss.Value -match '\$\(|`')) { $codeSpans += $ss }
            }
            foreach ($m in $toks) {
                $isLookup2 = $false
                foreach ($lk in $lookupKeys) {
                    if ($m.Index -ge $lk.Index -and $m.Index -lt ($lk.Index + $lk.Length)) { $isLookup2 = $true; break }
                }
                if ($isLookup2) { continue }
                $tv = $m.Value.Trim('"')  # quoted-token form
                # strip Win32-canonicalized trailing dots/spaces BEFORE resolution
                $tv = Get-CanonicalPathText $tv
                $rt = $null
                if ($tv -match '^[a-zA-Z]:[\\/]') {
                    try { $rt = [IO.Path]::GetFullPath($tv).ToLower().Replace('/', '\') } catch { }
                }
                else {
                    try { $rt = [IO.Path]::GetFullPath((Join-Path $cwd $tv)).ToLower().Replace('/', '\') } catch { }
                }
                if (-not $rt) { $rt = $tv.ToLower().Replace('/', '\') }
                # skip tokens inside DATA quote spans (not code spans, not destinations)
                $inData = $false
                foreach ($q in $quoteSpans) {
                    if ($m.Index -ge $q.Index -and $m.Index -lt ($q.Index + $q.Length)) {
                        $isCode2 = $false
                        foreach ($cs3 in $codeSpans) {
                            if ($cs3.Index -le $q.Index -and ($cs3.Index + $cs3.Length) -ge ($q.Index + $q.Length)) { $isCode2 = $true; break }
                        }
                        # under an ALL-TARGETS chain a quoted span whose content IS a single
                        # path (drive-rooted, or starting with a .. segment) is the verb's
                        # OPERAND, not prose.
                        $isPath2 = $false
                        if ($allTargets) {
                            $qc = Get-CanonicalPathText $q.Value.Trim('"').Trim('''')
                            if ($qc -match '^[a-zA-Z]:[\\/].+') { $isPath2 = $true }
                            elseif ($qc -match '^(\.[\\/])*\.\.([\\/]|$)') { $isPath2 = $true }
                        }
                        if (-not $isCode2 -and -not $isPath2 -and -not $destRaw.ContainsKey((Get-CanonicalPathText $q.Value.Trim('"').Trim('''')))) { $inData = $true }
                        break
                    }
                }
                if ($inData) { continue }
                if (($rt -eq $curRootL) -or ($rt.StartsWith($curRootL + '\'))) { continue }
                if ($rt -match $exemptPath) { continue }
                # the gate-tool carve is READ-SCOPED - a Bash interpreter chain may invoke the
                # gate tooling without a log row, but writes to the gate's own source (Write/MCP
                # or destructive verbs, which set allTargets) stay fully policed.
                if ($tool -eq 'Bash' -and -not $allTargets -and $rt -match '^c:[\\/]users[\\/]user[\\/]source[\\/]repos[\\/]tools[\\/]adversary-gate([\\/]|$)') { continue }
                if (-not $allTargets -and (-not $hasInterp -or $tv -notmatch '\.(py|ps1|js|mjs|cjs|sh|bash)$') -and -not $destRaw.ContainsKey($tv)) { continue }  # read operand - interpreter chains treat outside SCRIPT paths as executed bodies
                if (($rt -match 'source[\\]repos([\\/]|$)') -or ($rt -match '^e:[\\]ai([\\/]|$)')) {
                    $outside = $true; $paths = $m.Value; break
                }
            }
            # cd-arming is a SEGMENT-INITIAL scan on the RAW command - `cd <outside-repo> &&
            # <relative write>` targets the outside repo through paths the token scan cannot
            # resolve, so it arms $outside directly for any mutating chain.
            if (-not $outside) {
                foreach ($seg in ($cmd -split '[#|;&\r\n]+')) {
                    $cdo = [regex]::Match($seg.ToLower(), '^\s*(?:cd|set-location)\s+("[^"]+"|''[^'']+''|[a-zA-Z]:[\\/][^\s;|&]+|[^\s;|&]+)')
                    if (-not $cdo.Success) { continue }
                    $cv = $cdo.Groups[1].Value.Trim('"').Trim('''')
                    $cv = Get-CanonicalPathText $cv
                    $cvr = $null
                    if ($cv -match '^[a-zA-Z]:[\\/]') {
                        try { $cvr = [IO.Path]::GetFullPath($cv).ToLower().Replace('/', '\') } catch { }
                    } else {
                        try { $cvr = [IO.Path]::GetFullPath((Join-Path $cwd $cv)).ToLower().Replace('/', '\') } catch { }
                    }
                    if (-not $cvr) { continue }
                    if (($cvr -eq $curRootL) -or ($cvr.StartsWith($curRootL + '\'))) { continue }
                    if ($cvr -match $exemptPath) { continue }
                    # ([\\/]|$) - the policed TREE ROOT itself (no trailing separator) is
                    # outside; requiring one let `cd .. && rm -rf <repo>` bypass the arm.
                    if (($cvr -match 'source[\\]repos([\\/]|$)') -or ($cvr -match '^e:[\\]ai([\\/]|$)')) {
                        $outside = $true; $paths = $cv; break
                    }
                }
            }
        }
    }
    if (-not $isMutating) { exit 0 }

    # ---- G42 fail-arm (location-keyed on normalized paths; outside targets always denied;
    # the GUARD APPARATUS itself is not directly writable mid-FAIL - the fail-locked agent
    # cannot defang the guard, rewrite the ledger's dependencies through Write/Edit/MCP, or
    # delete the canonical health tooling. Apparatus fixes go through Bash+marker chains
    # (auditable) or the confined git-restore repair route; cross-session tamper is DETECTED
    # by the ledger's HEAD-pinned apparatus hashes in the canonical machinery.)
    if ($fail) {
        # the lock covers EVERY shipped mount (an enumeration that omits jcm_guard/jcm_mark/
        # stop_gate lets a fail-locked agent defang the G6 guard or the stop gate with one
        # silent in-repo Write) AND .git itself - commits here are plain git, so .git\hooks
        # and .git\config ARE the gate surface.
        $apparatus = 'zcode[\\/]zcode_(repo_guards|grounding|jcm_guard|jcm_mark)\.ps1$|zcode[\\/]zcode_stop_gate\.mjs$|zcode[\\/]session_health\.py$|repo_health[\\/]|\.zcode[\\/]|\.adversary[\\/]|\.git[\\/]|_git_do\.py$'
        $directApparatus = ($tool -ne 'Bash') -and ($pl -match $apparatus)
        # Bash remediation markers are INVOCATION SHAPES (python <script>.py), not raw
        # substrings - AND a Bash chain whose tokens hit the guard's own state (ledger,
        # .zcode config, .adversary, the repo-memory package) is NEVER remediation - the
        # sanctioned tools rewrite those themselves, no legitimate chain addresses them directly.
        $bashApparatusHit = $false
        if ($tool -eq 'Bash' -and $isMutating) {
            # the apparatus lock scans RAW COMMAND TEXT for apparatus-shaped paths (relative
            # AND absolute spellings) with ONE exemption - the token directly after `python`
            # (the sanctioned invocation itself).
            $apparatusTxt = '(?i)(zcode[\\/]zcode_(repo_guards|grounding|jcm_guard|jcm_mark)\.ps1|zcode[\\/]zcode_stop_gate\.mjs|zcode[\\/]session_health\.py|tools[\\/]repo_health([\\/]|$)|\.zcode([\\/]|$)|\.adversary([\\/]|$)|\.git([\\/]|$)|repo_memory([\\/]|$)|(^|[\s;&])_git_do\.py)'
            # quoted spans are DATA - a commit message containing an apparatus word must not
            # false-deny the sanctioned git commit shape. BUT a quoted span that IS a write
            # destination (captured in $destRaw) is a real target, AND a quoted span that is
            # EXECUTED CODE - the body of python -c / a shell wrapper - is NOT data.
            $quoteSpans = [regex]::Matches($cmd, '"[^"]*"|''[^'']*''')
            $codeSpans = @()
            foreach ($cs in [regex]::Matches($cmd, '(?i)(python|py|bash|sh|pwsh|powershell|node|deno|bun|perl|ruby|cmd)[^|;&\r\n]*\s+(-c|-e|--eval|-lc|-command|-file|/[ck])\s+("[^"]*"|''[^'']*'')')) {
                $codeSpans += $cs.Groups[3]
            }
            # double-quoted command-substitution spans are EXECUTED CODE ($(..)/backtick
            # expand before the command runs) - they join the code spans.
            foreach ($ss in $quoteSpans) {
                if ($ss.Value.StartsWith('"') -and ($ss.Value -match '\$\(|`')) { $codeSpans += $ss }
            }
            # a quoted span whose CONTENT carries an apparatus PATH is never prose (commit
            # messages do not contain zcode/zcode_repo_guards.ps1) - a quoted rm/move target
            # must hit even though it contributes no destRaw key.
            $apparatusPathOnly = '(?i)(zcode[\\/]zcode_(repo_guards|grounding|jcm_guard|jcm_mark)\.ps1|zcode[\\/]zcode_stop_gate\.mjs|zcode[\\/]session_health\.py|tools[\\/]repo_health([\\/]|$)|\.zcode([\\/]|$)|\.adversary([\\/]|$)|\.git([\\/]|$)|repo_memory([\\/]|$))'
            # git's message-bearing flags -m/-am/-em/-qm and --message make the following
            # quoted span a MESSAGE - but a DOUBLE-quoted span containing $( or a backtick is
            # EXECUTED CODE (bash expands it before the command runs), never prose.
            $msgSpans = @()
            foreach ($mm in [regex]::Matches($cmd, '(?i)(?:-[aeq]?m|--message)[=\s]*("[^"]*"|''[^'']*'')')) {
                if ($mm.Groups[1].Value.StartsWith('"') -and ($mm.Groups[1].Value -match '\$\(|`')) { continue }
                $msgSpans += $mm.Groups[1]
            }
            foreach ($am in [regex]::Matches($cmd, $apparatusTxt)) {
                $inQ = $false
                foreach ($q in $quoteSpans) {
                    if ($am.Index -ge $q.Index -and $am.Index -lt ($q.Index + $q.Length)) {
                        $isCode = $false
                        foreach ($cs2 in $codeSpans) {
                            if ($cs2.Index -le $q.Index -and ($cs2.Index + $cs2.Length) -ge ($q.Index + $q.Length)) { $isCode = $true; break }
                        }
                        if (-not $isCode) {
                            $qt = Get-CanonicalPathText $q.Value.Trim('"').Trim('''')
                            $isMsg2 = $false
                            foreach ($ms2 in $msgSpans) {
                                if ($ms2.Index -eq $q.Index) { $isMsg2 = $true; break }
                            }
                            if ($isMsg2 -or -not ($destRaw.ContainsKey($qt) -or ($qt -match $apparatusPathOnly))) { $inQ = $true }  # data: a message, or not a destination/path
                        }
                        break
                    }
                }
                if ($inQ) { continue }
                $pre = $cmd.Substring(0, $am.Index).TrimEnd().Trim('"').Trim('''').TrimEnd()  # a quoted operand leaves its opening quote in the prefix
                if ($pre -match '(?i)(python[0-9.]*|py)(\s+-[^\s;|&]+)*([\\/]|\s+[^\s;|&]*[\\/])?$') { continue }  # the invoked script itself, ANY interpreter spelling with flags, ANY path prefix
                $bashApparatusHit = $true; break
            }
            # the raw-text scan cannot see QUOTED targets - a quoted span whose trimmed
            # content IS an apparatus path or dir is a target, never prose.
            foreach ($q in $quoteSpans) {
                $isMsg3 = $false
                foreach ($ms3 in $msgSpans) {
                    if ($ms3.Index -eq $q.Index) { $isMsg3 = $true; break }
                }
                if ($isMsg3) { continue }
                # a quoted span that IS the sanctioned invocation's operand (its prefix ends
                # the invocation: interpreter + optional flags + optional path prefix) is the
                # invoked script itself - the same exemption the raw scan's $pre grants.
                $preQ = $cmd.Substring(0, $q.Index).TrimEnd()
                if ($preQ -match '(?i)(python[0-9.]*|py)(\s+-[^\s;|&]+)*([\\/]|\s+[^\s;|&]*[\\/])?$') { continue }
                $qt2 = Get-CanonicalPathText $q.Value.Trim('"').Trim('''')
                if (($qt2 -match $apparatusPathOnly) -or
                    ($qt2 -match '^(\.[\\/])?(zcode|\.zcode|\.adversary|\.git|repo_memory|tools[\\/]repo_health)([\\/].*)?$')) {
                    $bashApparatusHit = $true; break
                }
            }
            # interpreter BODIES are executed code - an apparatus path named INSIDE a
            # python -c / wrapper body hits even when quote-adjacent in the raw scan.
            foreach ($cs4 in $codeSpans) {
                $ct = Get-CanonicalPathText $cs4.Value.Trim('"').Trim('''')
                if ($ct -match $apparatusPathOnly) { $bashApparatusHit = $true; break }
                if ($ct -match '(^|[\s(''"])(zcode|\.zcode|\.adversary|\.git|repo_memory|tools[\\/]repo_health)([\\/'')\s]|$)') { $bashApparatusHit = $true; break }
            }
        }
        # invocation shapes ONLY, PLUS the sanctioned REPAIR route - CONFINED: every segment
        # must be a git restore/checkout that names HEAD explicitly (index restores are
        # poisonable mid-FAIL, HEAD~N downgrades the guard to weaker revisions, and a repair
        # verb in a mixed chain must not neutralize apparatus hits elsewhere in that chain).
        # Restoring HEAD bytes cannot defang the guard below its committed state.
        # PORT NOTE: colibri-marketplace commits run plain git and the canonical repo_health
        # tooling is invoked by its absolute Nexusmill spelling. The marketplace ledger-refresh
        # script (zcode/session_health.py - the command the G42 deny message itself
        # instructs) is sanctioned in its RELATIVE and curRoot-anchored spellings ONLY (a
        # zcode\session_health.py under any other root denies).
        $curRootE = ([regex]::Escape($curRootL) -replace '\\\\', '[\\/]')
        # the fail-trigger set and the allowlist must cover each other - store-missing
        # (assess failing) and repo-gitless are both remediable, so their remediation shapes
        # are sanctioned: mkdir/new-item scoped to e:/repo-memory ONLY (the harness store
        # root; any other destination stays denied), and git init (the fix for 'not a git
        # repository'; harmless on an existing repo, and the outside-repo check still
        # polices where it runs).
        $remMarker = ('(^|[\s;&])(?:python[0-9.]*|py)\b(?:\s+-[^\s;|&]+)*\s+(\./)?zcode[\\/]session_health\.py\b' +
                      '|(^|[\s;&])(?:python[0-9.]*|py)\b(?:\s+-[^\s;|&]+)*\s+[^\s;|&]*' + $curRootE + '[\\/]zcode[\\/]session_health\.py\b' +
                      '|(^|[\s;&])(?:python[0-9.]*|py)\b(?:\s+-[^\s;|&]+)*\s+[^\s;|&]*c:[\\/]users[\\/]user[\\/]source[\\/]repos[\\/]nexusmill[\\/]tools[\\/]repo_health[\\/][^\s;|&./\\]*\.py\b' +
                      '|^\s*(?:mkdir|md|new-item)\b(?:\s+-[^\s;|&]+)*\s+e:[\\/]repo-memory([\\/][^\s;|&./\\]*)?\s*$' +
                      '|\bgit\b[^|;&\r\n]*\s(commit|restore|checkout|init|add)\b')
        $gitRepair = $false
        if ($blobStripped -match '\bgit\b[^|;&\r\n]*\s(restore|checkout)\b') {
            $allRepair = $true
            foreach ($rseg in ($intentText -split '[|;&\r\n]+')) {  # comment-stripped surface
                $rt = $rseg.Trim()
                if ($rt -eq '') { continue }
                if ($rt -match '(?i)^git\b[^|]*\s(restore|checkout)\b' -and $rt -match '(?i)(--source=|-s\s+)head(\s|$)|head\s+--') { continue }
                # only the EXACT head revision (whitespace/segment end) is a sanctioned
                # repair; head~N/^/@/: downgraded the apparatus to older revisions.
                $allRepair = $false; break
            }
            $gitRepair = $allRepair
        }
        # the remediation grant is PER-SEGMENT - 'git commit' anywhere in the chain must not
        # declare the WHOLE chain remediation. cd/set-location segments are neutral (the
        # sanctioned cd-then-invoke shape). Comments strip OUTSIDE QUOTES ONLY (a char scan
        # tracking quote state), then a quoted span's CONTENT lifts only when operator-free
        # (a script path) - prose keeps its boundary, substitution spans stay collapsed.
        $liftSrc = ([string]$cmd).ToLower()
        $sb = [System.Text.StringBuilder]::new()
        $inQ = [char]0
        $prev = [char]0
        $cut = $false
        foreach ($ch in $liftSrc.ToCharArray()) {
            if ($cut) {
                if ($ch -eq "`n") { $cut = $false; [void]$sb.Append($ch); $prev = $ch } else { [void]$sb.Append(' ') }
                continue
            }
            if ($inQ -ne [char]0) {
                [void]$sb.Append($ch)
                if ($ch -eq $inQ) { $inQ = [char]0 }
                $prev = $ch
                continue
            }
            if ($ch -eq '"' -or $ch -eq "'") { $inQ = $ch; [void]$sb.Append($ch); $prev = $ch; continue }
            if ($ch -eq '#' -and ($prev -eq [char]0 -or [char]::IsWhiteSpace($prev))) { $cut = $true; [void]$sb.Append(' '); $prev = $ch; continue }
            [void]$sb.Append($ch)
            $prev = $ch
        }
        $liftText = [regex]::Replace($sb.ToString(), '"[^"]*"|''[^'']*''', {
            param($mm)
            $inner = $mm.Value.Trim('"').Trim('''')
            if ($inner -match '[|;&()$`\r\n]') { ' _QD_ ' } else { $inner }
        })
        $allRem = $true
        foreach ($rseg2 in ($liftText -split '[|;&\r\n]+')) {
            if ($rseg2.Trim() -eq '' -or $rseg2 -match '(?i)^\s*(cd|set-location)\s') { continue }
            # an UNQUOTED substitution in a segment is invisible code - the segment is not a
            # sanctioned shape no matter what precedes it; quoted spans are collapsed to
            # _QD_ by the lift, so legitimate messages still pass.
            if ($rseg2 -match '\$\(|`') { $allRem = $false; break }
            if ($rseg2 -notmatch $remMarker) { $allRem = $false; break }
        }
        # the repair confinement is TEXT-keyed - ANY repair verb in the chain requires the
        # confinement (a path-less 'git checkout HEAD~20' spelled no apparatus text).
        $hasRepairVerb = ($blobStripped -match '\bgit\b[^|;&\r\n]*\s(restore|checkout)\b')
        $repairOk = (-not $hasRepairVerb) -or $gitRepair
        $remediation = (-not $directApparatus -and $repairOk -and (-not $bashApparatusHit -or $gitRepair)) -and (
            (($tool -ne 'Bash') -and $inCurrent) -or
            (($tool -eq 'Bash') -and (-not $outside) -and
             $allRem))
        if (-not $remediation) {
            $reason = @"
BLOCKED by G42 (session health protocol): the CURRENT repo is FAILING - remediation first.
Current failings: $failings
Allowed while failing: Write/Edit (incl. safe_write/safe_replace) INSIDE this repo, Bash
chains INVOKING the sanctioned tools (python zcode/session_health.py assess | python
C:/Users/User/source/repos/Nexusmill/tools/repo_health/*.py | git commit), and git
restore/checkout (the sanctioned APPARATUS REPAIR - it restores
committed, gate-cleared bytes) - with no outside-repo target and no direct write to the
guard's own state (colibri_marketplace_ledger.json / .zcode config / .adversary / repo-memory
package / the zcode twins / the canonical repo_health tooling - the sanctioned tools rewrite
those themselves).
Re-run python zcode/session_health.py assess to refresh the ledger.
"@
            $out = @{ hookSpecificOutput = @{ hookEventName = "PreToolUse"; permissionDecision = "deny"; permissionDecisionReason = $reason } }
            $out | ConvertTo-Json -Depth 6 -Compress
            exit 0
        }
        exit 0
    }

    # ---- G43 cross-repo arm (current repo healthy) ----
    if (-not $outside) { exit 0 }

    if ($tool -eq 'Bash') {
        # INTENT verification: the DECLARATION must be an INVOCATION SHAPE on the
        # comment-stripped text (segment-initial; a trailing '# log_external.py' comment or
        # quoted literal must not unlock an unlogged outside mutation). The store row written
        # by the invoked call is the post-hoc audit (detection class - prevention is not
        # claimed for hand-typed commands).
        $declared = $false
        foreach ($iseg in ($intentText -split '[|;&\r\n]+')) {
            if ($iseg -match '^\s*([^\s;|&]*[\\/])?(python[0-9.]*|py)(\.exe)?\b(\s+-[^\s;|&]+)*\s+[^\s;|&]*log_external\.py') { $declared = $true; break }
        }
        if ($declared) { exit 0 }
        $reason = @"
BLOCKED by G43 (cross-repo adjustment ledger): this command mutates an OUTSIDE repo
($paths) without a declared adjustment log. Include in the SAME chain:
  python C:/Users/User/source/repos/Nexusmill/tools/repo_health/log_external.py --repo-path <target-repo-root> --topic "<what changed>" --decision "<the adjustment>" --rationale "<why>"
The store row that call writes is the audit trail. Owner escape: ZSKILL_GATE_OFF=1.
"@
        $out = @{ hookSpecificOutput = @{ hookEventName = "PreToolUse"; permissionDecision = "deny"; permissionDecisionReason = $reason } }
        $out | ConvertTo-Json -Depth 6 -Compress
        exit 0
    }

    # Write/Edit/MCP-edit: one-shot unlock - first deny plants the flag, log, retry consumes it.
    # The flag is TARGET-BOUND via a path hash, so a stale nosession flag from an abandoned
    # deny cannot unlock a different repo's edit in another session.
    $sid = if ($SessionId) { $SessionId } else { [string]$payload.session_id }
    if (-not $sid -or $sid -eq '${CLAUDE_SESSION_ID}') { $sid = "nosession" }
    $ph = 0
    foreach ($c in $paths.ToCharArray()) { $ph = (($ph * 31) + [int]$c) % 32003 }
    $flag = Join-Path $env:TEMP ("zskill-gate\repo_mem_pending_" + ($sid -replace '[^A-Za-z0-9_\-]', '_') + "_" + $ph + ".flag")
    # the flag is consumed ONLY when its stored content equals the CURRENT target path
    # (gate round 2 finding 2): the filename hash alone is a 15-bit key - a different
    # path that collides on it must NOT ride another target's unlock, and an
    # unreadable/corrupt flag falls through to the deny below, which re-plants it.
    if (Test-Path -LiteralPath $flag) {
        $prev = $null
        try { $prev = Get-Content -LiteralPath $flag -Raw -ErrorAction Stop } catch { }
        if ($null -ne $prev -and $prev.Trim() -eq $paths) {
            Remove-Item -LiteralPath $flag -ErrorAction SilentlyContinue
            exit 0
        }
    }
    try {
        New-Item -ItemType Directory -Force -Path (Split-Path $flag) | Out-Null
        Set-Content -LiteralPath $flag -Value $paths -ErrorAction Stop
    } catch { }
    $reason = @"
BLOCKED by G43 (cross-repo adjustment ledger): this edit targets an OUTSIDE repo ($paths).
1) Log the adjustment FIRST:
  python C:/Users/User/source/repos/Nexusmill/tools/repo_health/log_external.py --repo-path <target-repo-root> --topic "<what changed>" --decision "<the adjustment>" --rationale "<why>"
2) Retry this exact edit - the one-shot unlock (planted by this deny) allows ONE call.
The store row is the audit trail; hand-typed evasion is a canon violation (detection, not
prevention, is claimed). Owner escape: ZSKILL_GATE_OFF=1.
"@
    $out = @{ hookSpecificOutput = @{ hookEventName = "PreToolUse"; permissionDecision = "deny"; permissionDecisionReason = $reason } }
    $out | ConvertTo-Json -Depth 6 -Compress
    exit 0
}
catch {
    exit 0   # fail open - never block on a guard bug
}
