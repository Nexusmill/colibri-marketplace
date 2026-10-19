# zcode_jcm_mark.ps1 - ZCode PostToolUse hook. Records that jCodemunch was used in this session,
# which releases the Read/Bash-search guard in zcode_jcm_guard.ps1.
#
# Repo-by-repo port of Nexusmill/tools/zcode_jcm_mark.ps1 (via the Tools twin 65eb0c7; owner
# order 2026-10-18) - verbatim, the script carries no repo-specific content. Registered in
# .zcode/config.json, hooks.events.PostToolUse, matcher
# mcp__(plugin_jcodemunch_jcodemunch|jcodemunch)__.*.
# ZCode names plugin MCP tools mcp__plugin_<plugin>_<server>__tool, so BOTH that spelling and
# the bare Claude spelling are accepted. The session id arrives as -SessionId (expanded from
# ${CLAUDE_SESSION_ID} by the hook runner) because ZCode payloads carry none.
#
# Fail-open: any error exits 0 and writes nothing (the guard simply keeps blocking, which is the
# safe direction for a rule-enforcement marker).

param([string]$SessionId = "")
$ErrorActionPreference = "Stop"
try {
    $raw = [Console]::In.ReadToEnd()
    if (-not $raw) { exit 0 }
    $payload = $raw | ConvertFrom-Json

    $tool = [string]$payload.tool_name
    if ($tool -notlike "mcp__plugin_jcodemunch_jcodemunch__*" -and
        $tool -notlike "mcp__jcodemunch__*") { exit 0 }

    $sid = if ($SessionId) { $SessionId } else { [string]$payload.session_id }
    # the SAME fallback the guard uses: an unexpanded literal ${CLAUDE_SESSION_ID} must resolve
    # to the shared "nosession" marker on BOTH sides or the release path is dead
    if (-not $sid -or $sid -eq '${CLAUDE_SESSION_ID}') { $sid = "nosession" }
    $marker = Join-Path $env:TEMP ("jcmz_used_" + ($sid -replace '[^A-Za-z0-9_\-]', '_') + ".flag")
    Set-Content -LiteralPath $marker -Value (Get-Date -Format s) -ErrorAction SilentlyContinue
    exit 0
}
catch {
    exit 0
}
