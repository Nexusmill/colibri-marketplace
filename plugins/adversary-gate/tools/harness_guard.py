"""harness_guard.py - G39 layer 2: the Claude Code PreToolUse deny-guard.

Registered in ~/.claude/settings.json as a PreToolUse hook (matcher
Bash|Write|Edit|NotebookEdit). Blocks the agent-reachable paths AROUND the adversarial
commit gate - both the classic hook bypasses and the forgery route (writing the gate's
own state). Exit 2 blocks the tool call and shows stderr to the agent; exit 0 allows.

Blocked:
  Bash:  any `git ... --no-verify`; `git commit` with a -n short-flag cluster;
         hooksPath references (except setting core.hooksPath to .githooks, the arming
         value); `commit-tree`; `update-ref`; mutating `git notes` subcommands
         (add/append/copy/edit/remove/prune/merge); any command mentioning `.adversary`
         that is not an invocation of the gate tooling; ADVERSARY_FAKE outside the
         selftests.
  Write/Edit/NotebookEdit: any path with an `.adversary` segment (clearances and notes
         are written ONLY by the gate tooling itself, which runs as a subprocess inside
         git hooks - invisible to PreToolUse, so nothing legitimate breaks).

Fails OPEN on malformed input (never brick the harness): the pre-commit gate and the
audit tripwire still stand behind it. Known accepted false positive: `--no-verify`
appearing inside a quoted commit message still blocks - quote-stripping is out of
scope; reword the message.

Honesty (G1): this guard constrains agents operating through the harness. A human at a
shell walks around it freely - and that is fine (the OVERRIDE escape is the owner's
anyway). The catch-all layer is the audit tripwire, not this guard.
"""
import json
import re
import sys

# (pattern, reason) - checked against Bash commands, case-insensitive
BASH_RULES = [
    (r"\bgit\b[^\n]*\s--no-verify\b",
     "G39: --no-verify bypasses the mandatory adversarial commit gate. Run "
     "adversary_gate.py run to obtain clearance instead."),
    (r"\bgit\b[^\n|;&]*\bcommit\b[^\n|;&]*\s-[a-mo-z]*n[a-z]*\b",
     "G39: `git commit -n` (no-verify) bypasses the adversarial commit gate. Use full "
     "flags without -n, or obtain clearance via adversary_gate.py run."),
    (r"hookspath(?![\s=\"']*\.githooks\b)",
     "G39: re-pointing/unsetting core.hooksPath disarms the adversarial commit gate. "
     "Only `git config core.hooksPath .githooks` (arming) is permitted."),
    (r"\bcommit-tree\b",
     "G39: git plumbing commit-tree creates commits without hooks - the gate cannot "
     "see them. Commit through the normal porcelain path."),
    (r"\bupdate-ref\b",
     "G39: update-ref can move refs/write forged notes without any gate. Not permitted "
     "from the harness."),
    (r"\bgit\b[^\n|;&]*\bnotes\b[^\n|;&]*\b(add|append|copy|edit|remove|prune|merge)\b",
     "G39: adversary notes are written ONLY by adversary_gate.py record. Forging or "
     "deleting notes defeats the audit tripwire."),
    (r"adversary_fake",
     "G39: ADVERSARY_FAKE fakes the reviewer verdict - selftests only.",
     r"_selftest\.py"),
    (r"\.adversary\b",
     "G39: .adversary/ holds the gate's own state (clearances, override, notes staging) "
     "- agents never touch it directly. Use adversary_gate.py run/status/record.",
     r"(adversary_gate\.py|adversary_audit\.py|install_gate\.py|guard_selftest\.py)"),
]

FILE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}


def decide(tool_name, tool_input):
    """Returns None (allow) or a block-reason string."""
    if tool_name in FILE_TOOLS:
        path = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
        norm = path.replace("\\", "/").lower()
        parts = norm.split("/")
        if ".adversary" in parts:
            return ("G39: %s targets the adversarial gate's own state directory "
                    "(.adversary/). Clearances and overrides are written only by the "
                    "gate tooling; hand-editing them is forgery." % tool_name)
        return None
    if tool_name == "Bash":
        cmd = str(tool_input.get("command") or "")
        for rule in BASH_RULES:
            pat, reason = rule[0], rule[1]
            exempt = rule[2] if len(rule) > 2 else None
            if re.search(pat, cmd, re.IGNORECASE):
                if exempt and re.search(exempt, cmd, re.IGNORECASE):
                    continue
                return reason
    return None


def main():
    try:
        data = json.loads(sys.stdin.read() or "{}")
        reason = decide(str(data.get("tool_name") or ""), data.get("tool_input") or {})
    except Exception:
        return 0                     # fail OPEN: the gate + tripwire stand behind us
    if reason:
        sys.stderr.write(reason + "\n")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
