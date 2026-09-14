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
         ANY Bash reference to `.adversary/` - no read exemption (EV-022's five gate rounds
         proved a text guard cannot tell a read from a write once function shadowing / PATH
         / aliases are in play), so the whole state dir is off-limits to Bash; inspect it
         via `adversary_gate.py status`. Also a segment-leading shell-variable assignment
         of a commit-bypass flag (FLAG=-n / =--no-verify), incl. export/declare-prefixed.
  Write/Edit/NotebookEdit: any path with an `.adversary` segment (clearances and notes
         are written ONLY by the gate tooling itself, which runs as a subprocess inside
         git hooks - invisible to PreToolUse, so nothing legitimate breaks).
         Also (2026-09-04) any path with a `skill_gate` segment - the G38 skill gate's
         per-session ledgers and owner-only OVERRIDE (Tools/skill-gate); and any Bash
         reference to `skill_gate/` or `skill_gate\`, same covenant as `.adversary`.

Fails OPEN on malformed input (never brick the harness): the pre-commit gate and the
audit tripwire still stand behind it. Known accepted false positives (reword to proceed):
`--no-verify` inside a quoted commit message still blocks (quote-stripping is out of
scope); a segment-leading `VAR=-n` / `VAR=--no-verify` env-assignment blocks even when
benign; ANY command naming `.adversary/` blocks even a pure read (use `adversary_gate.py
status` to inspect gate state); and `export ADVERSARY_FAKE=CLEAR; python gate_selftest.py`
blocks because the per-segment `_selftest.py` exemption only sees its own segment - use the
single-segment form `ADVERSARY_FAKE=CLEAR python gate_selftest.py`. Residuals the audit
tripwire backstops, not this guard: glob/string-concat evasion that never spells the literal
`.adversary`, and unbounded shell-variable flag indirection (arrays, `${x:--n}`, computed).

Honesty (G1): this guard constrains agents operating through the harness. A human at a
shell walks around it freely - and that is fine (the OVERRIDE escape is the owner's
anyway). The catch-all layer is the audit tripwire, not this guard.
"""
import json
import re
import sys

# (pattern, reason) - checked against Bash commands, case-insensitive
BASH_RULES = [
    (r"--no-verify\b",
     "G39: --no-verify bypasses the mandatory adversarial commit gate (matched anywhere - "
     "it can be smuggled across lines via a shell var). Run adversary_gate.py run instead."),
    (r"^\s*[({]?\s*(?:(?:export|declare|typeset|readonly|local)\s+)?(?:-\w+\s+)*(?:\w+=\S*\s+)*\w+=(?:\$?['\"])?(?:--no-verify|-n)\b",
     "G39: assigning a commit-bypass flag to a shell variable (FLAG=-n) to smuggle it into "
     "`git commit $FLAG` is BEST-EFFORT blocked here (common assignment forms incl. "
     "subshell/grouped, multi-assignment, export/declare, and $'...' quoting). Unbounded "
     "shell indirection (arrays, ${x:--n}, computed values) is caught by the post-commit "
     "audit tripwire, not this guard. Commit through adversary_gate.py run."),
    (r"\bset\b\s+--\s+[^\n;&|]*-n\b",
     "G39: `set -- -n` then `git commit \"$@\"` smuggles the no-verify flag past the gate. "
     "Not permitted; commit through adversary_gate.py run (the audit tripwire backstops it)."),
    # A glued short bundle denies only when NO letter before the `n` is a value-taking commit
    # option (`m F c C t`, folded to `c f m t` because rules run under IGNORECASE): `-nm x` is
    # -n -m (deny) but `-mn x` is -m "n" - the hook RUNS, and denying it was a live false
    # positive (GUARD_PORTABILITY backlog 1, imported from Caliper's git-guard 2026-09-04).
    (r"\bgit\b[^\n|;&]*\bcommit\b[^\n|;&]*\s-[abd-eg-lo-su-z]*n[a-z]*\b",
     "G39: `git commit -n` (no-verify) bypasses the adversarial commit gate. Use full "
     "flags without -n, or obtain clearance via adversary_gate.py run."),
    # A variable-built git word (`c=git; $c commit -n`) leaves a literal `commit` token but no
    # `git` token in the segment (found by the 2026-09-04 backlog probe):
    (r"\$\{?\w+\}?[^\n|;&]*\bcommit\b[^\n|;&]*\s-[abd-eg-lo-su-z]*n[a-z]*\b",
     "G39: `$VAR commit -n` - a commit invoked through a shell variable with the no-verify "
     "flag bypasses the adversarial commit gate. Spell `git commit` out, without -n."),
    # 2026-09-06 (universal arming): the GLOBAL value is the owner's machine-wide arming - set
    # by Damien at a shell, never from the harness (before this rule `--global .githooks` was
    # allowed: guard_selftest found it while adding the canonical rows). Checked first.
    (r"--global\b[^\n;&|]*hookspath",
     "G39: the GLOBAL core.hooksPath is the owner's machine-wide arming - set by Damien at a "
     "shell, never from the harness. Per-repo arming is `install_gate.py <repo>`."),
    # ...in EVERY spelling (commit-B round 4, MEDIUM F2): a literal-free global/system write,
    # a section removal (drops the hooks value with the section), an include that pulls a
    # hookless value from an unprotected file, --edit, or a --file/-f target. Local reads and
    # local single-key writes stay allowed (the hooks-path rules above govern the key).
    (r"\bgit\b[^\n;&|]*\bconfig\b[^\n;&|]*(?:--global\b|--system\b|--worktree\b|--remove-section\b"
     r"|--rename-section\b|--edit\b|\s-e\b|--file\b|\s-f\s|\binclude\.path\b|\bincludeif\b)",
     "G39: git config writes that can re-point or drop the hooks path without naming it "
     "(--global/--system/--worktree, --remove-section/--rename-section, --edit, --file, "
     "include.path/includeIf) are the owner's alone. Per-repo arming is install_gate.py."),
    (r"\bGIT_CONFIG_(?:GLOBAL|SYSTEM|NOSYSTEM|PARAMETERS|COUNT|KEY_\d+|VALUE_\d+)\b",
     "G39: config-override environment variables (GIT_CONFIG_GLOBAL/SYSTEM/NOSYSTEM/PARAMETERS/"
     "COUNT/KEY_n) re-point the machine-wide arming for that command. Not permitted from the "
     "harness; the selftests set them in-process, never on a shell line."),
    # two arming spellings pass: the vendored `.githooks` and the machine-wide canonical
    # dispatcher dir Tools/adversary-gate/hooks (EXACT: any suffix or traversal after it denies;
    # either slash; optional trailing slash; case-insensitive like every rule here)
    # The value boundary is a plain SPACE, quote, separator or end - never \s: a trailing tab
    # or NBSP is stored verbatim by git, Win32 trims only U+0020 and dots, the hook dir then
    # does not resolve and NO hook runs (commit-B gate round 1, gate_20260906-182251, HIGH).
    # The assignment is ONE `=` or whitespace, then an optional quote - never a loose skip class:
    # `core.hooksPath = .githooks` sets the value to `=` (hookless) and used to pass.
    # ...and a quote after the value counts as its end ONLY when the quote sits at the very
    # END of the segment: the shell strips quotes, so `.githooks"x"` reaches git as the
    # hookless `.githooksx` (round 4, gate_20260906-190533) and `.githooks" "x` as the
    # hookless `.githooks x` (round 9, gate_20260906-204139) - a quote followed by anything,
    # even a space, denies on doubt. Quoted inline arming (`-c ...=".githooks" commit`) is
    # therefore denied too; spell it unquoted.
    (r"hookspath(?!(?:=|\s+)[\"']?(?:\.githooks[\\/]?|c:[\\/]users[\\/]user[\\/]source[\\/]repos[\\/]tools"
     r"[\\/]adversary-gate[\\/]hooks[\\/]?)(?=[ ;&|]|$|[\"']\s*$))",
     "G39: re-pointing/unsetting core.hooksPath disarms the adversarial commit gate. Only the "
     "two arming values are permitted: `.githooks` or the machine-wide canonical dir "
     "Tools/adversary-gate/hooks (install_gate.py sets it for you), with nothing after them."),
    # The machine-wide DISPATCHER dir (2026-09-06) is the live gate of every armed repo - same
    # covenant as .git/hooks and .adversary: no Bash reference at all (EV-022: a text guard
    # cannot tell rm from cat once shadowing/PATH/aliases are in play). A deleted dispatcher
    # runs NO hook; the suite's own tooling never spells the dir (hooks_selftest.py,
    # install_gate.py are siblings, not children). Edits go through safe_write and must land
    # through the gate (HOOK_NAMES code); an uncommitted edit fails closed on itself.
    # Exempt ONLY a segment that is, in its entirety, the arming command (`git config
    # core.hooksPath <canonical>`) or the inline `git -c core.hooksPath=<canonical> commit ...`
    # form - never a segment that merely contains one (EV-022: an exemption that can share a
    # segment with a forbidden action is a bypass).
    # Spelling coverage mirrors the .git/hooks rule exactly (commit-B round 2, HIGH F1):
    # deny-on-doubt across ANY intermediates (`z/..`), trailing dot/space runs per segment
    # (Win32 trims them), the three alternatives disjoint on `.` (linear time). `\bhooks\b`
    # keeps `hooks_selftest.py` (word continues) allowed while `hooks.` / `hooks/x` deny.
    (r"adversary-gate[. ]*[\\/](?:[^\s;&|'\". ]|[. ]+(?=[\\/])|\.(?![. ]*[\\/]))*\bhooks\b",
     "G39: referencing the machine-wide dispatcher dir (Tools/adversary-gate/hooks/) from the "
     "shell is not permitted - deleting or rewriting a dispatcher disarms every armed repo. "
     "Edit through safe_write and commit through the gate; verify with install_gate.py --census.",
     # the inline form's tail admits NO `$`, backtick, `<` or `>` at all: segments split on
     # ;&| only, so a substitution (round 2, HIGH F2) or a plain redirection that truncates
     # the dispatcher before git runs (round 3, HIGH F1) would ride inside the exemption
     r"^\s*git\s+(?:-c\s+core\.hookspath=(?:[\"'])?c:[\\/]users[\\/]user[\\/]source[\\/]repos[\\/]tools"
     r"[\\/]adversary-gate[\\/]hooks[\\/]?(?:[\"'])?\s+commit\b[^\n$`<>]*"
     r"|(?:-c\s+\S+\s+)?config\s+(?:--local\s+)?core\.hookspath\s+(?:[\"'])?c:[\\/]users[\\/]user"
     r"[\\/]source[\\/]repos[\\/]tools[\\/]adversary-gate[\\/]hooks[\\/]?(?:[\"'])?)\s*$"),
    # An NTFS 8.3 short-name alias (ADVERS~1, USER~1) resolves to the same dir and carries no
    # literal the rules above can see (commit-B round 4, F3): any alias segment followed by a
    # separator and, later in the same token, a hooks segment denies. git's HEAD~1 revision
    # syntax is never followed by a separator, so it stays allowed.
    # ...the alias segment may itself carry a trailing dot/space run (commit-B round 7, HIGH).
    # Anchored on the literal `~digits` (round 8, MEDIUM): a leading greedy class restarted at
    # every position of a long token and went quadratic (measured: a 300 KB token hung past
    # the 30 s selftest timeout); the alias NAME before the tilde carries no signal anyway.
    (r"~\d+[. ]*[\\/][^\s;&|'\"]*\bhooks\b",
     "G39: an 8.3 short-name path (NAME~1) leading to a hooks directory is the live hook dir "
     "or the machine-wide dispatcher dir under another spelling - not permitted from the shell."),
    (r"\bcommit-tree\b",
     "G39: git plumbing commit-tree creates commits without hooks - the gate cannot "
     "see them. Commit through the normal porcelain path."),
    (r"\bupdate-ref\b",
     "G39: update-ref can move refs/write forged notes without any gate. Not permitted "
     "from the harness."),
    (r"\bgit\b[^\n|;&]*\bnotes\b[^\n|;&]*\b(add|append|copy|edit|remove|prune|merge)\b",
     "G39: adversary notes are written ONLY by adversary_gate.py record. Forging or "
     "deleting notes defeats the audit tripwire."),
    (r"\bgit\b[^\n|;&]*\breplace\b",
     "G39: git replace substitutes objects under the gate/auditor (they now set "
     "GIT_NO_REPLACE_OBJECTS, but the command itself is not permitted from the harness)."),
    (r"\bfast-import\b",
     "G39: git fast-import creates commits without hooks - the gate cannot see them. "
     "Commit through the normal porcelain path."),
    (r"adversary_fake",
     "G39: ADVERSARY_FAKE fakes the reviewer verdict - selftests only.",
     r"_selftest\.py"),
    # BLOCK ANY Bash reference to .adversary/ - NO exemption. EV-022's five gate rounds
    # proved a text guard cannot tell a read from a write once function shadowing / PATH
    # hijack / aliases are in play (`cat` in argv[0] guarantees nothing runs cat), and every
    # "safe read" exemption tried (write-indicator denylist -> read allowlist -> per-segment
    # first-word + fn-shape) reopened a forgery route. The gate tools contain no ".adversary"
    # substring, so a normal `adversary_gate.py run/status/record` invocation never trips
    # this; an agent that wants to SEE gate state runs `adversary_gate.py status`, never
    # `ls/cat .adversary/`. A direct literal reference is therefore always the agent poking
    # the state dir - refused. Residual (accepted, audit-tripwire-backstopped): glob or
    # string-concat evasion that never spells the literal `.adversary`.
    (r"\.adversary\b",
     "G39: referencing .adversary/ (clearances, override, notes staging) directly from the "
     "shell is not permitted - once function shadowing / PATH / aliases are in play a text "
     "guard cannot tell a read from a write, so the whole state dir is off-limits to Bash. "
     "Use `adversary_gate.py status` to inspect it, or run/record to change gate state."),
    # G38 skill gate (2026-09-04): the ledger dir `skill_gate/` (underscore; the TOOL lives in
    # `skill-gate/` with a hyphen so invocations never match) holds per-session skill ledgers
    # and the owner-only OVERRIDE. Same covenant as .adversary: no Bash reference at all.
    (r"skill_gate[\\/]",
     "G38: referencing the skill gate's state dir (skill_gate/ - ledgers, OVERRIDE) from the "
     "shell is not permitted. Inspect it with `skill_gate.py status`; the OVERRIDE is the "
     "owner's alone."),
    # The LIVE hook dir .git/hooks (GUARD_PORTABILITY backlog 2, 2026-09-04): deleting or
    # rewriting the inner pre-commit hook disarms the gate below this guard. Same covenant as
    # .adversary - any reference, any case, any separator, NO read exemption (EV-022: a text
    # guard cannot tell a read from a write once shadowing/PATH/aliases are in play; Caliper's
    # readish/writeish split is the documented divergence). The TRACKED shim lives in
    # `.githooks/` (no separator), is gate-reviewed source, and never matches this rule.
    # Gate round 1 (gate_20260904-135918.md, HIGH): `.git/./hooks`, `.git//hooks`, `.git./hooks`
    # (Windows trailing dot) and `.git/info/../hooks` all resolve to the hook dir and all
    # slipped past an adjacency regex - so the rule is deny-on-doubt: ANY path token that
    # starts at `.git/` and reaches a `hooks` segment, whatever lies between. Round 2
    # (gate_20260904-141449.md, HIGH): Windows trims any RUN of trailing dots/spaces per
    # segment, so `.git../hooks` and a quoted `.git \hooks` must match too - `[. ]*`, not `\.?`.
    # ... and a trimmed `.. ` / `. ` run LATER in a quoted path (`.git\z\.. \hooks`) - a
    # dot/space run is admitted only when a separator follows it (EV-030). The three
    # alternatives are DISJOINT on `.` (round 5, gate_20260904-161013.md: an overlapping form
    # backtracked exponentially on `./` x 40 - measured, the hook hung): plain chars never
    # include a dot; a dot/space run only before a separator; a lone dot only when NOT
    # followed by such a run.
    (r"\.git[. ]*[\\/](?:[^\s;&|'\". ]|[. ]+(?=[\\/])|\.(?![. ]*[\\/]))*\bhooks\b",
     "G39: referencing the live hook directory (.git/hooks) from the shell is not permitted - "
     "rewriting or deleting the inner pre-commit hook disarms the adversarial commit gate. "
     "The reviewed shim is `.githooks/`; arming is `install_gate.py <repo>`."),
]

FILE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}


def decide(tool_name, tool_input):
    """Returns None (allow) or a block-reason string."""
    if tool_name in FILE_TOOLS:
        path = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
        norm = path.replace("\\", "/").lower()
        # Windows canonicalizes a trailing dot/space off a path segment, so ".adversary."
        # resolves to ".adversary" on disk - strip them before the segment compare. Every OS
        # also resolves `.`, empty (`//`) and `..` components away, and an adjacency test on
        # raw segments was defeated by exactly those (gate_20260904-135918.md, HIGH): fold
        # them here so the compare sees the path the filesystem sees.
        # Two readings of every all-dot/space segment (`..`, `.. `, `.. .`, `...`, `....`): the
        # OS may treat it as PARENT (pop) or as CURRENT (skip) depending on platform and exact
        # spelling - a text guard cannot know which, so BOTH are canonicalised and either one
        # producing the adjacency denies (deny-on-doubt). EV-030: the `..` test once ran before
        # the strip (`.. ` neither popped nor pushed); round 4 (gate_20260904-154627.md): a
        # `startswith("..")` pop threw `.git` away on `.git/.../hooks`.
        # Segment classes: exact "" / "." are CURRENT and exact ".." is PARENT (unambiguous);
        # any OTHER all-dot/space segment (`...`, `.. `, `. .`) is AMBIGUOUS. Only the ambiguous
        # ones are enumerated (round 6: a whole-path all-pop/all-skip pair missed the MIXED
        # `x\...\..\hooks`, where `...` must read current and `..` parent), and ANY assignment
        # producing a hit denies. More than 8 ambiguous segments is refused outright.
        segs = []
        for i, seg in enumerate(norm.split("/")):
            if i == 0:
                # drive-relative spelling `C:.git\hooks`: the drive letter is not a segment
                seg = re.sub(r"^[a-z]:", "", seg)
            core = seg.rstrip(". ")
            if core:
                segs.append(("name", core))
            elif seg == "..":
                segs.append(("parent", None))
            elif seg in ("", "."):
                segs.append(("current", None))
            else:
                segs.append(("ambiguous", None))
        amb = [i for i, s in enumerate(segs) if s[0] == "ambiguous"]
        if len(amb) > 8:
            return ("G39: %s path carries %d ambiguous dot/space segments - refused (deny-on-doubt; "
                    "no honest path is spelled that way)." % (tool_name, len(amb)))
        readings = []
        for mask in range(1 << len(amb)):
            out = []
            for i, (kind, val) in enumerate(segs):
                if kind == "ambiguous":
                    kind = "parent" if (mask >> amb.index(i)) & 1 else "current"
                if kind == "name":
                    out.append(val)
                elif kind == "parent" and out:
                    out.pop()
            readings.append(out)
        # round 5 (gate_20260904-161013.md, HIGH): a pop reading can DELETE the state-dir segment
        # (`.adversary\...\x`), so membership is tested on the union of ALL readings.
        parts = set().union(*readings)
        # an NTFS 8.3 alias segment (ADVERS~1, HOOKS~1) hides the protected name from every
        # check below; no honest harness write spells a path that way (commit-B round 4, F3)
        if any(re.search(r"~\d+$", p) for p in parts):
            return ("G39: %s path carries an 8.3 short-name segment (NAME~1) - the protected "
                    "directories cannot be recognised under that spelling; spell the path out."
                    % tool_name)
        if ".adversary" in parts:
            return ("G39: %s targets the adversarial gate's own state directory "
                    "(.adversary/). Clearances and overrides are written only by the "
                    "gate tooling; hand-editing them is forgery." % tool_name)
        if "skill_gate" in parts:
            return ("G38: %s targets the skill gate's state directory (skill_gate/). Ledgers "
                    "are written only by skill_gate.py; the OVERRIDE is the owner's alone."
                    % tool_name)
        # the live hook dir: consecutive segments `.git` / `hooks` in any case or separator
        # (`.githooks/` is one segment and stays editable - it is gate-reviewed source).
        if any(a == ".git" and b == "hooks" for r in readings for a, b in zip(r, r[1:])):
            return ("G39: %s targets the live hook directory (.git/hooks). Rewriting the inner "
                    "pre-commit hook disarms the adversarial commit gate; the reviewed shim is "
                    "`.githooks/`, armed by install_gate.py." % tool_name)
        # the machine-wide dispatcher dir: consecutive segments `adversary-gate` / `hooks`
        # (2026-09-06; the same covenant as .git/hooks - harness file tools never write it,
        # safe_write + the gate do)
        if any(a == "adversary-gate" and b == "hooks" for r in readings for a, b in zip(r, r[1:])):
            return ("G39: %s targets the machine-wide dispatcher dir (Tools/adversary-gate/hooks/), "
                    "the live gate of every armed repo. Dispatchers change only through safe_write "
                    "and a gated commit." % tool_name)
        return None
    if tool_name == "Bash":
        cmd = str(tool_input.get("command") or "")
        # Evaluate each rule PER SHELL SEGMENT: an exempt gate invocation in ONE segment
        # must not excuse a forbidden action in ANOTHER (e.g.
        # `adversary_gate.py status ; echo x > .adversary/clearance.json`). Splitting on
        # ; & | and newlines isolates each command; every rule pattern is per-command, so
        # a segment carrying the exemption clears only itself.
        segments = re.split(r"[;&|\n]+", cmd)
        for rule in BASH_RULES:
            pat, reason = rule[0], rule[1]
            exempt = rule[2] if len(rule) > 2 else None
            for seg in segments:
                # TWO views per segment (commit-B gate round 8, gate_20260906-201038, HIGH): the
                # raw text, and the text with every quote character removed - the shell strips
                # quote pairs and reassembles a token split by them (`adversary-gate/"hooks"`,
                # `core.hooks"Path=`), so a protected literal must be judged the way the shell
                # sees it. Deny if EITHER view trips a rule; an exemption is judged on the same
                # view that matched (deny-on-doubt).
                views = (seg,) if not ('"' in seg or "'" in seg) else (seg, seg.replace('"', "").replace("'", ""))
                for view in views:
                    if re.search(pat, view, re.IGNORECASE):
                        if exempt and re.search(exempt, view, re.IGNORECASE):
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
