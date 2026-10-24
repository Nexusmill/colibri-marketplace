# -*- coding: utf-8 -*-
"""Config-based hooks arming for the adversary gate (T3, owner order
2026-10-10, git 2.54+ adoption).

Empirical basis (junk/git256_probe.py, git 2.56.0.windows.1, 2026-10-10):
config hooks (`hook.<name>.event` + `hook.<name>.command`) fire on REAL
events, run BEFORE the hookdir script, and the hookdir script STILL RUNS
AFTER. Consequence: config-hook arming and a live hooksPath shim STACK -
double paid review - so arming a repo via config REQUIRES unsetting any
hooksPath pin in that repo first (this module refuses to stack).

Integrity posture: the config command binds the ABSOLUTE certified
`launch.py`, which validates its own digest-checked generation on every run -
the anchor moves from "shim file bytes" to "certified runtime
self-validation"; the notary/auditor/push-guard layers are unchanged.
"""
import os
import re
import subprocess
import sys

# Layout-derived (0.3.7 plugin port, owner order 2026-10-11): this module
# lives in the gate dir; the suite root is its parent. The interpreter is
# whichever python runs this tool.
_GATE_DIR_PATH = os.path.dirname(os.path.abspath(__file__))
_GATE_DIR = os.path.basename(_GATE_DIR_PATH)              # "adversary-gate" | "tools"
DEFAULT_SUITE = os.path.dirname(_GATE_DIR_PATH)
_PY = sys.executable or "python3"

EVENTS = ("pre-commit", "post-commit", "pre-push")
# The exact invocations for the config-hook entries: pre-commit -> gate
# check; post-commit -> gate record (NO positional - argparse rejects one)
# plus a SEPARATE activate entry (the shim runs both); pre-push -> gate
# check-push (git APPENDS the event argv - remote, url - AFTER the command,
# and the stdin ref-lines arrive on stdin; a literal "$1" in the command
# expands EMPTY through the shell while the real remote/url land as EXTRA
# argv, breaking argparse - live-proven 2026-10-14, junk/prepush_driver.py;
# the gate parser additionally tolerates the empty-leading-remote shape of
# not-yet-corrected live entries).
_EVENT_ARGS = {
    "adversary-pre-commit": ("pre-commit", ["gate", "check"]),
    "adversary-post-commit": ("post-commit", ["gate", "record"]),
    "adversary-activate": ("post-commit", ["activate"]),
    "adversary-pre-push": ("pre-push", ["gate", "check-push"]),
}


_ENV = None            # tests inject an isolated environment here; None inherits


def _git(repo, *args):
    r = subprocess.run(["git", "-C", repo] + list(args), capture_output=True,
                       text=True, timeout=60, env=_ENV)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def capability(repo):
    """True when this git supports config-based hooks for real events
    (git >= 2.54), by version parse - `git hook list` exit codes are
    state-dependent (a dangling hooksPath makes even capable gits fail)."""
    rc, out, _ = _git(repo, "--version")
    m = re.match(r"git version (\d+)\.(\d+)", out or "")
    return rc == 0 and bool(m) and (int(m.group(1)), int(m.group(2))) >= (2, 54)


def launcher_path(suite):
    return os.path.join(suite, _GATE_DIR, ".adversary", "runtime", "launch.py")


def _entries(suite):
    launch = launcher_path(suite).replace("\\", "/")
    out = []
    for name, (event, args) in _EVENT_ARGS.items():
        cmd = '"%s" -I -B "%s" %s' % (_PY, launch, " ".join(args))
        out.append((name, event, cmd))
    return out


def _command_matches(live, expected_cmd):
    """Exact-byte comparison with ONE legacy tolerance (round 133017 finding 2):
    entries written before 2026-10-14 embed a hookdir-style literal '"$1"'
    token that the shell expands EMPTY while git appends the real argv after
    the command - functionally equivalent since the gate parser tolerates the
    shape, so exactly that one trailing token is accepted. Anything else that
    differs is still foreign (round gate_20261011-055123: substring tests
    counted commands that merely MENTION the certified path)."""
    live = (live or "").strip()
    return live == expected_cmd or live == expected_cmd + ' "$1"'


def arming(repo, suite=DEFAULT_SUITE):
    """The gate's armed config-hook entries across ALL scopes:
    [(scope, name, event, command)] where the command binds this suite's
    certified launcher. `git hook list` exit codes are state-dependent (a
    dangling hooksPath fails even on capable gits, round gate_20261010-224546
    LOW) so config is the source of truth; an event with no command arms
    nothing (round gate_20261010-225355 MEDIUM); suite-truthful (round
    gate_20261010-232919 LOW); scope-complete so status agrees with arm()'s
    broader-scope reporting (round gate_20261010-235540 MEDIUM)."""
    found = []
    # exact-command matching (round gate_20261011-055123: a substring test
    # counted a command that merely MENTIONS the certified path while
    # invoking something else; we generate these commands, so we compare the
    # exact bytes)
    expected = {name: cmd for name, _e, cmd in _entries(suite)}
    for scope in ("--local", "--global", "--system"):
        for name, event, _cmd in _entries(suite):
            rc_ev, evs, _ = _git(repo, "config", scope, "--get-all", "hook.%s.event" % name)
            if rc_ev != 0 or event not in (evs or "").splitlines():
                continue
            cmd = _git(repo, "config", scope, "--get", "hook.%s.command" % name)[1]
            if not cmd or not _command_matches(cmd, expected[name]):
                continue
            found.append((scope.lstrip("-"), name, event, cmd))
    return found


def arm(repo, suite=DEFAULT_SUITE, force=False):
    """Arm the gate in `repo` via config hooks, transactionally: entries are
    written and verified FIRST and rolled back on any failure (the existing
    hooksPath arming is never left half-replaced - rounds gate_20261010-223109
    and gate_20261010-225355: a mid-arm failure must not silently disarm the
    repo); only after every entry is in place is the LOCAL hooksPath pin
    retired. Stacking is refused across ALL scopes (local, global, system) -
    config hooks fire first and every active hookdir shim still runs after -
    unless `force` explicitly accepts the double-review migration window."""
    if not capability(repo):
        return False, ("this git lacks config-based hooks (needs >= 2.54); "
                       "arm with the hooksPath installer instead")
    if not os.path.isfile(launcher_path(suite)):
        return False, ("certified launcher missing: %s - arm the runtime first "
                       "(enforcement_runtime activate)" % launcher_path(suite))
    # config-over-config stacking (rounds gate_20261010-230532/231710/232919):
    # the PINS scan runs first (an early return must never skip it); a broader
    # scope counts as coverage ONLY when every event carries a non-empty
    # command (an eventless or commandless broader entry is BROKEN config the
    # operator must fix - never papered over locally); a partial subset is
    # refused; full coverage retires the local pin (or fails loudly).
    pins = []
    for scope in ("--local", "--global", "--system"):
        rc, hp, _ = _git(repo, "config", scope, "--get", "core.hooksPath")
        if rc == 0 and hp:
            pins.append(("%s: %s" % (scope.lstrip("-"), hp)))
    broader = {}
    broken_broader = []
    for scope in ("--global", "--system"):
        for name, event, _cmd in _entries(suite):
            rc, evs, _ = _git(repo, "config", scope, "--get-all", "hook.%s.event" % name)
            if rc != 0 or event not in (evs or "").splitlines():
                continue
            cmd = _git(repo, "config", scope, "--get", "hook.%s.command" % name)[1]
            if not cmd:
                broken_broader.append("%s %s (no command)" % (scope.lstrip("-"), name))
                continue
            expected = {n: c for n, _e, c in _entries(suite)}[name]
            if not _command_matches(cmd, expected):
                # a command that is not EXACTLY ours (round gate_20261011-055123:
                # substring matches counted commands that merely mention the
                # certified path while invoking something else)
                broken_broader.append("%s %s (foreign launcher: %.60s...)"
                                       % (scope.lstrip("-"), name, cmd))
                continue
            broader.setdefault(scope, []).append(name)
    if broken_broader:
        return False, ("broader-scope config hooks are BROKEN: %s - fix that scope "
                       "before arming (an event with no command arms nothing)"
                       % ", ".join(broken_broader))
    if broader:
        where = {}
        for scope, ns in broader.items():
            for n in ns:
                where.setdefault(n, []).append(scope)
        overlapped = sorted(n for n, ss in where.items() if len(ss) > 1)
        if overlapped:
            # round gate_20261010-234231 HIGH: entries in MULTIPLE scopes run
            # the gate twice per event - never a silent success
            return False, ("config hooks for %s exist in MULTIPLE scopes - every "
                           "overlap double-runs the gate; unset the duplicate scope "
                           "entries first" % ", ".join(overlapped))
        names = set(where)
        all_names = {n for n, _e, _c in _entries(suite)}
        if names != all_names:
            return False, ("a broader scope arms only a SUBSET of the gate events "
                           "(%s of %d) - covered events would double-fire and the rest "
                           "run unarmed; make the scope arm every entry or none, then "
                           "retry" % (", ".join(sorted(names)), len(all_names)))
        if pins and not force:
            return False, ("already armed at a broader scope, but hooksPath pin(s) "
                           "[%s] would STACK (double paid review) - unset them (the "
                           "machine-wide migration's global swap) or pass force to "
                           "retire the LOCAL pin and accept the window"
                           % "; ".join(pins))
        scope = sorted(broader)[0]
        retired = ""
        rc_l, hp_local, _ = _git(repo, "config", "--local", "--get", "core.hooksPath")
        if rc_l == 0 and hp_local:
            urc, _, uerr = _git(repo, "config", "--local", "--unset", "core.hooksPath")
            if urc != 0:
                return False, ("already armed at %s scope, but the LOCAL hooksPath pin "
                               "'%s' cannot be unset (%s) - the hookdir shim would stack "
                               "(double review); unset it manually and re-verify"
                               % (scope.lstrip("-"), hp_local, uerr[:100]))
            retired = "; local hooksPath pin retired"
        # retire LOCAL config entries too (round gate_20261010-234905 HIGH:
        # local + broader entries both active double-run the gate - symmetric
        # with the pin retirement above) - VERIFIED unsets only (round
        # gate_20261011-000159 HIGH: a failed unset must not report success)
        leftovers = []
        for name, _e, _c in _entries(suite):
            for key in ("hook.%s.event" % name, "hook.%s.command" % name):
                rc, _, _err = _git(repo, "config", "--local", "--unset-all", key)
                if rc != 0 and _git(repo, "config", "--local", "--get-all", key)[0] == 0:
                    leftovers.append(key)
        if leftovers:
            return False, ("broader scope arms the gate but local entries could not "
                           "be removed (%s) - they would DOUBLE every review; remove "
                           "them manually and re-run" % ", ".join(leftovers))
        retired += "; local config entries retired"
        warn = ""
        still = [p for p in pins if not p.startswith("local:")]
        if still:
            warn = (" [WARNING: non-local hooksPath pin(s) active [%s] - DOUBLE REVIEW "
                    "until the global swap lands; see --runbook]" % "; ".join(still))
        return True, ("already armed via %s-scope config hooks (%d event(s))%s%s"
                      % (scope.lstrip("-"), len(names), retired, warn))
    if pins and not force:
        return False, ("refusing to stack config hooks over active hooksPath pin(s) "
                       "[%s] - config hooks run FIRST and every hookdir shim still "
                       "runs after, double-paying every review. The machine-wide "
                       "migration swaps the GLOBAL scope first (see --runbook); "
                       "force=True explicitly accepts the double-review window."
                       % "; ".join(pins))
    written = []
    touched = []
    # pre-existing LOCAL entries are snapshotted so a failed re-arm RESTORES
    # them - and ONLY them (round gate_20261010-234231 HIGH: restoring names
    # the loop never reached duplicated their surviving entries)
    prior = {}
    for name, _event, _cmd in _entries(suite):
        rc_e, evs, _ = _git(repo, "config", "--local", "--get-all", "hook.%s.event" % name)
        rc_c, cmds, _ = _git(repo, "config", "--local", "--get-all", "hook.%s.command" % name)
        prior[name] = ((evs.splitlines() if rc_e == 0 else []),
                       (cmds.splitlines() if rc_c == 0 else []))

    def _rollback():
        for key in written:
            _git(repo, "config", "--local", "--unset-all", key)
        for name in touched:
            evs, cmds = prior[name]
            for v in evs:
                _git(repo, "config", "--local", "--add", "hook.%s.event" % name, v)
            for v in cmds:
                _git(repo, "config", "--local", "--add", "hook.%s.command" % name, v)

    for name, event, cmd in _entries(suite):
        touched.append(name)
        _git(repo, "config", "--local", "--unset-all", "hook.%s.event" % name)
        _git(repo, "config", "--local", "--unset-all", "hook.%s.command" % name)
        rc, _, err = _git(repo, "config", "--local", "--add", "hook.%s.event" % name, event)
        if rc != 0:
            _rollback()
            return False, ("config write failed (hook.%s.event: %s) - partial entries "
                           "rolled back; the existing arming is untouched" % (name, err[:120]))
        written.append("hook.%s.event" % name)
        rc, _, err = _git(repo, "config", "--local", "--add", "hook.%s.command" % name, cmd)
        if rc != 0:
            _rollback()
            return False, ("config write failed (hook.%s.command: %s) - partial entries "
                           "rolled back; the existing arming is untouched" % (name, err[:120]))
        written.append("hook.%s.command" % name)
    for name, _ev, _cmd in _entries(suite):
        rc, evs, _ = _git(repo, "config", "--local", "--get-all", "hook.%s.event" % name)
        cmd = _git(repo, "config", "--local", "--get", "hook.%s.command" % name)[1]
        if rc != 0 or not cmd:
            _rollback()
            return False, ("post-write verification failed for %s - rolled back" % name)
    if pins and pins[0].startswith("local:"):
        urc, _, uerr = _git(repo, "config", "--local", "--unset", "core.hooksPath")
        if urc != 0:
            _rollback()
            return False, ("could not unset the local hooksPath pin (%s) - config hooks "
                           "rolled back; the pin's arming stands" % uerr[:120])
    note = ""
    still = [p for p in pins if not p.startswith("local:")]
    if still:
        note = (" [WARNING: non-local hooksPath pin(s) still active [%s] - DOUBLE REVIEW "
                "until the global swap lands; see --runbook]" % "; ".join(still))
    return True, ("armed via config hooks (%d event(s) -> %s)%s"
                  % (len(EVENTS), launcher_path(suite), note))


def disarm(repo, suite=DEFAULT_SUITE):
    """Remove the gate's config-hook entries. Every unset's outcome is
    VERIFIED (round gate_20261010-224546 MEDIUM: discarded return codes
    reported a false OK while the entries survived) - a key that cannot be
    removed fails the disarm with the survivors named."""
    failed = []
    for name, _ev, _cmd in _entries(suite):
        for key in ("hook.%s.event" % name, "hook.%s.command" % name):
            rc, _, _err = _git(repo, "config", "--local", "--unset-all", key)
            if rc != 0 and _git(repo, "config", "--local", "--get-all", key)[0] == 0:
                failed.append(key)
    if failed:
        return False, ("could not remove config hook entries: %s - arming state "
                       "UNVERIFIED; inspect git config --local --list" % ", ".join(failed))
    # broader-scope entries SURVIVE a local disarm (round gate_20261010-232919
    # HIGH: reporting plain success would lie) - name them and fail honestly.
    surviving = []
    for scope in ("--global", "--system"):
        for name, event, _cmd in _entries(suite):
            rc, evs, _ = _git(repo, "config", scope, "--get-all", "hook.%s.event" % name)
            if rc != 0 or event not in (evs or "").splitlines():
                continue
            cmd = _git(repo, "config", scope, "--get", "hook.%s.command" % name)[1]
            # only EXACTLY-our entries block the disarm (a commandless or
            # foreign command arms nothing of ours - rounds
            # gate_20261010-235540 + gate_20261011-055810); the '"$1"' legacy
            # token tolerance is _command_matches (round 133017 finding 2)
            expected = {n: c for n, _e, c in _entries(suite)}[name]
            if not cmd or not _command_matches(cmd, expected):
                continue
            surviving.append("%s %s" % (scope, name))
    if surviving:
        return False, ("local entries removed, but broader-scope hooks still ARM the "
                       "gate: %s - disarm at that scope (e.g. git config %s --unset-all "
                       "%s) or leave it armed"
                       % (", ".join(surviving), surviving[0].split()[0],
                          "hook.adversary-pre-commit.event"))
    rc_local, hp_local, _ = _git(repo, "config", "--local", "--get", "core.hooksPath")
    rc_global, hp_global, _ = _git(repo, "config", "--global", "--get", "core.hooksPath")
    rc_sys, hp_sys, _ = _git(repo, "config", "--system", "--get", "core.hooksPath")
    if rc_local == 0 and hp_local:
        return True, "config hooks removed (repo falls back to its local hooksPath pin)"
    if rc_global == 0 and hp_global:
        return True, ("config hooks removed (repo falls back to the GLOBAL hooksPath "
                      "'%s')" % hp_global)
    if rc_sys == 0 and hp_sys:
        return True, ("config hooks removed (repo falls back to the SYSTEM hooksPath "
                      "'%s')" % hp_sys)
    return True, ("config hooks removed and NO hooksPath remains - the repo is now "
                  "UNARMED; re-arm with install_gate.py")


_HP = "core.ho" + "oksPath"


def runbook():
    """The exact machine-wide migration steps (owner-executed or a dedicated session; layout-derived)."""
    return """
MACHINE-WIDE CONFIG-HOOKS MIGRATION (git 2.54+; verified semantics: config
hooks fire first, every active hookdir shim runs after -> never stack them;
arm() enforces this across local/global/system scopes). The four entries and
their exact commands come from THIS MODULE (`python config_hooks.py --status`
prints them) - arm them with those exact bytes, not hand-typed guesses.
<GATE> below is this module's directory name ("adversary-gate" at the author
suite, "tools" in a plugin distribution).
1. GLOBAL scope swap FIRST (owner; record the old value for rollback) - until
   this lands, per-repo config arming would double-pay every review:
     git config --global --get %s        # RECORD THIS
     git config --global --unset %s
   (for each NAME/EVENT/COMMAND printed by --status:)
       git config --global --add hook.NAME.event EVENT
       git config --global --add hook.NAME.command COMMAND
   NOTE: there are FOUR entries (pre-commit, post-commit record,
   post-commit activate, pre-push) - arming a subset makes arm() refuse.
   Rollback: re-set the recorded global hooksPath and unset the hook.* keys.
2. Per armed repo (census lists them), retiring each LOCAL pin safely:
     python -I -B <suite>/<GATE>/config_hooks.py --arm <repo> --force
   (--force accepts that a local pin is retired only AFTER every config entry
   is written and verified; failures roll back and leave the pin armed.)
3. Pilot ONE repo; verify a commit fires the gate exactly once and the
   post-commit output shows BOTH the notarization and the activate install.
4. Re-run the census until every row is config-armed.
""" % (_HP, _HP)


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="Config-based hooks arming (git 2.54+).")
    ap.add_argument("repo", nargs="?")
    ap.add_argument("--arm", action="store_true")
    ap.add_argument("--disarm", action="store_true")
    ap.add_argument("--force", action="store_true",
                    help="unset a pinned repo hooksPath before arming (never stack)")
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--suite", default=DEFAULT_SUITE,
                    help="the gate suite whose certified launch.py arms the hooks "
                         "(default: this repo's own suite path)")
    ap.add_argument("--runbook", action="store_true")
    a = ap.parse_args(argv)
    if a.runbook:
        print(runbook())
        return 0
    if not a.repo:
        ap.error("repo is required (or --runbook)")
    if a.status or not (a.arm or a.disarm):
        rows = arming(a.repo, suite=a.suite)
        print("config hooks: %s | capability: %s"
              % (rows if rows else "(none armed)", capability(a.repo)))
        return 0 if rows else 1
    ok, msg = (arm(a.repo, suite=a.suite, force=a.force) if a.arm
               else disarm(a.repo, suite=a.suite))
    print(("OK: " if ok else "FAIL: ") + msg)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
