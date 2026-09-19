"""install_gate.py - arm the MANDATORY adversarial commit gate (G39) on any git repo.

Agent-runnable (local subagent, external headless session, or a human), idempotent,
stdlib-only. It copies the CANONICAL shims (`adversary-gate/pre-commit` and
`adversary-gate/post-commit`, the single sources of truth - deliberately NOT embedded
here, so there is exactly one copy of each that can never drift) into
`<repo>/.githooks/` with LF newlines enforced, VENDORS the self-contained audit
tripwire (`adversary_audit.py`) beside them so CI can run it without the Tools repo,
anchors the tripwire with `.githooks/adversary_baseline` (= HEAD at first install;
never moved by a re-run - earlier commits had only transient clearances), sets
`notes.rewriteRef refs/notes/adversary` (rebases/amends carry notes to rewritten
commits), pins everything LF *durably* via `.githooks/.gitattributes` (autocrlf
checkouts would otherwise hand /bin/sh a CRLF script later), marks the hooks
executable for POSIX clones, sets `core.hooksPath .githooks` in that clone, and
verifies every claim it makes by reading the result back - including that the gate
tool the SHIMS exec actually exists on this machine (a missing tool means
fail-closed lockout, not an arming).

Usage:
  python install_gate.py <repo-path>                 install + verify (idempotent)
  python install_gate.py <repo-path> --verify-only   report ARMED/UNARMED, change nothing
  python install_gate.py <repo-path> --force         overwrite a DIFFERENT existing
                                                     .githooks/pre-commit, or re-point a
                                                     core.hooksPath set to something else

Exit codes (automation keys on these):
  0 = armed AND functional (shim canonical, hooksPath set, gate tool present)
  3 = armed but FAIL-CLOSED: the gate tool the shim execs is missing on this machine,
      so every commit is refused and none can clear - a lockout, not a working gate
  1 = anything else (not armed / not a repo / conflict without --force / verify failed)

The installer NEVER commits. The arming commit stages `.githooks/pre-commit`, which
the gate itself always gates - so the driver's closing sequence is the proof the hook
fires in this clone: stage the shims, optionally `adversary_gate.py run --context ...`
(the automatic review carries no context), then commit and EXPECT the gate to speak -
since 9597241 (2026-09-07) `check` requests the review itself ("ADVERSARY GATE:
requesting automatic independent review of staged changes.") or re-checks an existing
clearance; CLEAR lands + notarizes, BLOCK refuses; a code commit that lands silently
means the hook did not run. Docs: colibri-code-review/docs/GATE_INSTALLER.md.
"""
import argparse
import os
import re
import subprocess
import sys

GIT = r"C:\Program Files\Git\cmd\git.exe"
if not os.path.isfile(GIT):
    GIT = "git"                                    # non-standard machine: rely on PATH
HERE = os.path.dirname(os.path.abspath(__file__))
CANON = os.path.join(HERE, "pre-commit")
CANON_POST = os.path.join(HERE, "post-commit")
CANON_PREPUSH = os.path.join(HERE, "pre-push")
AUDITOR = os.path.join(HERE, "adversary_audit.py")
NOTES_REF = "refs/notes/adversary"
# 2026-09-06 (owner order: arming is UNIVERSAL): the machine-wide DISPATCHER hook dir. It is
# git's GLOBAL core.hooksPath on the owner's machine (set by the owner) and the ABSOLUTE value
# this installer pins per repo - a relative `.githooks` value dangles in a worktree whose branch
# predates the vendored hooks and git then runs NO hook at all (probed; two live cases found).
CANON_HOOKS_DIR = os.path.join(HERE, "hooks").replace("\\", "/")
HOOKS_KEY = "core.hooksPath"            # the one config key this installer reads and writes
DEFAULT_CENSUS_ROOTS = [
    r"C:\Users\User\source\repos",
    os.path.join(os.environ.get("CODEX_HOME", os.path.expanduser("~/.codex")), "worktrees"),
    r"C:\Users\User\Documents\codex",
]
# LF pins written into the target's .githooks/.gitattributes (sh rejects CRLF shims;
# the auditor + baseline are pinned too so vendored bytes stay deterministic)
ATTR_LINES = ("pre-commit text eol=lf", "post-commit text eol=lf",
              "pre-push text eol=lf",
              "adversary_audit.py text eol=lf", "adversary_baseline text eol=lf",
              "adversary_rules_epoch text eol=lf")


def _git(repo, *args):
    # GIT_NO_REPLACE_OBJECTS like the gate and the auditor (Tools D gate round 4,
    # gate_20260906-221844): a local `git replace` must not steer the epoch report or the
    # re-anchor target away from what the protected walkers judge
    try:
        p = subprocess.run([GIT, "-C", repo] + list(args), capture_output=True,
                           env=dict(os.environ, GIT_NO_REPLACE_OBJECTS="1"))
    except FileNotFoundError:
        return 127, "", "git executable not found (looked for %s and PATH)" % GIT
    return p.returncode, p.stdout.decode("utf-8", "replace").strip(), \
        p.stderr.decode("utf-8", "replace").strip()


def _canonical_shim(path=CANON):
    """Canonical shim bytes, LF-normalized (a CRLF checkout of the Tools repo must
    never install a shim /bin/sh chokes on), with the GATE= line SUBSTITUTED to point
    at THIS installer's own adversary_gate.py - so a relocated copy of the suite (a
    distributed plugin, another checkout path) installs shims that exec ITS gate
    instead of a path that only exists on the authoring machine. On the authoring
    machine the substitution reproduces the template bytes exactly (HERE == the
    template's own directory). Sanity-checked so a mangled canonical can't propagate."""
    if not os.path.isfile(path):
        raise SystemExit("FAIL: canonical shim missing at %s" % path)
    raw = open(path, "rb").read().replace(b"\r\n", b"\n")
    if not raw.startswith(b"#!/bin/sh") or b"adversary_gate.py" not in raw:
        raise SystemExit("FAIL: canonical shim at %s does not look like the gate shim - "
                         "refusing to propagate it" % path)
    gate_line = ('GATE="%s"' % os.path.join(HERE, "adversary_gate.py")
                 .replace("\\", "/")).encode("utf-8")
    raw, n = re.subn(rb'(?m)^GATE=".*"$', gate_line.replace(b"\\", b"\\\\"), raw)
    if n != 1:
        raise SystemExit("FAIL: canonical shim at %s has %d GATE= lines (expected "
                         "exactly 1) - refusing to propagate it" % (path, n))
    return raw


def _canonical_auditor():
    """Vendorable auditor bytes, LF-normalized + sanity-checked (same reasoning as the
    shims: exactly one canonical copy, refreshed on every install run)."""
    if not os.path.isfile(AUDITOR):
        raise SystemExit("FAIL: canonical auditor missing at %s" % AUDITOR)
    raw = open(AUDITOR, "rb").read().replace(b"\r\n", b"\n")
    if b"adversary_audit" not in raw or b"_audit_commit" not in raw:
        raise SystemExit("FAIL: %s does not look like the adversary auditor - refusing "
                         "to vendor it" % AUDITOR)
    return raw


def _bytes_state(root, rel, want):
    """'canonical' = raw bytes equal; 'crlf' = equal only after CRLF normalization
    (never blessed - see the pre-commit rationale); 'different'; 'absent'."""
    p = os.path.join(root, ".githooks", rel)
    if not os.path.isfile(p):
        return "absent"
    raw = open(p, "rb").read()
    if raw == want:
        return "canonical"
    if raw.replace(b"\r\n", b"\n") == want:
        return "crlf (CRLF endings; re-run the installer)"
    return "different"


def _shim_gate_path(canon):
    """The gate-tool path the shim itself will exec - THAT path (on the machine being
    armed), not this installer's own neighbor, is what decides whether commits can
    ever clear (adversary finding, installer birth review)."""
    for line in canon.decode("utf-8", "replace").splitlines():
        if line.startswith('GATE="') and line.rstrip().endswith('"'):
            return line.strip()[len('GATE="'):-1]
    return None


def _hooks_equivalent(hp, root):
    """True when an existing core.hooksPath already denotes an ARMING value: <root>/.githooks
    in ANY spelling (relative, './'-prefixed, trailing slash, absolute), or - since
    2026-09-06 - the machine-wide canonical dir CANON_HOOKS_DIR in any spelling. A literal
    string mismatch alone is not 'foreign' (adversary finding, installer birth review r3)."""
    if not hp:
        return False
    p = hp.replace("\\", "/").rstrip("/")
    if not os.path.isabs(p):
        p = os.path.join(root, p)
    norm = os.path.normcase(os.path.normpath(p))
    return norm in (os.path.normcase(os.path.normpath(os.path.join(root, ".githooks"))),
                    os.path.normcase(os.path.normpath(CANON_HOOKS_DIR)))


def _is_canonical_dir(hp):
    """The value IS the machine-wide dispatcher dir (absolute; resolves in every checkout)."""
    if not hp:
        return False
    p = hp.replace("\\", "/").rstrip("/")
    return os.path.isabs(p) and (os.path.normcase(os.path.normpath(p))
                                 == os.path.normcase(os.path.normpath(CANON_HOOKS_DIR)))


DISPATCHERS = ("pre-commit", "post-commit", "pre-push")


def _dispatchers_ok(hooks_dir=None):
    """The dispatcher dir the absolute pin names must EXIST with all three shims - pinning a
    missing dir arms nothing (git runs no hook) while every reporter says ARMED (gate round 3,
    gate_20260906-170958: a relocated suite copy without hooks/ did exactly that)."""
    d = hooks_dir or CANON_HOOKS_DIR
    return all(os.path.isfile(os.path.join(d, n)) for n in DISPATCHERS)


def _dispatchers_state():
    """'canonical' | 'tampered' | 'missing' | 'unverifiable'. The dispatchers EXECUTE from the
    suite's working tree (gate round 5, gate_20260906-173424): each must be tracked in the
    suite's git checkout and byte-identical to its committed HEAD blob - the same parity the
    vendored shim always had with its canonical. A suite that is not a git checkout (a plain
    plugin copy) has no reviewed reference: reported, never blessed as canonical."""
    if not _dispatchers_ok():
        return "missing"
    rc, top, _ = _git(HERE, "rev-parse", "--show-toplevel")
    if rc != 0:
        return "unverifiable"
    for n in DISPATCHERS:
        rel = os.path.relpath(os.path.join(CANON_HOOKS_DIR, n), top).replace("\\", "/")
        rc_t, _, _ = _git(top, "ls-files", "--error-unmatch", rel)
        rc_d, _, _ = _git(top, "diff", "--quiet", "HEAD", "--", rel)
        if rc_t != 0 or rc_d != 0:
            return "tampered"
    return "canonical"


def _dangling(hp, root):
    """An arming value that resolves to NOTHING in this checkout: a relative dir that does not
    exist here (worktrees on pre-vendoring branches - probe 2026-09-06) or an absolute dir
    that is missing or lacks its pre-commit (moved/partial suite copy). Git then runs no hook
    and the commit succeeds."""
    if not hp:
        return False
    p = hp.replace("\\", "/").rstrip("/")
    if not os.path.isabs(p):
        return not os.path.isdir(os.path.join(root, p))
    if not os.path.isdir(p):
        return True
    # OUR canonical dir needs ALL three layers: one that kept pre-commit but lost pre-push or
    # post-commit runs no push guard and no notary while looking armed (gate round 4); an
    # existing FOREIGN absolute dir is another hook system, not dangling (gate round 5 LOW)
    return _is_canonical_dir(p) and not _dispatchers_ok(p)


def _global_hooks_value():
    _, v, _ = _git(HERE, "config", "--global", HOOKS_KEY)
    return v


def _is_worktree(root):
    return os.path.isfile(os.path.join(root, ".git"))


def _epoch_state(root):
    """(sha, state, intro): the rules epoch as the auditor judges it (mirror of
    adversary_audit._epoch): 'none' | 'ok' | 'moved'. A recorded sha that is not an ancestor of
    the commit that FIRST added the epoch file is MOVED - a later rewrite (attack) or a
    squash/cherry-pick vendoring flow (Tools D gate round 1, LOW) - and the auditor then applies
    the hook-name rule to every commit and reports a violation (fail closed)."""
    # HEAD's tree only, like the auditor (Tools E gate round 1): the working-tree file is what
    # the installer just wrote; until it is committed the state is 'uncommitted'
    p = os.path.join(root, ".githooks", "adversary_rules_epoch")
    rc0, blob, _ = _git(root, "show", "HEAD:.githooks/adversary_rules_epoch")
    if rc0 != 0:
        return None, ("uncommitted" if os.path.isfile(p) else "none"), []
    sha = None
    for ln in blob.splitlines():
        parts = ln.split()
        if len(parts) == 2 and parts[0] == "hook-names":
            sha = parts[1]
    if not sha:
        return None, "none", []
    if sha == "ROOT":
        return sha, "ok", []                             # armed at birth: anchored below every commit
    # order-independent, full history (Tools D gate round 2): the sha must be an ancestor of
    # EVERY add; the third element is the list of adds (for --reanchor-epoch)
    rc_s, shallow, _ = _git(root, "rev-parse", "--is-shallow-repository")
    if rc_s != 0 or shallow.strip() == "true":
        return sha, "unreadable", []                     # shallow clone: ancestry unjudgeable
    rc, out, _ = _git(root, "log", "--full-history", "--diff-filter=A", "--format=%H", "--",
                      ":(top).githooks/adversary_rules_epoch")
    if rc != 0:
        return sha, "unreadable", []
    adds = out.split()
    if not adds:
        return sha, "unreadable", []                     # in HEAD's tree yet no add = truncation
    for add in adds:
        rc2, _, _ = _git(root, "merge-base", "--is-ancestor", sha, add)
        if rc2 != 0:
            return sha, "moved", adds
    return sha, "ok", adds


def _assess(root, canon, canon_post, canon_prepush, canon_aud):
    """ONE judgement of a checkout, shared by --verify-only and --census so the two reporters
    can never disagree (gate rounds 2-3). Returns a dict; `state` is one of:
      armed      - the effective hooks value is an arming value that RESOLVES here, the
                   vendored .githooks/ bytes are canonical (or absent on a pre-vendoring branch
                   under the canonical dir), baseline + rewriteRef present
      stale      - the hook layer is armed but vendored bytes / baseline / rewriteRef are not
                   canonical (re-run the installer, commit .githooks/)
      dangling   - the value resolves to nothing here: git runs NO hook
      unset      - no local and no global value
      overridden - another hook system's value"""
    hp, shim_state = _state(root, canon)
    gv = _global_hooks_value()
    eff = hp or gv
    post_state = _bytes_state(root, "post-commit", canon_post)
    prepush_state = _bytes_state(root, "pre-push", canon_prepush)
    aud_state = _bytes_state(root, "adversary_audit.py", canon_aud)
    base_path = os.path.join(root, ".githooks", "adversary_baseline")
    # armed at birth (2026-09-08): the installer writes ROOT on an empty repo, so a missing
    # baseline is unarmed even before the first commit
    base_ok = os.path.isfile(base_path)
    _, rref, _ = _git(root, "config", "notes.rewriteRef")
    _, rmode, _ = _git(root, "config", "notes.rewriteMode")
    rref_ok = rref == NOTES_REF and rmode == "ignore"   # a concatenating rebase corrupts notes: stale
    layer3 = (post_state == "canonical" and prepush_state == "canonical"
              and aud_state == "canonical" and base_ok and rref_ok)
    dangling = _dangling(eff, root)
    # the dispatchers this checkout would EXECUTE (only when the pin names our canonical dir)
    # must match their committed blobs - a working-tree edit there is 'tampered', never armed
    disp = _dispatchers_state() if _is_canonical_dir(eff) else "n/a"
    tampered = disp == "tampered"
    # A PRESENT vendored shim must still be canonical bytes (birth-review r5): the canonical
    # dir carries the arming ONLY when .githooks/ is absent here (pre-vendoring branch).
    vendored_absent = _is_canonical_dir(eff) and shim_state == "absent"
    hook_layer = _hooks_equivalent(eff, root) and not dangling and not tampered and (
        shim_state == "canonical" or vendored_absent)
    armed = hook_layer and (layer3 or (vendored_absent and rref_ok))
    # dangling before overridden: a value that resolves to NOTHING is the actionable fact
    # whatever it was meant to be (gate round 4 LOW - a deleted relocated suite's pin)
    if not eff:
        state = "unset"
    elif dangling:
        state = "dangling"
    elif not _hooks_equivalent(eff, root):
        state = "overridden"
    elif tampered:
        state = "tampered"
    elif armed:
        state = "armed"
    else:
        state = "stale"
    return {"hp": hp, "gv": gv, "eff": eff, "shim_state": shim_state, "post_state": post_state,
            "prepush_state": prepush_state, "aud_state": aud_state, "base_ok": base_ok,
            "rref": rref, "rmode": rmode, "rref_ok": rref_ok, "layer3": layer3, "dangling": dangling,
            "vendored_absent": vendored_absent, "hook_layer": hook_layer, "armed": armed,
            "dispatchers": disp, "state": state}


def _warn(msg):
    print("WARN: " + msg)


def _legacy_hooks(root):
    """Real (non-sample) hooks in the repo's DEFAULT hook dir ($GIT_DIR/hooks) -
    core.hooksPath will BYPASS them, which the operator must know about. Deliberately
    NOT `rev-parse --git-path hooks`: that honors an already-set core.hooksPath and
    would list our own installed .githooks/ as 'legacy' (false warning on re-runs)."""
    rc, gitdir, _ = _git(root, "rev-parse", "--git-dir")
    if rc != 0:
        return []
    gitdir = gitdir if os.path.isabs(gitdir) else os.path.join(root, gitdir)
    hookdir = os.path.join(gitdir, "hooks")
    if not os.path.isdir(hookdir):
        return []
    return sorted(n for n in os.listdir(hookdir)
                  if not n.endswith(".sample") and os.path.isfile(os.path.join(hookdir, n)))


def _npm_hook_manager(root):
    """Husky-style managers re-point core.hooksPath on `npm install`, silently
    disarming the gate later. Detection only - the fix is a human decision."""
    pj = os.path.join(root, "package.json")
    if not os.path.isfile(pj):
        return None
    try:
        text = open(pj, encoding="utf-8", errors="replace").read()
    except OSError:
        return None
    for marker in ("husky", "simple-git-hooks", "lefthook", "core.hooksPath"):
        if marker in text:
            return marker
    return None


def _state(root, canon):
    """(hooks_path, shim_state): 'canonical' = RAW bytes equal; 'crlf' = equal only after
    CRLF normalization (/bin/sh rejects such a script, so this is a BROKEN shim the
    verifier must never bless as canonical - adversary finding, birth review r5);
    'different'; 'absent'."""
    # --local: the GLOBAL value (the owner's machine-wide dispatcher dir) is a default, not this
    # clone's setting - reading the effective value made the installer refuse every fresh
    # repo on the owner's machine as 'another hook system' (hooks_selftest row 5, 2026-09-06).
    _, hp, _ = _git(root, "config", "--local", HOOKS_KEY)
    shim = os.path.join(root, ".githooks", "pre-commit")
    if not os.path.isfile(shim):
        return hp, "absent"
    raw = open(shim, "rb").read()
    if raw == canon:
        return hp, "canonical"
    if raw.replace(b"\r\n", b"\n") == canon:
        return hp, "crlf (CRLF endings - /bin/sh rejects this; re-run the installer)"
    return hp, "different"


def _checkouts_under(roots):
    """Every git checkout (clone or worktree) that IS a root or sits directly under one, plus
    every worktree each of them lists (Codex / VS Code worktrees live outside the repo dir)."""
    seen, out = set(), []

    def add(path):
        n = os.path.normcase(os.path.normpath(path))
        if n not in seen and os.path.exists(os.path.join(path, ".git")):
            seen.add(n)
            out.append(path)

    for r in roots:
        if not os.path.isdir(r):
            continue
        add(r)
        for d in sorted(os.listdir(r)):
            add(os.path.join(r, d))
    for path in list(out):
        rc, lst, _ = _git(path, "worktree", "list", "--porcelain")
        if rc == 0:
            for ln in lst.splitlines():
                if ln.startswith("worktree "):
                    add(ln[len("worktree "):])
    return out


def census(roots):
    """One row per checkout, judged by the SAME _assess() as --verify-only (gate round 3: the
    two reporters must agree on byte state too). state: armed | stale | dangling | unset |
    overridden. Reads config through git, never through a shell line."""
    canon = _canonical_shim()
    canon_post = _canonical_shim(CANON_POST)
    canon_prepush = _canonical_shim(CANON_PREPUSH)
    canon_aud = _canonical_auditor()
    rows = []
    for path in _checkouts_under(roots):
        rc, root, _ = _git(path, "rev-parse", "--show-toplevel")
        if rc != 0:
            continue
        s = _assess(root, canon, canon_post, canon_prepush, canon_aud)
        _, head, _ = _git(root, "rev-parse", "--short", "HEAD")
        _, br, _ = _git(root, "rev-parse", "--abbrev-ref", "HEAD")
        src = "local" if s["hp"] else ("global" if s["gv"] else "none")
        rows.append({"path": root, "kind": "worktree" if _is_worktree(root) else "clone",
                     "head": head or "-", "branch": br or "-", "state": s["state"],
                     "value": s["eff"], "source": src})
    return rows


def main(argv=None):
    ap = argparse.ArgumentParser(description="Arm the adversarial commit gate on a git repo.")
    ap.add_argument("repo", nargs="?", help="path to (or inside) the target working copy")
    ap.add_argument("--verify-only", action="store_true",
                    help="report ARMED/UNARMED and exit; change nothing")
    ap.add_argument("--force", action="store_true",
                    help="overwrite a different existing shim / re-point a foreign hooksPath")
    ap.add_argument("--census", nargs="*", metavar="ROOT",
                    help="report the arming state of EVERY checkout and worktree under the "
                         "roots (default: the owner's repo roots) and exit 0 only when all are "
                         "armed; change nothing")
    ap.add_argument("--reanchor-epoch", action="store_true",
                    help="owner recovery for a MOVED rules epoch (squash/cherry-pick vendoring): "
                         "rewrite it to the parent of the commit that first added the epoch file "
                         "- sound by construction, never later than the current value's intent; "
                         "refuses to touch a sound epoch (it must never move one forward)")
    a = ap.parse_args(argv)

    if a.census is not None:
        roots = a.census or DEFAULT_CENSUS_ROOTS
        rows = census(roots)
        if not rows:
            # gate round 2 LOW: inspecting nothing is not "all armed"
            print("census: NO CHECKOUTS found under %s - nothing inspected, refusing to report "
                  "success" % ", ".join(roots))
            return 2
        for r in rows:
            print("%-10s %-8s %-9s %-28s %s%s" % (
                r["state"], r["kind"], r["head"], r["branch"][:28], r["path"],
                "" if r["state"] == "armed" else
                "   [%s value: %s]" % (r["source"], r["value"] or "(none)")))
        bad = [r for r in rows if r["state"] != "armed"]
        print("\ncensus: %d checkout(s), %d not armed (global hooksPath: %s)"
              % (len(rows), len(bad), _global_hooks_value() or "(unset)"))
        return 1 if bad else 0
    if not a.repo:
        ap.error("repo is required unless --census is given")

    rc, root, err = _git(os.path.abspath(a.repo), "rev-parse", "--show-toplevel")
    if rc != 0:
        print("FAIL: %s is not inside a git working copy (%s)" % (a.repo, err[:200]))
        return 1
    canon = _canonical_shim()
    canon_post = _canonical_shim(CANON_POST)
    canon_prepush = _canonical_shim(CANON_PREPUSH)
    canon_aud = _canonical_auditor()
    hp, shim_state = _state(root, canon)

    gate_path = _shim_gate_path(canon)
    gate_ok = bool(gate_path) and os.path.isfile(gate_path)

    if a.reanchor_epoch:
        ep_sha, ep_state, adds = _epoch_state(root)
        if ep_state != "moved":
            print("FAIL: the rules epoch is %s - nothing to re-anchor (a sound epoch is never "
                  "moved; --reanchor-epoch is the recovery for a MOVED one only; an unreadable "
                  "history - a shallow clone - cannot be re-anchored soundly: use a full clone)"
                  % ep_state)
            return 1
        # the target must be an ancestor of EVERY add (order-independent, like the check):
        # the common ancestor of all the adds' parents; a root-commit add contributes itself
        parents = []
        for add in adds:
            rc, par, _ = _git(root, "rev-parse", "--verify", "--quiet", add + "^")
            parents.append(par if rc == 0 and par else add)
        if len(parents) == 1:
            target = parents[0]
        else:
            # criss-cross ancestry can print SEVERAL candidates: any one is a common ancestor,
            # take the first and validate it is a single sha (round 4 LOW)
            rc, out, _ = _git(root, "merge-base", "--octopus", *parents)
            target = (out.split() or [""])[0]
            if rc != 0 or not re.fullmatch(r"[0-9a-f]{40}", target):
                print("FAIL: the adds of the epoch file have no common ancestor - cannot re-anchor "
                      "soundly; the owner rules")
                return 1
        p = os.path.join(root, ".githooks", "adversary_rules_epoch")
        with open(p, "wb") as f:
            f.write(("hook-names %s\n" % target).encode("utf-8"))
        print("REANCHORED: rules epoch %s -> %s (common ancestor of the parents of every commit "
              "that added the epoch file: %s). Commit .githooks/adversary_rules_epoch through the "
              "gate." % ((ep_sha or "?")[:12], target[:12], ", ".join(a[:12] for a in adds)))
        return 0

    if a.verify_only:
        s = _assess(root, canon, canon_post, canon_prepush, canon_aud)
        ep_sha, ep_state, ep_adds = _epoch_state(root)
        armed, gv, eff = s["armed"], s["gv"], s["eff"]
        head = ("ARMED" if gate_ok else "ARMED (FAIL-CLOSED - gate tool missing)") \
            if armed else "UNARMED"
        print("%s  %s  [%s]" % (head, root, s["state"]))
        print("  core.hooksPath : %s" % (hp or ("(unset - GLOBAL applies: %s)" % gv if gv
                                                else "(unset)")))
        print("  global hooksPath : %s" % (gv or "(unset)"))
        dstate = _dispatchers_state()
        print("  dispatchers    : %s" % {
            "canonical": "canonical at %s (tracked, identical to the committed blobs)" % CANON_HOOKS_DIR,
            "tampered": "TAMPERED at %s (differs from the committed blob or untracked - every "
                        "pinned repo fails CLOSED until it is committed through the gate)" % CANON_HOOKS_DIR,
            "missing": "MISSING at %s (an absolute pin to this dir arms NOTHING - the suite copy "
                       "is incomplete)" % CANON_HOOKS_DIR,
            "unverifiable": "present at %s but the suite is not a git checkout - no reviewed "
                            "reference to verify the bytes against" % CANON_HOOKS_DIR,
        }[dstate])
        if s["state"] == "tampered":
            print("  TAMPERED       : the dispatcher bytes this checkout executes differ from "
                  "their committed blobs - commit them through the gate (Tools repo) first")
        if s["dangling"]:
            print("  DANGLING       : the value %r resolves to nothing in this checkout - git runs "
                  "NO hook here (a worktree on a pre-vendoring branch, or a moved/partial suite "
                  "copy); re-run the installer from a complete suite on the main checkout" % eff)
        if armed and not s["layer3"]:
            print("  WARN           : vendored .githooks/ is absent in THIS checkout (branch "
                  "predates vendoring): the commit gate and notary are armed by the canonical "
                  "dir, but the push guard has NO baseline here - push from the main checkout, "
                  "or re-run the installer on this branch and commit .githooks/")
        if s["state"] == "stale":
            print("  STALE          : the hook layer is armed but the vendored .githooks/ bytes, "
                  "baseline, rewriteRef or rewriteMode are not canonical - re-run the installer "
                  "and commit .githooks/")
        print("  shim           : %s" % s["shim_state"])
        print("  gate tool      : %s" % ("present at " + gate_path if gate_ok else
                                         "MISSING at %s (hook fails CLOSED - no commit "
                                         "can clear)" % (gate_path or "?")))
        print("  post-commit    : %s" % s["post_state"])
        print("  pre-push       : %s" % s["prepush_state"])
        print("  auditor        : %s" % s["aud_state"])
        print("  baseline       : %s" % ("present" if s["base_ok"] else "ABSENT (tripwire "
                                         "cannot anchor - re-run the installer)"))
        print("  rewriteRef     : %s" % (s["rref"] or "(unset - rebases will orphan notes)"))
        print("  rewriteMode    : %s" % (s["rmode"] or "(unset - git concatenates a copied note onto the "
                                                         "notary's fresh one on rebase; re-run the installer)"))
        print("  epoch          : %s" % {
            "none": "(none - the hook-name rule applies to every commit)",
            "uncommitted": "uncommitted (written by the installer, not yet in HEAD's tree) - the "
                           "hook-name rule applies to every commit until .githooks/ is committed",
            "ok": "ok (hook-names %s, anchored)" % (ep_sha or "?")[:12],
            "moved": "MOVED (hook-names %s is not an ancestor of every commit that added the "
                     "epoch file: %s) - the auditor applies the rule to every commit and reports a "
                     "violation; a squash/cherry-pick vendoring flow does this: recover with "
                     "--reanchor-epoch" % ((ep_sha or "?")[:12], ", ".join(a[:12] for a in ep_adds)),
            "unreadable": "UNREADABLE (git log failed) - the auditor applies the rule to every commit",
        }[ep_state])
        return (0 if gate_ok else 3) if armed else 1

    # -------- the absolute pin must name a dir that EXISTS with all three dispatchers, or it
    # arms nothing while every reporter says ARMED (gate round 3, MEDIUM-HIGH). Refuse first.
    if not _dispatchers_ok():
        print("FAIL: the canonical dispatcher dir %s is missing one of %s - pinning it would arm "
              "NOTHING (git runs no hook for a missing dir). This suite copy is incomplete: "
              "restore adversary-gate/hooks/ (Tools repo) and re-run."
              % (CANON_HOOKS_DIR, "/".join(DISPATCHERS)))
        return 1
    if _dispatchers_state() == "tampered":
        print("FAIL: a dispatcher in %s is TAMPERED (differs from its committed blob, or is "
              "untracked) - pinning it would execute unreviewed bytes in this repo. Commit the "
              "dispatcher through the gate (Tools repo) first, or restore it (git checkout)."
              % CANON_HOOKS_DIR)
        return 1

    # -------- conflicts that need a conscious decision, not a silent overwrite
    if hp and not _hooks_equivalent(hp, root) and not a.force:
        print("FAIL: core.hooksPath is already '%s' (another hook system?). "
              "Re-run with --force to re-point it to the canonical dispatcher dir %s."
              % (hp, CANON_HOOKS_DIR))
        return 1
    if shim_state == "different" and not a.force:
        print("FAIL: %s exists with DIFFERENT content than the canonical shim. "
              "Re-run with --force to overwrite it." % os.path.join(root, ".githooks", "pre-commit"))
        return 1

    # -------- warnings (installation proceeds; the operator must still know)
    legacy = _legacy_hooks(root)
    if legacy:
        _warn("existing hook(s) in the default hook dir will be BYPASSED by "
              "core.hooksPath: %s" % ", ".join(legacy))
    mgr = _npm_hook_manager(root)
    if mgr:
        _warn("package.json mentions '%s' - an npm-managed hook setup can re-point "
              "core.hooksPath on install and silently DISARM the gate. Re-verify with "
              "--verify-only after any npm install." % mgr)

    # -------- install: shim bytes, then per-clone config
    hooks_dir = os.path.join(root, ".githooks")
    if os.path.isfile(hooks_dir):
        print("FAIL: %s exists as a regular FILE - cannot create the hook directory. "
              "Move it aside and re-run." % hooks_dir)
        return 1
    os.makedirs(hooks_dir, exist_ok=True)
    for rel, payload in (("pre-commit", canon), ("post-commit", canon_post),
                         ("pre-push", canon_prepush),
                         ("adversary_audit.py", canon_aud)):
        dst = os.path.join(hooks_dir, rel)
        with open(dst, "wb") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        if open(dst, "rb").read() != payload:
            print("FAIL: %s readback does not match canonical bytes" % dst)
            return 1
        try:
            os.chmod(dst, 0o755)           # POSIX: git skips a non-executable hook
        except OSError:
            pass                           # Windows: only toggles read-only; harmless
    # durable LF guarantee IN THE TARGET: under autocrlf=true a later checkout would
    # hand /bin/sh a CRLF script (adversary finding, installer birth review). A
    # .gitattributes scoped inside .githooks/ pins it without touching the repo's own.
    attrs = os.path.join(hooks_dir, ".gitattributes")
    have = open(attrs, encoding="utf-8", errors="replace").read() if os.path.isfile(attrs) else ""
    for want in ATTR_LINES:
        if want not in have:
            have = have + ("" if not have or have.endswith("\n") else "\n") + want + "\n"
    with open(attrs, "wb") as f:
        f.write(have.encode("utf-8"))
    # tripwire anchor: notarization (durable notes) begins NOW - commits before this
    # HEAD were gated but their clearances were transient, so auditing them would be
    # pure false alarms. Written ONCE; never moved by a re-run.
    base_path = os.path.join(hooks_dir, "adversary_baseline")
    if not os.path.isfile(base_path):
        rc, head_sha, _ = _git(root, "rev-parse", "HEAD")
        if rc == 0 and head_sha:
            with open(base_path, "wb") as f:
                f.write((head_sha + "\n").encode("utf-8"))
        else:
            # ARMED AT BIRTH (owner ruling 2026-09-08: every commit is a mutation event and is
            # challenged - the root included): an empty repo anchors at the sentinel ROOT, which
            # the auditor reads as "walk every commit"; never moved to a later HEAD
            with open(base_path, "wb") as f:
                f.write(b"ROOT\n")
    # rules epoch (2026-09-06): the vendored auditor now classifies extensionless hook files as
    # code. Commits at/below THIS head touched them while they were docs-class and carry no note
    # by design, so the rule is confined to later commits. Written ONCE, never moved (like the
    # baseline); a repo with no commits gets it on the first re-run after a commit exists.
    epoch_path = os.path.join(hooks_dir, "adversary_rules_epoch")
    have_epoch = (open(epoch_path, encoding="utf-8", errors="replace").read()
                  if os.path.isfile(epoch_path) else "")
    if b"HOOK_NAMES" in canon_aud and not any(
            ln.split()[:1] == ["hook-names"] for ln in have_epoch.splitlines()):
        rc, head_sha, _ = _git(root, "rev-parse", "HEAD")
        # an EMPTY repo anchors the epoch at ROOT too (armed at birth): the hook-name rule then
        # applies to every commit, the root's own shims included
        anchor = head_sha if (rc == 0 and head_sha) else "ROOT"
        with open(epoch_path, "wb") as f:
            f.write((have_epoch + ("" if not have_epoch or have_epoch.endswith("\n") else "\n")
                     + "hook-names " + anchor + "\n").encode("utf-8"))
    # rebases/amends must carry notes to the rewritten commits, or every rebase would
    # orphan its clearances and the auditor would false-alarm on reviewed content
    rc, _, err = _git(root, "config", "notes.rewriteRef", NOTES_REF)
    if rc != 0:
        print("FAIL: could not set notes.rewriteRef (%s)" % err[:200])
        return 1
    # ...and carry them by IGNORE: git's default rewriteMode is CONCATENATE, which glued the
    # copied original note onto the fresh note the post-commit notary had written during a rebase
    # replay - two JSON documents in one note, 'note is not valid JSON' at the auditor (Nexusmill
    # PR #21 rebase, 2026-09-17). `ignore` keeps whatever note the rewritten commit already has:
    # the notary's fresh note when it fired (the only record of content the gate cleared AFTER a
    # squash, an edit or a content-changing amend - `overwrite` would destroy it, gate round 1
    # on this fix), else the copied original, the valid record of blob-identical replays.
    rc, _, err = _git(root, "config", "notes.rewriteMode", "ignore")
    if rc != 0:
        print("FAIL: could not set notes.rewriteMode (%s)" % err[:200])
        return 1
    # transient gate state (.adversary/: clearances + review artifacts) must never be
    # committed - same convention as the repos already armed by hand
    gi = os.path.join(root, ".gitignore")
    gi_have = open(gi, encoding="utf-8", errors="replace").read() if os.path.isfile(gi) else ""
    if not any(ln.strip() in (".adversary", ".adversary/") for ln in gi_have.splitlines()):
        with open(gi, "ab") as f:
            f.write((("" if not gi_have or gi_have.endswith("\n") else "\n")
                     + ".adversary/\n").encode("utf-8"))
    # the ABSOLUTE canonical dispatcher dir, not the relative .githooks: worktrees inherit it
    # and it resolves on every branch (2026-09-06)
    rc, _, err = _git(root, "config", HOOKS_KEY, CANON_HOOKS_DIR)
    if rc != 0:
        print("FAIL: could not set core.hooksPath (%s)" % err[:200])
        return 1

    # -------- verify every claim by reading it back
    hp, shim_state = _state(root, canon)
    post_state = _bytes_state(root, "post-commit", canon_post)
    prepush_state = _bytes_state(root, "pre-push", canon_prepush)
    aud_state = _bytes_state(root, "adversary_audit.py", canon_aud)
    _, rref, _ = _git(root, "config", "notes.rewriteRef")
    _, rmode, _ = _git(root, "config", "notes.rewriteMode")
    if (not _hooks_equivalent(hp, root) or shim_state != "canonical"
            or post_state != "canonical" or prepush_state != "canonical"
            or aud_state != "canonical" or rref != NOTES_REF or rmode != "ignore"):
        print("FAIL: post-install verification (hooksPath=%r shim=%s post=%s prepush=%s "
              "auditor=%s rewriteRef=%r rewriteMode=%r)" % (hp, shim_state, post_state, prepush_state,
                                                            aud_state, rref, rmode))
        return 1
    if not gate_ok:
        _warn("the gate tool the SHIM execs is missing on this machine (%s) - the hook "
              "will fail CLOSED: every commit refused, none can clear, and this is NOT "
              "a working arming until the Tools repo exists at that exact path."
              % (gate_path or "no GATE= line found in the canonical shim"))

    print("%s  %s" % ("ARMED" if gate_ok else
                      "ARMED (FAIL-CLOSED - gate tool missing: commits will be refused "
                      "and NONE can clear until the Tools repo exists at the shim's path)",
                      root))
    print("  core.hooksPath = %s (machine-wide canonical dir; .githooks/ vendored for CI + "
          "other machines) ; shims + vendored auditor = canonical bytes (LF, pinned by "
          ".githooks/.gitattributes) ; notes.rewriteRef = %s (rewriteMode ignore) ; gate tool %s"
          % (CANON_HOOKS_DIR, NOTES_REF, "present" if gate_ok else "MISSING"))
    print("NEXT (the arming commit proves the hooks end to end):")
    print("  1. git add .githooks .gitignore")
    print("  2. git update-index --chmod=+x .githooks/pre-commit .githooks/post-commit "
          ".githooks/pre-push")
    print("       <- records index mode 100755; os.chmod cannot set an exec bit on")
    print("          Windows, and POSIX git SILENTLY SKIPS a non-executable hook")
    print("  3. python %s run --context \"arming commit\"" % (gate_path or "<gate>"))
    print("       <- optional (needs OPENROUTER_API_KEY): the commit below requests the review")
    print("          by itself, but WITHOUT context; EXPECT 'VERDICT: CLEAR'")
    print("  4. git commit           <- EXPECT the gate to speak: 'ADVERSARY GATE: requesting")
    print("       automatic independent review of staged changes.' (or a re-check of the shas)")
    print("       then CLEAR -> the commit lands and post-commit notarizes it (verify:")
    print("       git notes --ref %s show HEAD); BLOCK -> refused with findings." % NOTES_REF)
    print("       A code commit that lands SILENTLY means the hook did not run: --verify-only")
    print("  5. git push             <- the pre-push guard audits and pushes %s itself" % NOTES_REF)
    return 0 if gate_ok else 3


if __name__ == "__main__":
    sys.exit(main())
