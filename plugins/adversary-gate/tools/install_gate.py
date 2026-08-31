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
fires in this clone: stage the shim, attempt the commit (EXPECT refusal), run
`adversary_gate.py run` to CLEAR, commit. Docs: colibri-code-review/docs/GATE_INSTALLER.md.
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
# LF pins written into the target's .githooks/.gitattributes (sh rejects CRLF shims;
# the auditor + baseline are pinned too so vendored bytes stay deterministic)
ATTR_LINES = ("pre-commit text eol=lf", "post-commit text eol=lf",
              "pre-push text eol=lf",
              "adversary_audit.py text eol=lf", "adversary_baseline text eol=lf")


def _git(repo, *args):
    try:
        p = subprocess.run([GIT, "-C", repo] + list(args), capture_output=True)
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
    """True when an existing core.hooksPath already denotes <root>/.githooks in ANY
    spelling (relative, './'-prefixed, trailing slash, absolute) - a literal string
    mismatch alone is not 'foreign' (adversary finding, installer birth review r3)."""
    if not hp:
        return False
    p = hp.replace("\\", "/").rstrip("/")
    if not os.path.isabs(p):
        p = os.path.join(root, p)
    return (os.path.normcase(os.path.normpath(p))
            == os.path.normcase(os.path.normpath(os.path.join(root, ".githooks"))))


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
    _, hp, _ = _git(root, "config", "core.hooksPath")
    shim = os.path.join(root, ".githooks", "pre-commit")
    if not os.path.isfile(shim):
        return hp, "absent"
    raw = open(shim, "rb").read()
    if raw == canon:
        return hp, "canonical"
    if raw.replace(b"\r\n", b"\n") == canon:
        return hp, "crlf (CRLF endings - /bin/sh rejects this; re-run the installer)"
    return hp, "different"


def main(argv=None):
    ap = argparse.ArgumentParser(description="Arm the adversarial commit gate on a git repo.")
    ap.add_argument("repo", help="path to (or inside) the target working copy")
    ap.add_argument("--verify-only", action="store_true",
                    help="report ARMED/UNARMED and exit; change nothing")
    ap.add_argument("--force", action="store_true",
                    help="overwrite a different existing shim / re-point a foreign hooksPath")
    a = ap.parse_args(argv)

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

    if a.verify_only:
        post_state = _bytes_state(root, "post-commit", canon_post)
        prepush_state = _bytes_state(root, "pre-push", canon_prepush)
        aud_state = _bytes_state(root, "adversary_audit.py", canon_aud)
        base_path = os.path.join(root, ".githooks", "adversary_baseline")
        # a repo with no commits yet CANNOT have a baseline - that alone is not unarmed
        # (the installer warns and writes it on the first re-run after a commit exists)
        rc_head, _, _ = _git(root, "rev-parse", "--verify", "--quiet", "HEAD")
        base_ok = os.path.isfile(base_path) or rc_head != 0
        _, rref, _ = _git(root, "config", "notes.rewriteRef")
        rref_ok = rref == NOTES_REF
        layer3 = (post_state == "canonical" and prepush_state == "canonical"
                  and aud_state == "canonical" and base_ok and rref_ok)
        armed = _hooks_equivalent(hp, root) and shim_state == "canonical" and layer3
        head = ("ARMED" if gate_ok else "ARMED (FAIL-CLOSED - gate tool missing)") \
            if armed else "UNARMED"
        print("%s  %s" % (head, root))
        print("  core.hooksPath : %s" % (hp or "(unset)"))
        print("  shim           : %s" % shim_state)
        print("  gate tool      : %s" % ("present at " + gate_path if gate_ok else
                                         "MISSING at %s (hook fails CLOSED - no commit "
                                         "can clear)" % (gate_path or "?")))
        print("  post-commit    : %s" % post_state)
        print("  pre-push       : %s" % prepush_state)
        print("  auditor        : %s" % aud_state)
        print("  baseline       : %s" % ("present" if base_ok else "ABSENT (tripwire "
                                         "cannot anchor - re-run the installer)"))
        print("  rewriteRef     : %s" % (rref or "(unset - rebases will orphan notes)"))
        return (0 if gate_ok else 3) if armed else 1

    # -------- conflicts that need a conscious decision, not a silent overwrite
    if hp and not _hooks_equivalent(hp, root) and not a.force:
        print("FAIL: core.hooksPath is already '%s' (another hook system?). "
              "Re-run with --force to re-point it to .githooks." % hp)
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
            _warn("repo has no commits yet - no adversary_baseline written; re-run the "
                  "installer after the first commit so the tripwire can anchor.")
    # rebases/amends must carry notes to the rewritten commits, or every rebase would
    # orphan its clearances and the auditor would false-alarm on reviewed content
    rc, _, err = _git(root, "config", "notes.rewriteRef", NOTES_REF)
    if rc != 0:
        print("FAIL: could not set notes.rewriteRef (%s)" % err[:200])
        return 1
    # transient gate state (.adversary/: clearances + review artifacts) must never be
    # committed - same convention as the repos already armed by hand
    gi = os.path.join(root, ".gitignore")
    gi_have = open(gi, encoding="utf-8", errors="replace").read() if os.path.isfile(gi) else ""
    if not any(ln.strip() in (".adversary", ".adversary/") for ln in gi_have.splitlines()):
        with open(gi, "ab") as f:
            f.write((("" if not gi_have or gi_have.endswith("\n") else "\n")
                     + ".adversary/\n").encode("utf-8"))
    rc, _, err = _git(root, "config", "core.hooksPath", ".githooks")
    if rc != 0:
        print("FAIL: could not set core.hooksPath (%s)" % err[:200])
        return 1

    # -------- verify every claim by reading it back
    hp, shim_state = _state(root, canon)
    post_state = _bytes_state(root, "post-commit", canon_post)
    prepush_state = _bytes_state(root, "pre-push", canon_prepush)
    aud_state = _bytes_state(root, "adversary_audit.py", canon_aud)
    _, rref, _ = _git(root, "config", "notes.rewriteRef")
    if (not _hooks_equivalent(hp, root) or shim_state != "canonical"
            or post_state != "canonical" or prepush_state != "canonical"
            or aud_state != "canonical" or rref != NOTES_REF):
        print("FAIL: post-install verification (hooksPath=%r shim=%s post=%s prepush=%s "
              "auditor=%s rewriteRef=%r)" % (hp, shim_state, post_state, prepush_state,
                                             aud_state, rref))
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
    print("  core.hooksPath = .githooks ; both shims + vendored auditor = canonical bytes "
          "(LF, pinned by .githooks/.gitattributes) ; notes.rewriteRef = %s ; gate tool %s"
          % (NOTES_REF, "present" if gate_ok else "MISSING"))
    print("NEXT (the arming commit proves the hooks end to end):")
    print("  1. git add .githooks .gitignore")
    print("  2. git update-index --chmod=+x .githooks/pre-commit .githooks/post-commit "
          ".githooks/pre-push")
    print("       <- records index mode 100755; os.chmod cannot set an exec bit on")
    print("          Windows, and POSIX git SILENTLY SKIPS a non-executable hook")
    print("  3. git commit           <- EXPECT 'ADVERSARY GATE: commit REFUSED'")
    print("  4. python %s run        (needs OPENROUTER_API_KEY)" % (gate_path or "<gate>"))
    print("  5. git commit           <- passes; post-commit then notarizes it (verify:")
    print("       git notes --ref %s show HEAD)" % NOTES_REF)
    print("  6. when pushing, ALSO push the notes: git push origin %s" % NOTES_REF)
    return 0 if gate_ok else 3


if __name__ == "__main__":
    sys.exit(main())
