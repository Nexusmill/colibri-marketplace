"""install_gate selftest: full arming lifecycle in throwaway git repos, no network
(ADVERSARY_FAKE stubs the model, honored only in advgate_* repos). Exit 0 iff ALL PASS.
Location-independent: expected shim bytes get the SAME GATE= substitution the installer
applies, so the suite passes from any copy of the tool directory (plugin distribution)."""
import os
import re
import subprocess
import sys
import tempfile

GIT = r"C:\Program Files\Git\cmd\git.exe"
if not os.path.isfile(GIT):
    GIT = "git"                                    # same fallback as install_gate.py
HERE = os.path.dirname(os.path.abspath(__file__))
INSTALLER = os.path.join(HERE, "install_gate.py")
GATE = os.path.join(HERE, "adversary_gate.py")
CANON = os.path.join(HERE, "pre-commit")
PY = sys.executable
results = {}


def check(name, ok, detail=""):
    results[name] = (bool(ok), detail)
    print(("PASS " if ok else "FAIL ") + name + ((" " + detail) if detail and not ok else ""))


def git(repo, *args, expect_ok=True):
    p = subprocess.run([GIT, "-C", repo] + list(args), capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    if expect_ok and p.returncode != 0:
        raise SystemExit("git %s: %s" % (args[:2], p.stderr[:300]))
    return p


def run(cmd, cwd=None, env_extra=None):
    env = dict(os.environ)
    env["ADVERSARY_SELFTEST"] = "1"
    env.update(env_extra or {})
    return subprocess.run([PY] + cmd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", cwd=cwd, env=env)


def fresh_repo():
    tmp = tempfile.mkdtemp(prefix="advgate_")
    subprocess.run([GIT, "init", "-q", tmp], capture_output=True)
    git(tmp, "config", "user.email", "t@t")
    git(tmp, "config", "user.name", "t")
    return tmp


def canon_shim(name):
    """Expected installed bytes for a shim: LF-normalized template with the GATE= line
    substituted to THIS directory's gate - mirroring install_gate._canonical_shim."""
    raw = open(os.path.join(HERE, name), "rb").read().replace(b"\r\n", b"\n")
    gate_line = ('GATE="%s"' % os.path.join(HERE, "adversary_gate.py")
                 .replace("\\", "/")).encode("utf-8")
    return re.sub(rb'(?m)^GATE=".*"$', gate_line.replace(b"\\", b"\\\\"), raw)


def main():
    canon = canon_shim("pre-commit")
    tmp = fresh_repo()

    # 1. verify-only on an unarmed repo reports UNARMED, exit 1
    r = run([INSTALLER, tmp, "--verify-only"])
    check("verify_only_unarmed", r.returncode == 1 and "UNARMED" in r.stdout, r.stdout[:120])

    # 2. install arms: exit 0, hooksPath set, shim bytes == canonical (LF)
    r = run([INSTALLER, tmp])
    hp = git(tmp, "config", "core.hooksPath").stdout.strip()
    shim_path = os.path.join(tmp, ".githooks", "pre-commit")
    shim = open(shim_path, "rb").read() if os.path.isfile(shim_path) else b""
    check("install_arms", r.returncode == 0 and "ARMED" in r.stdout, r.stdout[:200])
    check("next_steps_include_chmod", "update-index --chmod=+x" in r.stdout, r.stdout[-300:])
    check("hookspath_set", hp == ".githooks", hp)
    check("shim_is_canonical_lf", shim == canon and b"\r" not in shim)
    attrs_path = os.path.join(tmp, ".githooks", ".gitattributes")
    attrs = open(attrs_path, encoding="utf-8").read() if os.path.isfile(attrs_path) else ""
    check("lf_pinned_in_target", "pre-commit text eol=lf" in attrs, attrs[:120])
    gi_path = os.path.join(tmp, ".gitignore")
    gi = open(gi_path, encoding="utf-8").read() if os.path.isfile(gi_path) else ""
    check("adversary_gitignored", ".adversary/" in gi, gi[:120])
    if os.name != "nt":
        check("shim_executable_posix", os.access(os.path.join(tmp, ".githooks", "pre-commit"),
                                                 os.X_OK))

    # 3. idempotent second run (incl. no duplicated .gitattributes pin) + verify-only ARMED
    r = run([INSTALLER, tmp])
    check("idempotent_rerun", r.returncode == 0 and "ARMED" in r.stdout, r.stdout[:120])
    attrs2 = open(attrs_path, encoding="utf-8").read()
    check("gitattributes_not_duplicated", attrs2.count("pre-commit text eol=lf") == 1, attrs2[:120])
    gi2 = open(gi_path, encoding="utf-8").read()
    check("gitignore_not_duplicated", gi2.count(".adversary/") == 1, gi2[:120])
    r = run([INSTALLER, tmp, "--verify-only"])
    check("verify_only_armed", r.returncode == 0 and "ARMED" in r.stdout, r.stdout[:120])

    # 4. THE PROOF: a real commit staging code is refused by the installed hook,
    #    then passes after a (faked) CLEAR clearance
    open(os.path.join(tmp, "mod.py"), "w").write("def f():\n    return 1\n")
    git(tmp, "add", "mod.py")
    r = git(tmp, "commit", "-m", "should be blocked", expect_ok=False)
    check("installed_hook_blocks", r.returncode != 0 and "ADVERSARY GATE" in (r.stderr + r.stdout),
          (r.stderr + r.stdout)[:150])
    r = run([GATE, "run"], cwd=tmp, env_extra={"ADVERSARY_FAKE": "CLEAR"})
    check("clearance_obtainable", r.returncode == 0, (r.stdout + r.stderr)[-150:])
    r = git(tmp, "commit", "-m", "now allowed", expect_ok=False)
    check("installed_hook_allows_after_clear", r.returncode == 0, (r.stderr + r.stdout)[:150])

    # 4a. LAYER 3 claims: post-commit shim + vendored auditor + rewriteRef + baseline
    canon_post = canon_shim("post-commit")
    canon_prepush = canon_shim("pre-push")
    canon_aud = open(os.path.join(HERE, "adversary_audit.py"), "rb").read().replace(b"\r\n", b"\n")
    post = open(os.path.join(tmp, ".githooks", "post-commit"), "rb").read()
    prepush = open(os.path.join(tmp, ".githooks", "pre-push"), "rb").read()
    aud = open(os.path.join(tmp, ".githooks", "adversary_audit.py"), "rb").read()
    check("post_commit_installed", post == canon_post and b"\r" not in post)
    check("pre_push_installed", prepush == canon_prepush and b"\r" not in prepush)
    check("auditor_vendored", aud == canon_aud)
    rref = git(tmp, "config", "notes.rewriteRef").stdout.strip()
    check("rewriteref_set", rref == "refs/notes/adversary", rref)
    attrs3 = open(attrs_path, encoding="utf-8").read()
    check("new_lf_pins_present", "post-commit text eol=lf" in attrs3
          and "pre-push text eol=lf" in attrs3
          and "adversary_audit.py text eol=lf" in attrs3, attrs3[:200])
    # the install ran on a repo with NO commits -> baseline skipped with a warning
    base_path = os.path.join(tmp, ".githooks", "adversary_baseline")
    check("baseline_skipped_no_head", not os.path.isfile(base_path))
    # the cleared commit above exists now: post-commit should have NOTARIZED it
    note = git(tmp, "notes", "--ref", "refs/notes/adversary", "show", "HEAD", expect_ok=False)
    check("e2e_note_written_by_hook", note.returncode == 0 and "CLEAR" in note.stdout,
          note.stderr[:150])
    # re-run now that HEAD exists: baseline written = HEAD, then a further cleared
    # commit audits clean END TO END via the VENDORED auditor
    r = run([INSTALLER, tmp])
    head_now = git(tmp, "rev-parse", "HEAD").stdout.strip()
    base = open(base_path, encoding="utf-8").read().strip() if os.path.isfile(base_path) else ""
    check("baseline_written_on_rerun", r.returncode == 0 and base == head_now, base[:60])
    open(os.path.join(tmp, "next.py"), "w").write("n = 1\n")
    git(tmp, "add", "next.py")
    r = run([GATE, "run"], cwd=tmp, env_extra={"ADVERSARY_FAKE": "CLEAR"})
    r = git(tmp, "commit", "-m", "post-baseline cleared", expect_ok=False)
    check("post_baseline_commit_ok", r.returncode == 0, (r.stderr + r.stdout)[:150])
    r = run([os.path.join(tmp, ".githooks", "adversary_audit.py"), "--repo", tmp])
    check("vendored_auditor_clean", r.returncode == 0 and "clean" in r.stdout,
          (r.stdout + r.stderr)[-200:])
    # a re-run must NOT move the baseline (it would erase audit coverage)
    r = run([INSTALLER, tmp])
    base2 = open(base_path, encoding="utf-8").read().strip()
    check("baseline_preserved_on_rerun", base2 == head_now, base2[:60])

    # 4b. an EQUIVALENT hooksPath spelling ('./.githooks/') is not treated as foreign
    tmpe = fresh_repo()
    git(tmpe, "config", "core.hooksPath", "./.githooks/")
    r = run([INSTALLER, tmpe])
    check("equivalent_hookspath_not_foreign", r.returncode == 0 and "ARMED" in r.stdout,
          r.stdout[:150])

    # 4c. a CRLF-mangled but otherwise-canonical shim: the audit must NOT bless it
    #     (sh rejects CRLF), and a plain re-run (no --force) repairs it to LF
    crlf_shim = os.path.join(tmpe, ".githooks", "pre-commit")
    with open(crlf_shim, "wb") as f:
        f.write(canon.replace(b"\n", b"\r\n"))
    r = run([INSTALLER, tmpe, "--verify-only"])
    check("crlf_shim_not_blessed", r.returncode == 1 and "crlf" in r.stdout,
          "rc=%s %s" % (r.returncode, r.stdout[:150]))
    r = run([INSTALLER, tmpe])
    check("crlf_shim_repaired", r.returncode == 0
          and open(crlf_shim, "rb").read() == canon, r.stdout[:120])

    # 5. a foreign core.hooksPath is refused without --force, re-pointed with it
    tmp2 = fresh_repo()
    git(tmp2, "config", "core.hooksPath", ".husky")
    r = run([INSTALLER, tmp2])
    check("foreign_hookspath_refused", r.returncode == 1 and "--force" in r.stdout, r.stdout[:150])
    r = run([INSTALLER, tmp2, "--force"])
    hp2 = git(tmp2, "config", "core.hooksPath").stdout.strip()
    check("force_repoints", r.returncode == 0 and hp2 == ".githooks", hp2)

    # 6. a tampered shim is refused without --force, restored to canonical with it
    with open(os.path.join(tmp2, ".githooks", "pre-commit"), "wb") as f:
        f.write(b"#!/bin/sh\nexit 0\n")                    # a neutered shim
    r = run([INSTALLER, tmp2])
    check("tampered_shim_refused", r.returncode == 1 and "--force" in r.stdout, r.stdout[:150])
    r = run([INSTALLER, tmp2, "--force"])
    restored = open(os.path.join(tmp2, ".githooks", "pre-commit"), "rb").read()
    check("force_restores_canonical", r.returncode == 0 and restored == canon)

    # 7. FAIL-CLOSED arming is a DISTINCT exit (3), never a bare success: an installer
    #    copy whose canonical shim points at a nonexistent gate tool
    import shutil
    fakedir = tempfile.mkdtemp(prefix="advgate_fakecanon_")
    shutil.copy(INSTALLER, os.path.join(fakedir, "install_gate.py"))
    shutil.copy(os.path.join(HERE, "post-commit"), os.path.join(fakedir, "post-commit"))
    shutil.copy(os.path.join(HERE, "pre-push"), os.path.join(fakedir, "pre-push"))
    shutil.copy(os.path.join(HERE, "adversary_audit.py"),
                os.path.join(fakedir, "adversary_audit.py"))
    with open(os.path.join(fakedir, "pre-commit"), "wb") as f:
        f.write(b'#!/bin/sh\nGATE="C:/nonexistent_advgate/adversary_gate.py"\n'
                b'exec python "$GATE" check\n')
    tmp3 = fresh_repo()
    r = run([os.path.join(fakedir, "install_gate.py"), tmp3])
    check("failclosed_install_exit3", r.returncode == 3 and "FAIL-CLOSED" in r.stdout,
          "rc=%s %s" % (r.returncode, r.stdout[:150]))
    r = run([os.path.join(fakedir, "install_gate.py"), tmp3, "--verify-only"])
    check("failclosed_verify_exit3", r.returncode == 3 and "FAIL-CLOSED" in r.stdout,
          "rc=%s %s" % (r.returncode, r.stdout[:150]))

    # 7b. RELOCATED suite (plugin-distribution contract): an installer run from a
    #     copied directory substitutes the shims' GATE= line to ITS OWN gate and
    #     arms functional (exit 0) - the shim must never point at the authoring
    #     machine's path when the suite lives elsewhere
    reloc = tempfile.mkdtemp(prefix="advgate_reloc_")
    for fn in ("install_gate.py", "adversary_gate.py", "adversary_audit.py",
               "pre-commit", "post-commit", "pre-push"):
        shutil.copy(os.path.join(HERE, fn), os.path.join(reloc, fn))
    tmp5 = fresh_repo()
    r = run([os.path.join(reloc, "install_gate.py"), tmp5])
    shim5 = open(os.path.join(tmp5, ".githooks", "pre-commit"), encoding="utf-8").read()
    want_gate = 'GATE="%s"' % os.path.join(reloc, "adversary_gate.py").replace("\\", "/")
    check("relocated_install_functional", r.returncode == 0 and "ARMED" in r.stdout,
          "rc=%s %s" % (r.returncode, r.stdout[:150]))
    check("relocated_gate_substituted", want_gate in shim5, shim5[:200])

    # 8. a regular FILE named .githooks -> clean FAIL, no traceback
    tmp4 = fresh_repo()
    open(os.path.join(tmp4, ".githooks"), "w").write("not a dir\n")
    r = run([INSTALLER, tmp4])
    check("githooks_file_fails_clean", r.returncode == 1 and "FAIL" in r.stdout
          and "Traceback" not in r.stderr, (r.stdout + r.stderr)[:150])

    # 9. not a git repo -> clean FAIL, no traceback
    plain = tempfile.mkdtemp(prefix="advgate_plain_")
    r = run([INSTALLER, plain])
    check("non_repo_fails_clean", r.returncode == 1 and "FAIL" in r.stdout
          and "Traceback" not in r.stderr, (r.stdout + r.stderr)[:150])

    bad = {k: v for k, v in results.items() if not v[0]}
    print("\n%d/%d PASS" % (len(results) - len(bad), len(results)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
