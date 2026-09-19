"""install_gate selftest: full arming lifecycle in throwaway git repos, no network
(ADVERSARY_FAKE stubs the model, honored only in advgate_* repos). Exit 0 iff ALL PASS.
Location-independent: expected shim bytes get the SAME GATE= substitution the installer
applies, so the suite passes from any copy of the tool directory (plugin distribution)."""
import os
import re
import shutil
import subprocess
import sys
import tempfile

GIT = r"C:\Program Files\Git\cmd\git.exe"
if not os.path.isfile(GIT):
    GIT = "git"                                    # same fallback as install_gate.py
ORIG = os.path.dirname(os.path.abspath(__file__))
# ISOLATE from the owner's GLOBAL hook path (the machine-wide dispatcher, 2026-09-06): every
# fixture commit below would otherwise be intercepted by the REAL gate on the armed machine
# and the whole battery would collapse there (gate round 6, gate_20260906-180222). Rows that
# test a global value pass their own GIT_CONFIG_GLOBAL via env_extra.
_ISO_DIR = tempfile.mkdtemp(prefix="advgate_gcfg_")
with open(os.path.join(_ISO_DIR, "gitconfig"), "w", encoding="utf-8") as _f:
    _f.write("[user]\n\tname = t\n\temail = t@t\n")
os.environ["GIT_CONFIG_GLOBAL"] = os.path.join(_ISO_DIR, "gitconfig")
os.environ["GIT_CONFIG_NOSYSTEM"] = "1"
SUITE_FILES = ("install_gate.py", "adversary_gate.py", "adversary_audit.py",
               "pre-commit", "post-commit", "pre-push")
DISPATCHER_FILES = ("pre-commit", "post-commit", "pre-push", ".gitattributes")


def suite_copy():
    """A COMMITTED temp copy of the suite. The dispatchers verify themselves against their
    committed blobs (gate round 5), so a selftest that ran the authoring working tree would be
    refused as 'tampered' whenever a dispatcher is being edited - the very moment it must
    run. The copy is what a distributed suite looks like anyway."""
    d = tempfile.mkdtemp(prefix="advgate_suite_")
    for fn in SUITE_FILES:
        shutil.copy(os.path.join(ORIG, fn), os.path.join(d, fn))
    os.makedirs(os.path.join(d, "hooks"))
    for fn in DISPATCHER_FILES:
        shutil.copy(os.path.join(ORIG, "hooks", fn), os.path.join(d, "hooks", fn))
    subprocess.run([GIT, "init", "-q", d], capture_output=True)
    for k, v in (("user.email", "t@t"), ("user.name", "t"), ("core.autocrlf", "false")):
        subprocess.run([GIT, "-C", d, "config", k, v], capture_output=True)
    subprocess.run([GIT, "-C", d, "add", "-A"], capture_output=True)
    # a fixture commit, never a gated one: --no-verify, and the copy MUST have a HEAD (a
    # HEAD-less copy reads 'tampered' everywhere and silently collapses the battery)
    p = subprocess.run([GIT, "-C", d, "commit", "-q", "--no-verify", "-m", "suite copy"],
                       capture_output=True, text=True)
    head = subprocess.run([GIT, "-C", d, "rev-parse", "--verify", "--quiet", "HEAD"],
                          capture_output=True, text=True)
    if p.returncode != 0 or head.returncode != 0:
        raise SystemExit("suite_copy: fixture commit failed - %s" % (p.stdout + p.stderr)[:300])
    return d


HERE = suite_copy()
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
                       encoding="utf-8", errors="replace",
                       # ADVERSARY_SELFTEST: the selftest's own temp repos stay GATED (the
                       # EV-045 fixture skip is disabled under the selftest knob)
                       env=dict(os.environ, ADVERSARY_MODEL="", ADVERSARY_SELFTEST="1"))
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
    # 2026-09-06 (universal arming): the installer pins the ABSOLUTE canonical dispatcher dir,
    # not the relative .githooks - a worktree on a branch without .githooks/ inherits a relative
    # value that dangles and git runs NO hook there (probe_precedence, spec 4.1).
    CANON_DIR = os.path.join(HERE, "hooks").replace("\\", "/")
    check("hookspath_set", hp.replace("\\", "/").rstrip("/").lower() == CANON_DIR.lower(), hp)
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
    # 2026-09-17 (Nexusmill PR #21 rebase): git's default notes.rewriteMode is CONCATENATE - the rebase copied the
    # original commit's note onto the replayed commit AFTER the post-commit notary had written a fresh one, gluing
    # two JSON documents into one note ('note is not valid JSON' at the auditor). The installer pins IGNORE, not
    # overwrite (gate round 1 on the fix): when the notary fired on the rewritten commit its fresh note is the ONLY
    # record of the content the gate cleared post-rewrite (a squash, an edit, a content-changing amend), and the copy
    # must not replace it; when the notary was silent the original note is still copied. Read HERE, before the
    # replay block below sets the key by hand (gate round 3): this row sees the INSTALLER's value only.
    rmode = git(tmp, "config", "notes.rewriteMode", expect_ok=False).stdout.strip()  # unset = exit 1
    check("rewritemode_ignore", rmode == "ignore", rmode)

    # 4b. the incident end to end (2026-09-17; gate rounds 1-2 on this fix): the shape is a REBASE REPLAY of a
    # notarized commit whose clearance is still fresh - the notary fires inside the replayed commit, then the
    # sequencer's rewrite step copies the ORIGINAL commit's note onto the same commit. Under git's default
    # (concatenate) that glues two JSON documents into one note and the auditor rejects it; the installer's pin
    # (ignore) keeps the notary's fresh note. Both halves are proven: the incident reproduced under the default,
    # then prevented under the pin. Every git call here is GATED (the selftest knob keeps the fixture skip off).
    import hashlib
    import json
    gated = dict(os.environ, ADVERSARY_MODEL="", ADVERSARY_SELFTEST="1", ADVERSARY_FAKE="CLEAR", DOCSCAN_FAKE="CLEAR")

    def gitg(*args):
        return subprocess.run([GIT, "-C", tmp] + list(args), capture_output=True, text=True, encoding="utf-8",
                              errors="replace", env=gated)

    def head_note():
        return git(tmp, "notes", "--ref", "refs/notes/adversary", "show", "HEAD", expect_ok=False).stdout

    base = git(tmp, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip()
    base_tip = git(tmp, "rev-parse", "HEAD").stdout.strip()
    gitg("checkout", "-q", "-b", "replay")
    open(os.path.join(tmp, "mod2.py"), "w").write("def g():\n    return 2\n")
    git(tmp, "add", "mod2.py")
    run([GATE, "run"], cwd=tmp, env_extra={"ADVERSARY_FAKE": "CLEAR"})           # the clearance the replay will still find
    r = gitg("commit", "-q", "-m", "replayed later")
    check("replay_fixture_notarized", r.returncode == 0 and "CLEAR note written" in (r.stdout + r.stderr),
          (r.stdout + r.stderr)[-200:])
    mod2_sha = hashlib.sha256(open(os.path.join(tmp, "mod2.py"), "rb").read()).hexdigest()

    def move_base(name):
        gitg("checkout", "-q", base)
        open(os.path.join(tmp, name), "w").write("the base moves\n")
        git(tmp, "add", name)
        r = gitg("commit", "-q", "-m", "base moves")
        gitg("checkout", "-q", "replay")
        return r.returncode == 0

    # half 1 - git's default, the incident: two JSON documents in one note
    git(tmp, "config", "notes.rewriteMode", "concatenate")
    ok_base = move_base("a.md")
    r = gitg("rebase", "-q", base)
    note = head_note()
    try:
        json.loads(note)
        glued = False
    except ValueError:
        glued = True
    check("incident_reproduces_under_git_default", ok_base and r.returncode == 0 and glued
          and note.count('"type"') == 2, (r.stderr[-160:] if r.returncode else note[:160]))
    # half 2 - the installer's pin: the replayed HEAD carries ONE valid note naming mod2's blob
    git(tmp, "config", "notes.rewriteMode", "ignore")
    ok_base = move_base("b.md")
    r = gitg("rebase", "-q", base)
    note = head_note()
    try:
        doc = json.loads(note)
        ok = (doc.get("type") == "CLEAR" and doc.get("files", {}).get("mod2.py", {}).get("sha") == mod2_sha
              and note.count('"type"') == 1)
    except ValueError:
        ok = False
    check("pin_keeps_one_valid_note_on_replay", ok_base and r.returncode == 0 and ok,
          (r.stderr[-160:] if r.returncode else note[:160]))
    gitg("checkout", "-q", base)                       # hand the repo back as found: the rows below expect the
    git(tmp, "reset", "-q", "--hard", base_tip)        # cleared commit at HEAD and no replay branch
    git(tmp, "branch", "-q", "-D", "replay")

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
    # the install ran on a repo with NO commits -> ARMED AT BIRTH (owner ruling 2026-09-08):
    # the baseline is the sentinel ROOT (the auditor walks every commit, root included) and the
    # rules epoch is `hook-names ROOT` (the hook-name rule applies everywhere); neither waits
    # for a first commit, neither is ever moved
    base_path = os.path.join(tmp, ".githooks", "adversary_baseline")
    check("baseline_root_at_birth", os.path.isfile(base_path)
          and open(base_path, encoding="utf-8").read().strip() == "ROOT")
    epoch_path = os.path.join(tmp, ".githooks", "adversary_rules_epoch")
    check("epoch_root_at_birth", os.path.isfile(epoch_path)
          and "hook-names ROOT" in open(epoch_path, encoding="utf-8").read())
    # the cleared commit above exists now: post-commit should have NOTARIZED it
    note = git(tmp, "notes", "--ref", "refs/notes/adversary", "show", "HEAD", expect_ok=False)
    check("e2e_note_written_by_hook", note.returncode == 0 and "CLEAR" in note.stdout,
          note.stderr[:150])
    # re-run now that HEAD exists: baseline written = HEAD, then a further cleared
    # commit audits clean END TO END via the VENDORED auditor
    r = run([INSTALLER, tmp])
    head_now = git(tmp, "rev-parse", "HEAD").stdout.strip()
    base = open(base_path, encoding="utf-8").read().strip() if os.path.isfile(base_path) else ""
    check("baseline_root_kept_on_rerun", r.returncode == 0 and base == "ROOT", base[:60])
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
    check("baseline_preserved_on_rerun", base2 == "ROOT", base2[:60])

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
    check("force_repoints", r.returncode == 0
          and hp2.replace("\\", "/").rstrip("/").lower() == CANON_DIR.lower(), hp2)

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
    fakedir = tempfile.mkdtemp(prefix="advgate_fakecanon_")
    shutil.copy(INSTALLER, os.path.join(fakedir, "install_gate.py"))
    shutil.copy(os.path.join(HERE, "post-commit"), os.path.join(fakedir, "post-commit"))
    shutil.copy(os.path.join(HERE, "pre-push"), os.path.join(fakedir, "pre-push"))
    shutil.copy(os.path.join(HERE, "adversary_audit.py"),
                os.path.join(fakedir, "adversary_audit.py"))
    with open(os.path.join(fakedir, "pre-commit"), "wb") as f:
        f.write(b'#!/bin/sh\nGATE="C:/nonexistent_advgate/adversary_gate.py"\n'
                b'exec python "$GATE" check\n')
    # a suite copy must carry its dispatchers (gate round 3) - the fail-closed case is about
    # the GATE TOOL being missing, not the dispatcher dir
    os.makedirs(os.path.join(fakedir, "hooks"))
    for fn in ("pre-commit", "post-commit", "pre-push"):
        shutil.copy(os.path.join(HERE, "hooks", fn), os.path.join(fakedir, "hooks", fn))
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
    # gate round 3 (gate_20260906-170958) MEDIUM-HIGH: a suite copy WITHOUT hooks/ must never
    # pin an absolute dir that does not exist - git would run NO hook and the installer said
    # ARMED (fail-open). It must refuse, arming nothing.
    r = run([os.path.join(reloc, "install_gate.py"), tmp5])
    hp5 = git(tmp5, "config", "--local", "core.hooksPath", expect_ok=False).stdout.strip()
    check("relocated_without_dispatchers_refused", r.returncode == 1 and "dispatcher" in r.stdout
          and hp5 == "", "rc=%s hp=%r %s" % (r.returncode, hp5, r.stdout[:200]))
    os.makedirs(os.path.join(reloc, "hooks"))
    for fn in ("pre-commit", "post-commit", "pre-push", ".gitattributes"):
        shutil.copy(os.path.join(HERE, "hooks", fn), os.path.join(reloc, "hooks", fn))
    r = run([os.path.join(reloc, "install_gate.py"), tmp5])
    shim5 = open(os.path.join(tmp5, ".githooks", "pre-commit"), encoding="utf-8").read()
    want_gate = 'GATE="%s"' % os.path.join(reloc, "adversary_gate.py").replace("\\", "/")
    check("relocated_install_functional", r.returncode == 0 and "ARMED" in r.stdout,
          "rc=%s %s" % (r.returncode, r.stdout[:150]))
    check("relocated_gate_substituted", want_gate in shim5, shim5[:200])
    # ...and the pinned dispatcher actually RUNS: a code commit in the relocated-armed repo is
    # refused (never again a green row that never attempted a commit)
    open(os.path.join(tmp5, "r.py"), "w").write("r = 1\n")
    git(tmp5, "add", "r.py")
    r = subprocess.run([GIT, "-C", tmp5, "commit", "-qm", "relocated code"], capture_output=True,
                       text=True, encoding="utf-8", errors="replace",
                       env=dict(os.environ, ADVERSARY_SELFTEST="1", ADVERSARY_MODEL=""))
    check("relocated_dispatcher_refuses_code_commit", r.returncode != 0
          and "ADVERSARY GATE" in (r.stdout + r.stderr), (r.stdout + r.stderr)[-200:])

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

    # 10. universal arming (2026-09-06): global value is REPORTED not mistaken for local, a
    #     dangling relative value in a worktree is flagged, our own relative value re-pins
    #     without --force, and --census classifies every checkout. Isolated from the real
    #     ~/.gitconfig (which carries the canonical dir on the owner's machine after Task 6).
    iso_dir = tempfile.mkdtemp(prefix="advgate_iso_")
    iso_cfg = os.path.join(iso_dir, "gitconfig")
    open(iso_cfg, "w").write("[user]\n\tname = t\n\temail = t@t\n")
    iso = {"GIT_CONFIG_GLOBAL": iso_cfg, "GIT_CONFIG_NOSYSTEM": "1"}
    r = run([INSTALLER, tmp, "--verify-only"], env_extra=iso)
    check("verify_prints_global_row", "global hooksPath" in r.stdout, r.stdout[:300])
    git(tmp, "config", "core.hooksPath", ".githooks")            # back to the pre-2026-09-06 value
    git(tmp, "branch", "old")
    wt = tmp + "-wt"
    git(tmp, "worktree", "add", "-q", "--detach", wt, "old")
    git(wt, "rm", "-rq", ".githooks", expect_ok=False)              # model a pre-vendoring branch
    git(wt, "commit", "-qm", "drop hooks", "--no-verify", expect_ok=False)
    r = run([INSTALLER, wt, "--verify-only"], env_extra=iso)
    check("verify_flags_dangling_worktree", r.returncode == 1 and "DANGLING" in r.stdout, r.stdout[:300])
    r = run([INSTALLER, tmp], env_extra=iso)                        # our own relative value: not foreign
    hp3 = git(tmp, "config", "core.hooksPath").stdout.strip().replace("\\", "/").rstrip("/")
    check("repin_without_force", r.returncode == 0 and hp3.lower() == CANON_DIR.lower(),
          r.stdout[:200] + " | " + hp3)
    r = run([INSTALLER, wt, "--verify-only"], env_extra=iso)
    check("worktree_armed_after_repin", r.returncode == 0 and "ARMED" in r.stdout, r.stdout[:300])
    # the installer must read the LOCAL value: a GLOBAL canonical value alone is not 'foreign'
    # and must not block an install (hooks_selftest row 5 found this)
    glob_cfg = os.path.join(iso_dir, "gitconfig_global_canon")
    open(glob_cfg, "w", encoding="utf-8").write(
        "[core]\n\thooksPath = %s\n[user]\n\tname = t\n\temail = t@t\n" % CANON_DIR)
    tmpg = fresh_repo()
    r = run([INSTALLER, tmpg], env_extra={"GIT_CONFIG_GLOBAL": glob_cfg, "GIT_CONFIG_NOSYSTEM": "1"})
    check("global_canonical_not_foreign", r.returncode == 0 and "ARMED" in r.stdout, r.stdout[:200])
    # census over a temp root: armed clone, dangling worktree, unset clone, overridden clone
    croot = tempfile.mkdtemp(prefix="advcensus_")
    for name, cfg in (("unset", None), ("husky", ".husky/_")):
        rp = os.path.join(croot, name)
        subprocess.run([GIT, "init", "-q", rp], capture_output=True)
        git(rp, "config", "user.email", "t@t")
        git(rp, "config", "user.name", "t")
        if cfg:
            # a REAL other hook system has its dir (round 4: a value that resolves to nothing
            # is 'dangling', not 'overridden')
            os.makedirs(os.path.join(rp, cfg), exist_ok=True)
            git(rp, "config", "core.hooksPath", cfg)
    dang = os.path.join(croot, "dang")
    subprocess.run([GIT, "init", "-q", dang], capture_output=True)
    git(dang, "config", "user.email", "t@t")
    git(dang, "config", "user.name", "t")
    git(dang, "config", "core.hooksPath", ".githooks")              # value set, dir absent
    r = run([INSTALLER, "--census", croot, tmp], env_extra=iso)
    states = [ln.split()[0] for ln in r.stdout.splitlines()
              if ln.split() and ln.split()[0] in ("armed", "dangling", "unset", "overridden")]
    check("census_reports_four_states", r.returncode == 1 and "armed" in states
          and "dangling" in states and "unset" in states and "overridden" in states
          and ".husky" in r.stdout, "rc=%s %s" % (r.returncode, r.stdout[:600]))
    run([INSTALLER, os.path.join(croot, "unset")], env_extra=iso)
    run([INSTALLER, dang], env_extra=iso)
    r = run([INSTALLER, "--census", croot, tmp], env_extra=iso)
    states2 = [ln.split()[0] for ln in r.stdout.splitlines()
               if ln.split() and ln.split()[0] in ("armed", "dangling", "unset", "overridden")]
    check("census_only_overridden_left", r.returncode == 1 and states2.count("overridden") == 1
          and "dangling" not in states2 and "unset" not in states2,
          "rc=%s %s" % (r.returncode, r.stdout[:400]))
    run([INSTALLER, os.path.join(croot, "husky"), "--force"], env_extra=iso)
    r = run([INSTALLER, "--census", croot, tmp], env_extra=iso)
    check("census_exit0_all_armed", r.returncode == 0 and "overridden" not in r.stdout,
          "rc=%s %s" % (r.returncode, r.stdout[:400]))
    # gate round 2 (gate_20260906-165900) LOW: a census that finds NOTHING must not exit 0
    r = run([INSTALLER, "--census", os.path.join(croot, "no-such-root")], env_extra=iso)
    check("census_empty_is_not_success", r.returncode == 2 and "no checkouts" in r.stdout.lower(),
          "rc=%s %s" % (r.returncode, r.stdout[:200]))
    # gate round 2 LOW: --verify-only must agree with --census on GLOBAL-only arming - a repo
    # with NO local value under a global canonical dir is armed (vendored files present)
    git(tmpg, "config", "--unset", "core.hooksPath")
    r = run([INSTALLER, tmpg, "--verify-only"],
            env_extra={"GIT_CONFIG_GLOBAL": glob_cfg, "GIT_CONFIG_NOSYSTEM": "1"})
    check("verify_only_global_only_armed", r.returncode == 0 and "ARMED" in r.stdout
          and "GLOBAL" in r.stdout, "rc=%s %s" % (r.returncode, r.stdout[:300]))
    # gate round 2 MEDIUM: vendoring a HOOK_NAMES-aware auditor writes the rules epoch ONCE
    epoch_path = os.path.join(tmp, ".githooks", "adversary_rules_epoch")
    check("rules_epoch_written", os.path.isfile(epoch_path)
          and open(epoch_path).read().startswith("hook-names "), "")
    first_epoch = open(epoch_path).read() if os.path.isfile(epoch_path) else ""
    open(os.path.join(tmp, "later.md"), "w").write("x\n")
    git(tmp, "add", "later.md")
    git(tmp, "commit", "-qm", "later", "--no-verify")
    run([INSTALLER, tmp], env_extra=iso)
    check("rules_epoch_never_moved", os.path.isfile(epoch_path) and open(epoch_path).read() == first_epoch, "")
    # Tools D gate round 1 (gate_20260906-212201) LOW: a squash-shaped vendoring flow leaves the
    # epoch anchored at a sha the introducing commit never descended from -> MOVED, fail closed.
    # The explicit owner recovery `--reanchor-epoch` rewrites it to the PARENT of the commit
    # that first added the file (sound by construction: nothing before it had the file) and
    # refuses to touch a sound epoch (it must never be a forward-moving tool).
    sq = tempfile.mkdtemp(prefix="advgate_sq_")
    subprocess.run([GIT, "init", "-q", "-b", "main", sq], capture_output=True)
    git(sq, "config", "user.email", "t@t")
    git(sq, "config", "user.name", "t")
    open(os.path.join(sq, "README.md"), "w").write("base\n")
    git(sq, "add", "README.md")
    git(sq, "commit", "-q", "-m", "base")
    git(sq, "checkout", "-q", "-b", "feature")
    open(os.path.join(sq, "f.md"), "w").write("f\n")
    git(sq, "add", "f.md")
    git(sq, "commit", "-q", "-m", "feature")
    run([INSTALLER, sq], env_extra=iso)                       # vendors + writes the epoch at feature HEAD
    git(sq, "add", ".githooks", ".gitignore")
    git(sq, "commit", "-q", "--no-verify", "-m", "vendor on feature")
    git(sq, "checkout", "-q", "main")
    git(sq, "merge", "--squash", "feature")
    git(sq, "commit", "-q", "--no-verify", "-m", "squash")
    r = run([INSTALLER, sq, "--verify-only"], env_extra=iso)
    check("verify_reports_moved_epoch", "epoch" in r.stdout.lower() and "MOVED" in r.stdout, r.stdout[:400])
    r = run([INSTALLER, sq, "--reanchor-epoch"], env_extra=iso)
    intro_parent = git(sq, "rev-parse", "HEAD^").stdout.strip()
    ep_line = open(os.path.join(sq, ".githooks", "adversary_rules_epoch")).read().strip()
    check("reanchor_rewrites_to_intro_parent", r.returncode == 0 and ep_line == "hook-names " + intro_parent,
          "rc=%s line=%r want=%s %s" % (r.returncode, ep_line, intro_parent[:12], r.stdout[:200]))
    git(sq, "add", ".githooks/adversary_rules_epoch")
    git(sq, "commit", "-q", "--no-verify", "-m", "reanchor")
    r = run([INSTALLER, sq, "--verify-only"], env_extra=iso)
    check("verify_epoch_ok_after_reanchor", "MOVED" not in r.stdout and "epoch" in r.stdout.lower(), r.stdout[:400])
    r = run([INSTALLER, sq, "--reanchor-epoch"], env_extra=iso)
    ep_line2 = open(os.path.join(sq, ".githooks", "adversary_rules_epoch")).read().strip()
    check("reanchor_refuses_a_sound_epoch", r.returncode != 0 and ep_line2 == ep_line,
          "rc=%s %s" % (r.returncode, r.stdout[:200]))
    # Tools D gate round 3 (gate_20260906-220055): in a SHALLOW clone the history is truncated -
    # verify reports the epoch UNREADABLE and --reanchor-epoch refuses (a shallow-local
    # merge-base could be LATER than the true introduction)
    shallow = os.path.join(iso_dir, "shallow")
    subprocess.run([GIT, "clone", "-q", "--depth", "1", "file:///" + sq.replace("\\", "/"), shallow],
                   capture_output=True)
    r = run([INSTALLER, shallow, "--verify-only"], env_extra=iso)
    check("verify_reports_unreadable_epoch_in_shallow_clone", "UNREADABLE" in r.stdout, r.stdout[:400])
    r = run([INSTALLER, shallow, "--reanchor-epoch"], env_extra=iso)
    check("reanchor_refuses_in_shallow_clone", r.returncode != 0 and "unreadable" in r.stdout.lower(),
          "rc=%s %s" % (r.returncode, r.stdout[:200]))
    # gate round 3 MEDIUM-HIGH, the reviewer's exact scenario: the suite's dispatcher dir is
    # GONE after the pin (moved / partially synced copy) - the ABSOLUTE canonical value now
    # resolves to nothing, so verify-only AND census must say DANGLING, never armed
    # gate round 5 (gate_20260906-173424) MEDIUM-HIGH: the dispatchers EXECUTE from the suite's
    # working tree, so an uncommitted one-line edit there would disarm every pinned repo while
    # existence-only checks stayed green. Parity with the vendored shim's byte check: the suite
    # is a git checkout, each dispatcher is compared with its committed HEAD blob - dirty =
    # `tampered` (verify-only UNARMED, census tampered, installer refuses to pin) - and the
    # dispatcher itself fails CLOSED on its own uncommitted modification before running the gate.
    subprocess.run([GIT, "init", "-q", reloc], capture_output=True)
    git(reloc, "config", "user.email", "t@t")
    git(reloc, "config", "user.name", "t")
    git(reloc, "add", "-A")
    git(reloc, "commit", "-q", "--no-verify", "-m", "suite copy committed")   # fixture commit
    r = run([os.path.join(reloc, "install_gate.py"), tmp5, "--verify-only"], env_extra=iso)
    check("committed_dispatchers_verify_armed", r.returncode == 0 and "ARMED" in r.stdout,
          "rc=%s %s" % (r.returncode, r.stdout[:300]))
    pc = os.path.join(reloc, "hooks", "pre-commit")
    neutered = open(pc, "rb").read().replace(b'"$PYBIN" "$GATE" check || exit $?', b"true")
    with open(pc, "wb") as f:
        f.write(neutered)
    r = run([os.path.join(reloc, "install_gate.py"), tmp5, "--verify-only"], env_extra=iso)
    check("tampered_dispatcher_verify_unarmed", r.returncode == 1 and "UNARMED" in r.stdout
          and "tampered" in r.stdout.lower(), "rc=%s %s" % (r.returncode, r.stdout[:400]))
    r = run([os.path.join(reloc, "install_gate.py"), "--census", tmp5], env_extra=iso)
    check("census_tampered_dispatcher", r.returncode == 1 and "tampered" in r.stdout,
          "rc=%s %s" % (r.returncode, r.stdout[:300]))
    tmp6 = fresh_repo()
    r = run([os.path.join(reloc, "install_gate.py"), tmp6], env_extra=iso)
    hp6 = git(tmp6, "config", "--local", "core.hooksPath", expect_ok=False).stdout.strip()
    check("installer_refuses_tampered_dispatcher", r.returncode == 1 and "tampered" in r.stdout.lower()
          and hp6 == "", "rc=%s hp=%r %s" % (r.returncode, hp6, r.stdout[:300]))
    open(os.path.join(tmp5, "t.py"), "w").write("t = 1\n")
    git(tmp5, "add", "t.py")
    r = subprocess.run([GIT, "-C", tmp5, "commit", "-qm", "code under a neutered dispatcher"],
                       capture_output=True, text=True, encoding="utf-8", errors="replace",
                       env=dict(os.environ, ADVERSARY_SELFTEST="1", ADVERSARY_MODEL=""))
    check("neutered_dispatcher_fails_closed_on_itself", r.returncode != 0
          and "MODIFIED" in (r.stdout + r.stderr), (r.stdout + r.stderr)[-250:])
    git(reloc, "checkout", "--", "hooks/pre-commit")
    r = run([os.path.join(reloc, "install_gate.py"), tmp5, "--verify-only"], env_extra=iso)
    check("restored_dispatcher_verify_armed", r.returncode == 0 and "ARMED" in r.stdout,
          "rc=%s %s" % (r.returncode, r.stdout[:200]))
    # gate round 5 LOW: an ABSOLUTE foreign hook dir that EXISTS is `overridden` like its
    # relative spelling, not `dangling`
    husky_abs = os.path.join(tmp5, ".husky", "_")
    os.makedirs(husky_abs, exist_ok=True)
    git(tmp5, "config", "core.hooksPath", husky_abs.replace("\\", "/"))
    r = run([os.path.join(reloc, "install_gate.py"), "--census", tmp5], env_extra=iso)
    check("census_absolute_foreign_existing_is_overridden", r.returncode == 1
          and "overridden" in r.stdout and "dangling" not in r.stdout,
          "rc=%s %s" % (r.returncode, r.stdout[:300]))
    git(tmp5, "config", "core.hooksPath", os.path.join(reloc, "hooks").replace("\\", "/"))
    # gate round 4 (gate_20260906-172433) MEDIUM: PARTIAL loss - pre-commit survives but the
    # push guard and notary dispatchers are gone: two of three layers absent must never be
    # 'armed' (verify-only UNARMED + DANGLING, census dangling, exit 1)
    os.remove(os.path.join(reloc, "hooks", "pre-push"))
    r = run([os.path.join(reloc, "install_gate.py"), tmp5, "--verify-only"], env_extra=iso)
    check("partial_dispatcher_loss_is_dangling", r.returncode == 1 and "UNARMED" in r.stdout
          and "DANGLING" in r.stdout, "rc=%s %s" % (r.returncode, r.stdout[:400]))
    r = run([os.path.join(reloc, "install_gate.py"), "--census", tmp5], env_extra=iso)
    check("census_partial_dispatcher_loss_is_dangling", r.returncode == 1 and "dangling" in r.stdout,
          "rc=%s %s" % (r.returncode, r.stdout[:300]))
    # gate round 4 LOW: a FOREIGN absolute value that resolves to nothing is reported as
    # dangling (the actionable fact), not as another hook system
    ghost = os.path.join(iso_dir, "no-such-hooks-dir").replace("\\", "/")
    git(tmp5, "config", "core.hooksPath", ghost)
    r = run([os.path.join(reloc, "install_gate.py"), "--census", tmp5], env_extra=iso)
    check("census_foreign_ghost_is_dangling", r.returncode == 1 and "dangling" in r.stdout
          and "overridden" not in r.stdout, "rc=%s %s" % (r.returncode, r.stdout[:300]))
    git(tmp5, "config", "core.hooksPath", os.path.join(reloc, "hooks").replace("\\", "/"))
    shutil.rmtree(os.path.join(reloc, "hooks"))
    r = run([os.path.join(reloc, "install_gate.py"), tmp5, "--verify-only"], env_extra=iso)
    check("absolute_missing_dir_is_dangling", r.returncode == 1 and "UNARMED" in r.stdout
          and "DANGLING" in r.stdout and "MISSING" in r.stdout,
          "rc=%s %s" % (r.returncode, r.stdout[:400]))
    r = run([os.path.join(reloc, "install_gate.py"), "--census", tmp5], env_extra=iso)
    check("census_absolute_missing_is_dangling", r.returncode == 1 and "dangling" in r.stdout,
          "rc=%s %s" % (r.returncode, r.stdout[:300]))
    tmpd = fresh_repo()
    run([INSTALLER, tmpd], env_extra=iso)
    # gate round 3 LOW-MEDIUM: census and verify-only agree on BYTE state too - a canonical pin
    # over a CRLF-mangled vendored shim is `stale`, never `armed`
    git(tmpd, "config", "core.hooksPath", CANON_DIR)
    with open(os.path.join(tmpd, ".githooks", "pre-commit"), "wb") as f:
        f.write(canon.replace(b"\n", b"\r\n"))
    r = run([INSTALLER, "--census", tmpd], env_extra=iso)
    check("census_crlf_vendored_is_stale", r.returncode == 1 and "stale" in r.stdout
          and "armed " not in r.stdout.split("census:")[0], "rc=%s %s" % (r.returncode, r.stdout[:300]))
    r = run([INSTALLER, tmpd, "--verify-only"], env_extra=iso)
    check("verify_agrees_crlf_is_unarmed", r.returncode == 1 and "UNARMED" in r.stdout,
          "rc=%s %s" % (r.returncode, r.stdout[:200]))

    bad = {k: v for k, v in results.items() if not v[0]}
    print("\n%d/%d PASS" % (len(results) - len(bad), len(results)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
