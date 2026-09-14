"""adversary_audit selftest: bypass, forgery, override and drift scenarios in a throwaway
repo, no network (ADVERSARY_FAKE stubs the model). Exit 0 iff ALL PASS."""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
GIT = r"C:\Program Files\Git\cmd\git.exe"
if not os.path.isfile(GIT):
    GIT = "git"                       # same fallback as the tools under test
# ISOLATE from the owner's GLOBAL hook path (the machine-wide dispatcher, 2026-09-06): the
# fixture commits below would otherwise be intercepted by the REAL gate on the armed machine
# (gate round 6, gate_20260906-180222). The tmp repos carry their own user.name/email.
_ISO_DIR = tempfile.mkdtemp(prefix="advgate_gcfg_")
with open(os.path.join(_ISO_DIR, "gitconfig"), "w", encoding="utf-8") as _f:
    _f.write("[user]\n\tname = t\n\temail = t@t\n")
os.environ["GIT_CONFIG_GLOBAL"] = os.path.join(_ISO_DIR, "gitconfig")
os.environ["GIT_CONFIG_NOSYSTEM"] = "1"
GATE = os.path.join(HERE, "adversary_gate.py")
AUDIT = os.path.join(HERE, "adversary_audit.py")
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


def gate(repo, *args, env_extra=None):
    env = dict(os.environ)
    env["ADVERSARY_SELFTEST"] = "1"
    env.update(env_extra or {})
    return subprocess.run([PY, GATE] + list(args), capture_output=True, text=True,
                          encoding="utf-8", errors="replace", cwd=repo, env=env)


def audit(repo, *args):
    return subprocess.run([PY, AUDIT, "--repo", repo] + list(args), capture_output=True,
                          text=True, encoding="utf-8", errors="replace")


def main():
    # 0. drift tripwire: the vendorable auditor must mirror the gate's code-path rules
    sys.path.insert(0, HERE)
    import adversary_gate as g
    import adversary_audit as a
    check("parity_code_exts", g.CODE_EXTS == a.CODE_EXTS)
    check("parity_prefixes", g.GATED_PREFIXES == a.GATED_PREFIXES)
    check("parity_hook_names", g.HOOK_NAMES == a.HOOK_NAMES
          and a._is_code("adversary-gate/hooks/pre-commit") and not a._is_code("hooks/README"))
    check("parity_empty_tree", g.EMPTY_TREE == a.EMPTY_TREE and g.NOTES_REF == a.NOTES_REF)

    tmp = tempfile.mkdtemp(prefix="advgate_")
    subprocess.run([GIT, "init", "-q", tmp], capture_output=True)
    git(tmp, "config", "user.email", "t@t")
    git(tmp, "config", "user.name", "t")

    # baseline commit (docs) + baseline file, as the installer would write it
    open(os.path.join(tmp, "README.md"), "w").write("base\n")
    git(tmp, "add", "README.md")
    git(tmp, "commit", "-q", "-m", "base")
    base = git(tmp, "rev-parse", "HEAD").stdout.strip()
    os.makedirs(os.path.join(tmp, ".githooks"), exist_ok=True)
    open(os.path.join(tmp, ".githooks", "adversary_baseline"), "w").write(base + "\n")

    # 1. cleared + recorded commit -> clean
    open(os.path.join(tmp, "ok.py"), "w").write("a = 1\n")
    git(tmp, "add", "ok.py")
    r = gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    check("setup_clear_run", r.returncode == 0, r.stdout[-150:])
    git(tmp, "commit", "-q", "-m", "cleared change")
    r = gate(tmp, "record")
    check("setup_record", r.returncode == 0, r.stderr[:150])
    r = audit(tmp)
    check("clean_history_passes", r.returncode == 0 and "clean" in r.stdout, r.stdout[-200:])

    # 2. bypass commit (no clearance, no note) -> VIOLATION
    open(os.path.join(tmp, "byp.py"), "w").write("b = 2\n")
    git(tmp, "add", "byp.py")
    git(tmp, "commit", "-q", "--no-verify", "-m", "bypassed")
    r = audit(tmp)
    check("bypass_flagged", r.returncode == 1 and "UNNOTARIZED" in r.stdout, r.stdout[-200:])

    # 3. forged note (right structure, wrong sha) -> VIOLATION
    open(os.path.join(tmp, "forg.py"), "w").write("c = 3\n")
    git(tmp, "add", "forg.py")
    git(tmp, "commit", "-q", "--no-verify", "-m", "forged")
    forged = {"type": "CLEAR", "files": {"forg.py": {"sha": "0" * 64}}}
    git(tmp, "notes", "--ref", "refs/notes/adversary", "add", "-m", json.dumps(forged), "HEAD")
    r = audit(tmp)
    check("forged_sha_flagged", r.returncode == 1 and "does not match" in r.stdout,
          r.stdout[-250:])

    # 4. owner OVERRIDE -> listed loudly, passes; --strict-override -> violation
    open(os.path.join(tmp, "ovr.py"), "w").write("d = 4\n")
    git(tmp, "add", "ovr.py")
    os.makedirs(os.path.join(tmp, ".adversary"), exist_ok=True)
    open(os.path.join(tmp, ".adversary", "OVERRIDE"), "w").write("audit selftest emergency")
    r = gate(tmp, "check")
    check("override_consumed", r.returncode == 0 and "OVERRIDDEN" in r.stderr)
    git(tmp, "commit", "-q", "-m", "override change")
    r = gate(tmp, "record")
    check("override_recorded", r.returncode == 0, r.stderr[:150])

    # 5. docs-only commit is skipped entirely
    open(os.path.join(tmp, "notes.md"), "w").write("docs\n")
    git(tmp, "add", "notes.md")
    git(tmp, "commit", "-q", "-m", "docs only")

    r = audit(tmp, "--json")
    try:
        d = json.loads(r.stdout)
    except ValueError:
        d = {}
    check("json_counts", d.get("commits_walked") == 5 and d.get("code_commits_audited") == 4
          and len(d.get("violations", [])) == 2 and len(d.get("overrides", [])) == 1,
          r.stdout[-300:])
    check("json_exit_violations", r.returncode == 1)

    # audit only the tail (after the forged commit): override passes, strict flags it
    forged_rev = git(tmp, "rev-parse", "HEAD~2").stdout.strip()
    r = audit(tmp, "--baseline", forged_rev)
    check("override_passes_default", r.returncode == 0 and "OVERRIDE" in r.stdout,
          r.stdout[-200:])
    r = audit(tmp, "--baseline", forged_rev, "--strict-override")
    check("override_strict_flags", r.returncode == 1)

    # 6. no baseline anywhere -> usage error, not a silent pass
    r = subprocess.run([PY, AUDIT, "--repo", tmp, "--baseline", "not-a-rev"],
                       capture_output=True, text=True)
    check("bad_baseline_errors", r.returncode == 2, r.stdout[:150])

    # 7. rules epoch (2026-09-06, gate round 2 MEDIUM): HOOK_NAMES reclassified extensionless
    #    hook files as code; without a migration every historical commit that touched
    #    Tools/adversary-gate/pre-commit etc. while they were docs-class becomes a permanent
    #    UNNOTARIZED violation. `.githooks/adversary_rules_epoch` (`hook-names <sha>`, written
    #    by the installer when it vendors a HOOK_NAMES-aware auditor) confines the rule to
    #    commits strictly AFTER that sha.
    ep = tempfile.mkdtemp(prefix="advgate_epoch_")
    subprocess.run([GIT, "init", "-q", ep], capture_output=True)
    git(ep, "config", "user.email", "t@t")
    git(ep, "config", "user.name", "t")
    open(os.path.join(ep, "README.md"), "w").write("base\n")
    git(ep, "add", "README.md")
    git(ep, "commit", "-q", "-m", "base")
    ep_base = git(ep, "rev-parse", "HEAD").stdout.strip()
    os.makedirs(os.path.join(ep, ".githooks", "x"), exist_ok=True)
    open(os.path.join(ep, ".githooks", "adversary_baseline"), "w").write(ep_base + "\n")
    os.makedirs(os.path.join(ep, "tool"), exist_ok=True)
    open(os.path.join(ep, "tool", "pre-commit"), "w", newline="\n").write("#!/bin/sh\nexit 0\n")
    git(ep, "add", "tool/pre-commit")
    git(ep, "commit", "-q", "--no-verify", "-m", "historical shim edit (docs-class at the time)")
    ep_hist = git(ep, "rev-parse", "HEAD").stdout.strip()
    r = audit(ep)
    check("epoch_absent_reclassifies_history", r.returncode == 1 and "UNNOTARIZED" in r.stdout,
          r.stdout[-200:])
    open(os.path.join(ep, ".githooks", "adversary_rules_epoch"), "w").write("hook-names %s\n" % ep_hist)
    # Tools E gate round 1 (gate_20260906-223831): an UNCOMMITTED epoch is never trusted - only
    # the blob in HEAD's tree counts (working-tree reads are case-folded on Windows/macOS and
    # follow symlinks; tree lookups are exact) - the rule applies everywhere until it is committed
    r = audit(ep)
    check("uncommitted_epoch_applies_rule_everywhere", r.returncode == 1 and "UNNOTARIZED" in r.stdout,
          r.stdout[-200:])
    # committing the epoch is itself a gated (.githooks/) code change: clear + notarize it
    git(ep, "add", ".githooks/adversary_rules_epoch")
    r = gate(ep, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    check("epoch_commit_cleared", r.returncode == 0, r.stdout[-150:])
    git(ep, "commit", "-q", "--no-verify", "-m", "commit the epoch")
    r = gate(ep, "record")
    check("epoch_commit_recorded", r.returncode == 0, r.stderr[:150])
    r = audit(ep)
    check("epoch_at_history_is_clean", r.returncode == 0 and "clean" in r.stdout, r.stdout[-200:])
    open(os.path.join(ep, "tool", "pre-commit"), "a", newline="\n").write("# after the epoch\n")
    git(ep, "add", "tool/pre-commit")
    git(ep, "commit", "-q", "--no-verify", "-m", "post-epoch shim edit, no note")
    r = audit(ep)
    check("post_epoch_hook_edit_flagged", r.returncode == 1 and "UNNOTARIZED" in r.stdout
          and "tool/pre-commit" in r.stdout, r.stdout[-250:])
    # a .py commit before the epoch is still audited (the epoch confines ONLY the new rule)
    open(os.path.join(ep, "old.py"), "w").write("x=1\n")
    git(ep, "add", "old.py")
    git(ep, "commit", "-q", "--no-verify", "-m", "py without note")
    r = audit(ep)
    check("epoch_does_not_excuse_py", r.returncode == 1 and "old.py" in r.stdout, r.stdout[-250:])

    # 12. case-variant attack (Tools E round 1): a tracked `.githooks/ADVERSARY_RULES_EPOCH` naming a
    #     later sha satisfies a case-folded working-tree read but is NOT the epoch blob; the exact
    #     tree lookup misses it and the rule must keep applying (the post-epoch shim edit stays
    #     flagged). Built directly in the index so the working tree holds the variant name.
    cv = tempfile.mkdtemp(prefix="advgate_casevar_")
    subprocess.run([GIT, "init", "-q", "-b", "main", cv], capture_output=True)
    git(cv, "config", "user.email", "t@t")
    git(cv, "config", "user.name", "t")
    open(os.path.join(cv, "README.md"), "w").write("base\n")
    git(cv, "add", "README.md")
    git(cv, "commit", "-q", "-m", "base")
    cv_base = git(cv, "rev-parse", "HEAD").stdout.strip()
    os.makedirs(os.path.join(cv, ".githooks"), exist_ok=True)
    open(os.path.join(cv, ".githooks", "adversary_baseline"), "w").write(cv_base + "\n")
    git(cv, "add", ".githooks/adversary_baseline")
    git(cv, "commit", "-q", "--no-verify", "-m", "baseline")
    os.makedirs(os.path.join(cv, "tool"), exist_ok=True)
    open(os.path.join(cv, "tool", "pre-commit"), "w", newline="\n").write("#!/bin/sh\nexit 0\n")
    git(cv, "add", "tool/pre-commit")
    git(cv, "commit", "-q", "--no-verify", "-m", "R: un-notarized hook-file edit")
    r_sha = git(cv, "rev-parse", "HEAD").stdout.strip()
    blob = subprocess.run([GIT, "-C", cv, "hash-object", "-w", "--stdin"], input="hook-names %s\n" % r_sha,
                          capture_output=True, text=True).stdout.strip()
    git(cv, "update-index", "--add", "--cacheinfo", "100644,%s,.githooks/ADVERSARY_RULES_EPOCH" % blob)
    git(cv, "commit", "-q", "--no-verify", "-m", "attacker: case-variant epoch naming R")
    git(cv, "checkout", "-q", "--", ".githooks")
    r = audit(cv)
    check("case_variant_epoch_is_not_the_epoch", r.returncode == 1 and "tool/pre-commit" in r.stdout,
          r.stdout[-300:])
    # parity: the gate applies the same epoch to the commits it audits on push
    check("parity_epoch_helper", hasattr(g, "_hook_names_apply") and hasattr(a, "_hook_names_apply")
          and g.RULES_EPOCH_FILE == a.RULES_EPOCH_FILE)

    # 8. the epoch is ANCHORED IN HISTORY (deepagents re-vendor gate round 1, gate_20260906-210758):
    #    a later commit must not be able to move the epoch sha forward and grandfather earlier
    #    hook-file commits out of the rule. The recorded sha may never be later than the commit
    #    that first ADDED the epoch file; a moved epoch is a violation and the rule applies to
    #    every commit (fail closed) - in the auditor AND in the gate's push-side walker.
    ep2 = tempfile.mkdtemp(prefix="advgate_epoch2_")
    subprocess.run([GIT, "init", "-q", ep2], capture_output=True)
    git(ep2, "config", "user.email", "t@t")
    git(ep2, "config", "user.name", "t")
    open(os.path.join(ep2, "README.md"), "w").write("base\n")
    git(ep2, "add", "README.md")
    git(ep2, "commit", "-q", "-m", "base")
    ep2_base = git(ep2, "rev-parse", "HEAD").stdout.strip()
    os.makedirs(os.path.join(ep2, ".githooks"), exist_ok=True)
    open(os.path.join(ep2, ".githooks", "adversary_baseline"), "w").write(ep2_base + "\n")
    open(os.path.join(ep2, ".githooks", "adversary_rules_epoch"), "w").write("hook-names %s\n" % ep2_base)
    git(ep2, "add", ".githooks")
    git(ep2, "commit", "-q", "--no-verify", "-m", "vendor with epoch (legit)")
    os.makedirs(os.path.join(ep2, "tool"), exist_ok=True)
    open(os.path.join(ep2, "tool", "pre-commit"), "w", newline="\n").write("#!/bin/sh\nexit 0\n")
    git(ep2, "add", "tool/pre-commit")
    git(ep2, "commit", "-q", "--no-verify", "-m", "post-epoch shim edit, no note")
    r = audit(ep2)
    check("anchored_epoch_flags_post_epoch_shim", r.returncode == 1 and "tool/pre-commit" in r.stdout,
          r.stdout[-250:])
    # the attack: rewrite the epoch to HEAD (a descendant of the introducing commit) and commit it
    open(os.path.join(ep2, ".githooks", "adversary_rules_epoch"), "w").write(
        "hook-names %s\n" % git(ep2, "rev-parse", "HEAD").stdout.strip())
    git(ep2, "add", ".githooks/adversary_rules_epoch")
    git(ep2, "commit", "-q", "--no-verify", "-m", "move the epoch forward")
    r = audit(ep2)
    check("moved_epoch_is_a_violation", r.returncode == 1 and "epoch" in r.stdout.lower()
          and "tool/pre-commit" in r.stdout, r.stdout[-400:])
    # ...from a SUBDIRECTORY too (Tools D gate round 1, gate_20260906-212201: a cwd-relative
    # pathspec made the anchor read nothing from a subdir and trust the moved sha)
    for where, label in ((ep2, "root"), (os.path.join(ep2, "tool"), "subdir")):
        check("moved_epoch_gate_side_fails_closed_from_" + label,
              subprocess.run([PY, "-c",
                              "import os,sys; os.chdir(sys.argv[1]); sys.path.insert(0, sys.argv[2]); "
                              "import adversary_gate as g; print(g._hook_names_apply('HEAD~1'))",
                              where, HERE], capture_output=True, text=True).stdout.strip() == "True",
              "gate-side walker must apply the rule when the epoch was moved (cwd=%s)" % label)

    # 9. a SQUASH-shaped vendoring flow (the epoch recorded at a feature HEAD, the file arriving on
    #    main inside a squash commit whose parent never had that sha) reads as MOVED: fail-closed,
    #    documented, recoverable only by the installer's explicit --reanchor-epoch (Tools D round 1
    #    LOW) - the auditor side of that contract
    sq = tempfile.mkdtemp(prefix="advgate_squash_")
    subprocess.run([GIT, "init", "-q", "-b", "main", sq], capture_output=True)
    git(sq, "config", "user.email", "t@t")
    git(sq, "config", "user.name", "t")
    open(os.path.join(sq, "README.md"), "w").write("base\n")
    git(sq, "add", "README.md")
    git(sq, "commit", "-q", "-m", "base")
    sq_base = git(sq, "rev-parse", "HEAD").stdout.strip()
    git(sq, "checkout", "-q", "-b", "feature")
    open(os.path.join(sq, "f.md"), "w").write("feature\n")
    git(sq, "add", "f.md")
    git(sq, "commit", "-q", "-m", "feature work")
    feat_head = git(sq, "rev-parse", "HEAD").stdout.strip()
    os.makedirs(os.path.join(sq, ".githooks"), exist_ok=True)
    open(os.path.join(sq, ".githooks", "adversary_baseline"), "w").write(sq_base + "\n")
    open(os.path.join(sq, ".githooks", "adversary_rules_epoch"), "w").write("hook-names %s\n" % feat_head)
    git(sq, "add", ".githooks")
    git(sq, "commit", "-q", "--no-verify", "-m", "vendor on the feature branch")
    git(sq, "checkout", "-q", "main")
    git(sq, "merge", "--squash", "feature")
    git(sq, "commit", "-q", "--no-verify", "-m", "squash: feature + vendoring")
    r = audit(sq)
    check("squash_flow_reads_moved_and_fails_closed", r.returncode == 1 and "MOVED" in r.stdout,
          r.stdout[-300:])

    # 10. the anchor must be ORDER-INDEPENDENT (Tools D gate round 2, gate_20260906-214441): with
    #     forged committer dates an attacker's re-add of the epoch file on a side branch lists as
    #     the 'earliest' add in date order. The rule: the recorded sha must be an ancestor of
    #     EVERY commit that ever added the epoch file - the original introduction included.
    fk = tempfile.mkdtemp(prefix="advgate_forged_")
    subprocess.run([GIT, "init", "-q", "-b", "main", fk], capture_output=True)
    git(fk, "config", "user.email", "t@t")
    git(fk, "config", "user.name", "t")
    open(os.path.join(fk, "README.md"), "w").write("base\n")
    git(fk, "add", "README.md")
    git(fk, "commit", "-q", "-m", "c0")
    c0 = git(fk, "rev-parse", "HEAD").stdout.strip()
    os.makedirs(os.path.join(fk, ".githooks"), exist_ok=True)
    open(os.path.join(fk, ".githooks", "adversary_baseline"), "w").write(c0 + "\n")
    open(os.path.join(fk, ".githooks", "adversary_rules_epoch"), "w").write("hook-names %s\n" % c0)
    git(fk, "add", ".githooks")
    git(fk, "commit", "-q", "--no-verify", "-m", "V: legit introduction of the epoch")
    os.makedirs(os.path.join(fk, "tool"), exist_ok=True)
    open(os.path.join(fk, "tool", "pre-commit"), "w", newline="\n").write("#!/bin/sh\nexit 0\n")
    git(fk, "add", "tool/pre-commit")
    git(fk, "commit", "-q", "--no-verify", "-m", "H: un-notarized hook-file edit after the epoch")
    r = audit(fk)
    check("forged_setup_flags_hook_edit", r.returncode == 1 and "tool/pre-commit" in r.stdout, r.stdout[-200:])
    # the attack: from c0, commit E (any), re-add the epoch naming E with FORGED old dates, merge
    # back with a resolution that writes a third value (not TREESAME to either parent)
    git(fk, "checkout", "-q", "-b", "side", c0)
    old = {"GIT_AUTHOR_DATE": "2000-01-01T00:00:00", "GIT_COMMITTER_DATE": "2000-01-01T00:00:00"}
    open(os.path.join(fk, "e.md"), "w").write("e\n")
    git(fk, "add", "e.md")
    subprocess.run([GIT, "-C", fk, "commit", "-q", "--no-verify", "-m", "E"], env=dict(os.environ, **old),
                   capture_output=True)
    e_sha = git(fk, "rev-parse", "HEAD").stdout.strip()
    os.makedirs(os.path.join(fk, ".githooks"), exist_ok=True)
    open(os.path.join(fk, ".githooks", "adversary_rules_epoch"), "w").write("hook-names %s\n" % e_sha)
    git(fk, "add", ".githooks/adversary_rules_epoch")
    subprocess.run([GIT, "-C", fk, "commit", "-q", "--no-verify", "-m", "forged re-add naming E"],
                   env=dict(os.environ, **old), capture_output=True)
    git(fk, "checkout", "-q", "main")
    subprocess.run([GIT, "-C", fk, "merge", "-q", "--no-ff", "--no-verify", "-m", "merge side", "side"],
                   capture_output=True)      # conflicts on the epoch file: resolve with a THIRD value
    open(os.path.join(fk, ".githooks", "adversary_rules_epoch"), "w").write("hook-names %s\n" % e_sha)
    git(fk, "add", ".githooks/adversary_rules_epoch")
    subprocess.run([GIT, "-C", fk, "commit", "-q", "--no-verify", "-m", "merge side (resolved)"],
                   capture_output=True)
    r = audit(fk)
    check("forged_date_readd_still_moved", r.returncode == 1 and "MOVED" in r.stdout
          and "tool/pre-commit" in r.stdout, r.stdout[-400:])
    check("forged_date_gate_side_fails_closed",
          subprocess.run([PY, "-c",
                          "import os,sys; os.chdir(sys.argv[1]); sys.path.insert(0, sys.argv[2]); "
                          "import adversary_gate as g; print(g._hook_names_apply('HEAD~2'))",
                          fk, HERE], capture_output=True, text=True).stdout.strip() == "True",
          "gate-side walker must apply the rule under the forged-date re-add")

    # 11. a SHALLOW clone (Tools D gate round 3, gate_20260906-220055): truncated history yields
    #     no add commits for a file that IS in HEAD's tree - that can only be truncation, never
    #     'not committed yet', so the anchor reads UNREADABLE (fail closed) on every site
    shallow = tempfile.mkdtemp(prefix="advgate_shallow_") + "/c"
    subprocess.run([GIT, "clone", "-q", "--depth", "1", "file:///" + ep2.replace("\\", "/"), shallow],
                   capture_output=True)
    st = subprocess.run([PY, "-c",
                         "import sys; sys.path.insert(0, sys.argv[2]); import adversary_audit as a; "
                         "print(a._epoch(sys.argv[1])[1])", shallow, HERE],
                        capture_output=True, text=True).stdout.strip()
    check("shallow_clone_epoch_unreadable", st == "unreadable", "state=%r" % st)
    check("shallow_clone_gate_side_fails_closed",
          subprocess.run([PY, "-c",
                          "import os,sys; os.chdir(sys.argv[1]); sys.path.insert(0, sys.argv[2]); "
                          "import adversary_gate as g; print(g._hook_names_apply('HEAD'))",
                          shallow, HERE], capture_output=True, text=True).stdout.strip() == "True",
          "gate-side walker must apply the rule in a shallow clone")

    # 12b. ARMED AT BIRTH (owner ruling 2026-09-08): baseline ROOT walks EVERY commit, the root
    # included - a bypassed root commit is UNNOTARIZED; a notarized root is clean; the ROOT
    # epoch applies the hook-name rule to the root itself
    rt = tempfile.mkdtemp(prefix="advgate_root_")
    subprocess.run([GIT, "init", "-q", rt], capture_output=True)
    git(rt, "config", "user.email", "t@t")
    git(rt, "config", "user.name", "t")
    os.makedirs(os.path.join(rt, ".githooks"), exist_ok=True)
    open(os.path.join(rt, ".githooks", "adversary_baseline"), "w").write("ROOT\n")
    open(os.path.join(rt, ".githooks", "adversary_rules_epoch"), "w").write("hook-names ROOT\n")
    open(os.path.join(rt, "first.py"), "w").write("first = 1\n")
    git(rt, "add", "first.py", ".githooks/adversary_baseline", ".githooks/adversary_rules_epoch")
    git(rt, "commit", "-q", "--no-verify", "-m", "bypassed root")
    r = audit(rt)
    check("root_baseline_walks_root_commit", r.returncode == 1 and "UNNOTARIZED" in r.stdout
          and "1 commit(s)" in r.stdout, r.stdout[-250:])
    rt2 = tempfile.mkdtemp(prefix="advgate_root2_")
    subprocess.run([GIT, "init", "-q", rt2], capture_output=True)
    git(rt2, "config", "user.email", "t@t")
    git(rt2, "config", "user.name", "t")
    os.makedirs(os.path.join(rt2, ".githooks"), exist_ok=True)
    open(os.path.join(rt2, ".githooks", "adversary_baseline"), "w").write("ROOT\n")
    open(os.path.join(rt2, ".githooks", "adversary_rules_epoch"), "w").write("hook-names ROOT\n")
    open(os.path.join(rt2, "first.py"), "w").write("first = 1\n")
    git(rt2, "add", "first.py", ".githooks/adversary_baseline", ".githooks/adversary_rules_epoch")
    r = gate(rt2, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    git(rt2, "commit", "-q", "-m", "cleared root")
    r = gate(rt2, "record")
    check("root_setup_record", r.returncode == 0, r.stderr[:150])
    r = audit(rt2)
    check("notarized_root_clean", r.returncode == 0 and "clean" in r.stdout, r.stdout[-250:])
    root_sha = git(rt2, "rev-parse", "HEAD").stdout.strip()
    check("root_epoch_applies_everywhere", a._epoch(rt2) == ("ROOT", "ok")
          and a._hook_names_apply(rt2, root_sha) is True, str(a._epoch(rt2)))
    # ROOT skips ancestry validation but must still report truncated history.
    root_shallow = os.path.join(tempfile.mkdtemp(prefix="advgate_root_shallow_"), "clone")
    git(rt2, "clone", "-q", "--depth", "1", "file:///" + rt2.replace("\\", "/"), root_shallow)
    git(root_shallow, "fetch", "-q", "origin", "refs/notes/adversary:refs/notes/adversary")
    check("root_shallow_epoch_unreadable", a._epoch_uncached(root_shallow) == ("ROOT", "unreadable"))
    r = audit(root_shallow, "--json")
    shallow_doc = json.loads(r.stdout)
    check("root_shallow_notarized_history_refused", r.returncode == 1 and any(
          v["commit"] == "rules-epoch" and "UNREADABLE" in v["detail"]
          for v in shallow_doc["violations"]), "rc=%s %s" % (r.returncode, r.stdout[-300:]))
    from unittest.mock import patch
    with patch.object(a, "_git", side_effect=[(0, "hook-names ROOT\n"), (128, "")]):
        check("root_shallow_probe_error_fails_closed",
              a._epoch_uncached(rt2) == ("ROOT", "unreadable"))

    # 12c. the window between arming and the first commit (gate round 1, gate_20260908-223749):
    # an EMPTY repo with a ROOT baseline has nothing to audit - exit 0, never a raw git error
    rt3 = tempfile.mkdtemp(prefix="advgate_root3_")
    subprocess.run([GIT, "init", "-q", rt3], capture_output=True)
    os.makedirs(os.path.join(rt3, ".githooks"), exist_ok=True)
    open(os.path.join(rt3, ".githooks", "adversary_baseline"), "w").write("ROOT\n")
    r = audit(rt3)
    check("root_baseline_empty_repo_nothing_to_audit", r.returncode == 0
          and "nothing to audit" in r.stdout, "rc=%s %s" % (r.returncode, (r.stdout + r.stderr)[-200:]))
    # 12f. --json on the same unborn repo must still emit a JSON document (attic re-anchor gate
    # round 1, gate_20260908-231849, LOW): rc 0 with a human line broke --json consumers
    r = audit(rt3, "--json")
    try:
        doc = json.loads(r.stdout)
    except ValueError:
        doc = None
    check("root_baseline_empty_repo_json", r.returncode == 0 and isinstance(doc, dict)
          and doc.get("baseline") == "ROOT" and doc.get("commits_walked") == 0
          and doc.get("violations") == [], "rc=%s %s" % (r.returncode, r.stdout[-200:]))
    # 12d. a BROKEN history read is never 'nothing to audit' (gate round 2, gate_20260908-224532,
    # MEDIUM): with commits present but HEAD's object missing (a broken clone), the ROOT
    # baseline must exit 2 (fail closed), never 0
    rt4 = tempfile.mkdtemp(prefix="advgate_root4_")
    subprocess.run([GIT, "init", "-q", rt4], capture_output=True)
    git(rt4, "config", "user.email", "t@t")
    git(rt4, "config", "user.name", "t")
    os.makedirs(os.path.join(rt4, ".githooks"), exist_ok=True)
    open(os.path.join(rt4, ".githooks", "adversary_baseline"), "w").write("ROOT\n")
    open(os.path.join(rt4, "a.py"), "w").write("a = 1\n")
    git(rt4, "add", "a.py")
    git(rt4, "commit", "-q", "--no-verify", "-m", "root")
    head4 = git(rt4, "rev-parse", "HEAD").stdout.strip()
    obj4 = os.path.join(rt4, ".git", "objects", head4[:2], head4[2:])   # the loose commit object
    os.chmod(obj4, 0o600)                                                # (read-only on Windows)
    os.remove(obj4)
    r = audit(rt4)
    check("root_baseline_broken_history_fails_closed", r.returncode == 2
          and "fail closed" in r.stdout, "rc=%s %s" % (r.returncode, (r.stdout + r.stderr)[-200:]))
    # 12e. a CORRUPT branch ref (present but unresolvable) is the third state (gate round 3,
    # gate_20260908-230240): rev-parse fails like an unborn head, yet there ARE commits - fail closed
    rt5 = tempfile.mkdtemp(prefix="advgate_root5_")
    subprocess.run([GIT, "init", "-q", rt5], capture_output=True)
    git(rt5, "config", "user.email", "t@t")
    git(rt5, "config", "user.name", "t")
    os.makedirs(os.path.join(rt5, ".githooks"), exist_ok=True)
    open(os.path.join(rt5, ".githooks", "adversary_baseline"), "w").write("ROOT\n")
    open(os.path.join(rt5, "a.py"), "w").write("a = 1\n")
    git(rt5, "add", "a.py")
    git(rt5, "commit", "-q", "--no-verify", "-m", "root")
    branch5 = git(rt5, "symbolic-ref", "HEAD").stdout.strip()          # refs/heads/<name>
    with open(os.path.join(rt5, ".git", *branch5.split("/")), "w") as f:
        f.write("notasha\n")
    r = audit(rt5)
    check("root_baseline_corrupt_ref_fails_closed", r.returncode == 2
          and "fail closed" in r.stdout, "rc=%s %s" % (r.returncode, (r.stdout + r.stderr)[-200:]))

    # Deleted loose/packed branch refs leave commits in the object store. ROOT must
    # refuse this hidden history in both text and JSON modes (2026-09-09 review finding).
    for packed in (False, True):
        hidden = tempfile.mkdtemp(prefix="advgate_hidden_")
        git(hidden, "init", "-q")
        os.makedirs(os.path.join(hidden, ".githooks"))
        with open(os.path.join(hidden, ".githooks", "adversary_baseline"), "w") as f:
            f.write("ROOT\n")
        with open(os.path.join(hidden, "hidden.py"), "w") as f:
            f.write("value = 1\n")
        git(hidden, "add", "hidden.py")
        git(hidden, "commit", "-qm", "hidden history fixture")
        if packed:
            git(hidden, "repack", "-ad")
            git(hidden, "pack-refs", "--all")
        branch = git(hidden, "symbolic-ref", "HEAD").stdout.strip()
        git(hidden, "update-ref", "-d", branch)
        for mode in ((), ("--json",)):
            r = audit(hidden, *mode)
            check("root_deleted_ref_%s_%s_fails_closed" % (packed, bool(mode)),
                  r.returncode == 2 and "fail closed" in r.stdout,
                  "rc=%s %s" % (r.returncode, (r.stdout + r.stderr)[-200:]))

    bad = {k: v for k, v in results.items() if not v[0]}
    print("\n%d/%d PASS" % (len(results) - len(bad), len(results)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
