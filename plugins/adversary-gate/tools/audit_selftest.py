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

    bad = {k: v for k, v in results.items() if not v[0]}
    print("\n%d/%d PASS" % (len(results) - len(bad), len(results)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
