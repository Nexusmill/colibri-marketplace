"""adversary_gate selftest: full lifecycle in a throwaway git repo, no network
(ADVERSARY_FAKE stubs the model). Exit 0 iff ALL PASS."""
import json
import os
import subprocess
import sys
import tempfile

GIT = r"C:\Program Files\Git\cmd\git.exe"
if not os.path.isfile(GIT):
    GIT = "git"                       # same fallback as the tools under test
GATE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "adversary-gate", "adversary_gate.py") \
    if "adversary-gate" not in os.path.dirname(os.path.abspath(__file__)) \
    else os.path.join(os.path.dirname(os.path.abspath(__file__)), "adversary_gate.py")
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


def main():
    tmp = tempfile.mkdtemp(prefix="advgate_")
    subprocess.run([GIT, "init", "-q", tmp], capture_output=True)
    git(tmp, "config", "user.email", "t@t")
    git(tmp, "config", "user.name", "t")

    # 1. unreviewed staged code -> check refuses
    open(os.path.join(tmp, "mod.py"), "w").write("def f():\n    return 1\n")
    git(tmp, "add", "mod.py")
    r = gate(tmp, "check")
    check("refuses_unreviewed", r.returncode == 1 and "unreviewed" in r.stderr, r.stderr[:120])

    # 2. faked CLEAR run -> clearance -> check passes
    r = gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    check("fake_clear_run", r.returncode == 0 and "CLEAR" in r.stdout, r.stdout[-120:])
    r = gate(tmp, "check")
    check("passes_cleared", r.returncode == 0, r.stderr[:120])

    # 3. re-edit after clearance -> stale -> refused
    open(os.path.join(tmp, "mod.py"), "a").write("# edited after review\n")
    git(tmp, "add", "mod.py")
    r = gate(tmp, "check")
    check("stale_after_edit", r.returncode == 1 and "stale" in r.stderr, r.stderr[:120])

    # 4. faked BLOCK -> no clearance, exit 1
    r = gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "BLOCK"})
    check("fake_block_refuses", r.returncode == 1)
    r = gate(tmp, "check")
    check("still_refused_after_block", r.returncode == 1)

    # 5. docs-only staging passes free
    git(tmp, "reset", "-q")
    open(os.path.join(tmp, "notes.md"), "w").write("docs only\n")
    git(tmp, "add", "notes.md")
    r = gate(tmp, "check")
    check("docs_pass_free", r.returncode == 0, r.stderr[:120])

    # 6. THE HOOK: a real `git commit` is refused, then passes after clearance
    hooks = os.path.join(tmp, ".githooks")
    os.makedirs(hooks, exist_ok=True)
    open(os.path.join(hooks, "pre-commit"), "w", newline="\n").write(
        '#!/bin/sh\nexec "%s" "%s" check\n' % (PY.replace("\\", "/"), GATE.replace("\\", "/")))
    git(tmp, "config", "core.hooksPath", ".githooks")
    git(tmp, "add", "mod.py", "notes.md")
    r = git(tmp, "commit", "-m", "should be blocked", expect_ok=False)
    check("hook_blocks_commit", r.returncode != 0 and "ADVERSARY GATE" in (r.stderr + r.stdout),
          (r.stderr + r.stdout)[:150])
    r = gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    check("clear_again", r.returncode == 0)
    r = git(tmp, "commit", "-m", "now allowed", expect_ok=False)
    check("hook_allows_after_clear", r.returncode == 0, (r.stderr + r.stdout)[:150])

    # 7. OVERRIDE is one-shot
    open(os.path.join(tmp, "mod.py"), "a").write("# another change\n")
    git(tmp, "add", "mod.py")
    os.makedirs(os.path.join(tmp, ".adversary"), exist_ok=True)
    open(os.path.join(tmp, ".adversary", "OVERRIDE"), "w").write("selftest emergency")
    r = gate(tmp, "check")
    ov_gone = not os.path.exists(os.path.join(tmp, ".adversary", "OVERRIDE"))
    check("override_oneshot", r.returncode == 0 and "OVERRIDDEN" in r.stderr and ov_gone)
    r = gate(tmp, "check")
    check("gated_again_after_override", r.returncode == 1)

    # 8. editing the gate's own hook is GATED (extensionless files under .githooks/)
    git(tmp, "reset", "-q")
    open(os.path.join(tmp, ".githooks", "pre-commit"), "a", newline="\n").write("# neutered?\n")
    git(tmp, "add", ".githooks/pre-commit")
    r = gate(tmp, "check")
    check("hook_edit_is_gated", r.returncode == 1, r.stderr[:120])

    # 9. deleting a code file is gated; clearing covers the removal
    git(tmp, "reset", "-q", "--hard")
    git(tmp, "rm", "-q", "mod.py")
    r = gate(tmp, "check")
    check("deletion_is_gated", r.returncode == 1 and "removal" in r.stderr, r.stderr[:120])
    r = gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    check("deletion_clearable", r.returncode == 0)
    r = gate(tmp, "check")
    check("deletion_passes_after_clear", r.returncode == 0, r.stderr[:120])

    # 10. record: the cleared deletion commit gets a durable note; record is idempotent
    # (re-arm first: test 8 STAGED the hook, so test 9's reset --hard deleted the
    # staged-not-committed file from the worktree - the repo was silently unarmed)
    os.makedirs(hooks, exist_ok=True)
    open(os.path.join(hooks, "pre-commit"), "w", newline="\n").write(
        '#!/bin/sh\nexec "%s" "%s" check\n' % (PY.replace("\\", "/"), GATE.replace("\\", "/")))
    r = git(tmp, "commit", "-m", "deletion commit", expect_ok=False)
    check("deletion_commit_ok", r.returncode == 0, (r.stderr + r.stdout)[:150])
    r = gate(tmp, "record")
    note = git(tmp, "notes", "--ref", "refs/notes/adversary", "show", "HEAD", expect_ok=False)
    data = json.loads(note.stdout) if note.returncode == 0 else {}
    check("record_writes_note", r.returncode == 0 and data.get("type") == "CLEAR"
          and "D:mod.py" in data.get("files", {}), (r.stderr or note.stderr)[:150])
    r = gate(tmp, "record")
    check("record_idempotent", r.returncode == 0)

    # 11. record fails CLOSED: a --no-verify bypass commit gets NO note and exit 1
    open(os.path.join(tmp, "bypass.py"), "w").write("x = 1\n")
    git(tmp, "add", "bypass.py")
    git(tmp, "commit", "--no-verify", "-m", "bypassed")
    r = gate(tmp, "record")
    note = git(tmp, "notes", "--ref", "refs/notes/adversary", "show", "HEAD", expect_ok=False)
    check("record_fail_closed", r.returncode == 1 and note.returncode != 0
          and "NOT notarized" in r.stderr, r.stderr[:150])

    # 12. OVERRIDE provenance: the note carries the reason, for the matching commit only
    open(os.path.join(tmp, "ov.py"), "w").write("y = 2\n")
    git(tmp, "add", "ov.py")
    open(os.path.join(tmp, ".adversary", "OVERRIDE"), "w").write("owner emergency")
    r = git(tmp, "commit", "-m", "override commit", expect_ok=False)
    check("override_commit_ok", r.returncode == 0, (r.stderr + r.stdout)[:150])
    r = gate(tmp, "record")
    note = git(tmp, "notes", "--ref", "refs/notes/adversary", "show", "HEAD", expect_ok=False)
    data = json.loads(note.stdout) if note.returncode == 0 else {}
    check("override_note", r.returncode == 0 and data.get("type") == "OVERRIDE"
          and "owner emergency" in data.get("reason", ""), (r.stderr or note.stderr)[:150])

    # 13. a stale override_used.json cannot bless a DIFFERENT commit
    open(os.path.join(tmp, ".adversary", "override_used.json"), "w").write(
        json.dumps({"reason": "stale", "when": "x", "staged": {"nope.py": "0" * 64}}))
    open(os.path.join(tmp, "st.py"), "w").write("z = 3\n")
    git(tmp, "add", "st.py")
    git(tmp, "commit", "--no-verify", "-m", "stale override attempt")
    r = gate(tmp, "record")
    note = git(tmp, "notes", "--ref", "refs/notes/adversary", "show", "HEAD", expect_ok=False)
    check("stale_override_discarded", r.returncode == 1 and note.returncode != 0
          and not os.path.exists(os.path.join(tmp, ".adversary", "override_used.json")),
          r.stderr[:150])

    # 14. .github/workflows/ is gated code (enforcement config, like .githooks/)
    os.makedirs(os.path.join(tmp, ".github", "workflows"), exist_ok=True)
    open(os.path.join(tmp, ".github", "workflows", "ci.yml"), "w").write("name: x\n")
    git(tmp, "add", ".github/workflows/ci.yml")
    r = gate(tmp, "check")
    check("workflows_are_gated", r.returncode == 1 and "ci.yml" in r.stderr, r.stderr[:150])

    # 15. PUSH GUARD: un-notarized history is refused; after baselining, the push
    # passes and the notes ref travels to the remote automatically
    git(tmp, "reset", "-q")
    remote_dir = tempfile.mkdtemp(prefix="advgate_remote_")
    subprocess.run([GIT, "init", "-q", "--bare", remote_dir], capture_output=True)
    git(tmp, "remote", "add", "origin", remote_dir)
    open(os.path.join(hooks, "pre-push"), "w", newline="\n").write(
        '#!/bin/sh\nexec "%s" "%s" check-push "$1"\n'
        % (PY.replace("\\", "/"), GATE.replace("\\", "/")))
    r = git(tmp, "push", "origin", "HEAD:refs/heads/main", expect_ok=False)
    check("push_guard_refuses_unnotarized", r.returncode != 0
          and "PUSH GUARD" in (r.stderr + r.stdout), (r.stderr + r.stdout)[:200])
    open(os.path.join(hooks, "adversary_baseline"), "w").write(
        git(tmp, "rev-parse", "HEAD").stdout.strip() + "\n")
    r = git(tmp, "push", "origin", "HEAD:refs/heads/main", expect_ok=False)
    check("push_guard_allows_baselined", r.returncode == 0, (r.stderr + r.stdout)[:200])
    r = git(remote_dir, "show-ref", "refs/notes/adversary", expect_ok=False)
    check("notes_travel_with_push", r.returncode == 0, (r.stdout + r.stderr)[:120])

    # 15b. REGRESSION (caught live): push with BOTH a remote sha and a baseline -
    # rev-list's --not toggles, so two --not flags would re-include pre-baseline
    # history and refuse a fully notarized push
    open(os.path.join(tmp, "after_base.py"), "w").write("ab = 1\n")
    git(tmp, "add", "after_base.py")
    gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    git(tmp, "commit", "-m", "post-baseline cleared", expect_ok=False)
    gate(tmp, "record")
    r = git(tmp, "push", "origin", "HEAD:refs/heads/main", expect_ok=False)
    check("push_guard_remote_plus_baseline", r.returncode == 0,
          (r.stderr + r.stdout)[:200])

    # 16. push-guard edge cases straight through the stdin protocol
    def push_stdin(payload):
        env = dict(os.environ)
        env["ADVERSARY_SELFTEST"] = "1"
        return subprocess.run([PY, GATE, "check-push", "origin"], input=payload,
                              capture_output=True, text=True, encoding="utf-8",
                              errors="replace", cwd=tmp, env=env)
    head = git(tmp, "rev-parse", "HEAD").stdout.strip()
    r = push_stdin("refs/heads/x %s refs/heads/x %s\n" % ("0" * 40, head))
    check("push_guard_skips_deletion", r.returncode == 0, r.stderr[:120])
    r = push_stdin("refs/notes/adversary %s refs/notes/adversary %s\n" % (head, "0" * 40))
    check("push_guard_skips_notes_ref", r.returncode == 0, r.stderr[:120])

    bad = {k: v for k, v in results.items() if not v[0]}
    print("\n%d/%d PASS" % (len(results) - len(bad), len(results)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
