"""adversary_gate selftest: full lifecycle in a throwaway git repo, no network
(ADVERSARY_FAKE stubs the model). Exit 0 iff ALL PASS."""
import hashlib
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
    # Historical clearance-state tests stay passive; auto-review has separate coverage.
    if args and args[0] == "check":
        args = ("verify",) + args[1:]

    env = dict(os.environ)
    env["ADVERSARY_SELFTEST"] = "1"
    env.update(env_extra or {})
    return subprocess.run([PY, GATE] + list(args), capture_output=True, text=True,
                          encoding="utf-8", errors="replace", cwd=repo, env=env)


def main():
    tmp = tempfile.mkdtemp(prefix="advgate_")
    os.environ["ADVERSARY_SELFTEST"] = "1"          # inherited by git-spawned hooks too
    os.environ["ADVERSARY_FAKE"] = "BLOCK"          # hooks must never call a paid reviewer
    os.environ["DOCSCAN_FAKE"] = "CLEAR"            # docs semantic scan stubbed CLEAR by
    #                                                 default; docscan tests below flip it
    subprocess.run([GIT, "init", "-q", tmp], capture_output=True)
    git(tmp, "config", "user.email", "t@t")
    git(tmp, "config", "user.name", "t")

    # 0. code-class coverage (EV-029, 2026-09-04): Caliper's tools/git-guard.mjs - the security
    # guard itself - sailed through a gate run unreviewed because CODE_EXTS had no ES-module /
    # CommonJS / TypeScript-module extensions. The reviewer must see every JS/TS module form.
    sys.path.insert(0, os.path.dirname(GATE))
    import adversary_gate as _g
    check("code_exts_js_ts_module_forms",
          all(_g._is_code(p) for p in ("tools/git-guard.mjs", "lib/x.cjs", "src/a.mts", "src/b.cts")),
          "missing: %s" % [p for p in ("tools/git-guard.mjs", "lib/x.cjs", "src/a.mts", "src/b.cts")
                           if not _g._is_code(p)])
    check("code_exts_docs_still_not_code", not _g._is_code("README.md") and not _g._is_code("notes.txt"))
    # 2026-09-06 (universal arming): extensionless git HOOK files are code wherever they live -
    # the canonical shims in adversary-gate/ and the machine-wide dispatchers in
    # adversary-gate/hooks/ were never in the staged-code list (only .githooks/ was gated), so
    # the single source of every vendored shim could be edited un-reviewed.
    check("hook_files_are_code_anywhere",
          all(_g._is_code(p) for p in ("adversary-gate/hooks/pre-commit", "adversary-gate/pre-push",
                                       "adversary-gate/post-commit", "x/y/pre-commit")),
          "missing: %s" % [p for p in ("adversary-gate/hooks/pre-commit", "adversary-gate/pre-push",
                                       "adversary-gate/post-commit", "x/y/pre-commit") if not _g._is_code(p)])
    check("hook_named_docs_still_not_code", not _g._is_code("docs/pre-commit.md")
          and not _g._is_code("hooks/README"))

    # 0b. the DOCS feed must survive colour and external-diff configuration (EV-031, found by the
    # gate reviewing its own distributed copy): with `color.diff=always` git paints ANSI codes on
    # a pipe and no line starts with '+'; with GIT_EXTERNAL_DIFF set git runs the driver instead of
    # emitting a diff. Either way the local docs scan would receive nothing and pass silently.
    open(os.path.join(tmp, "notes.md"), "w").write("plain line\nMARKER-EV031-added-doc-line\n")
    git(tmp, "add", "notes.md")
    git(tmp, "config", "color.diff", "always")
    _cwd = os.getcwd()
    os.chdir(tmp)
    try:
        try:
            _doc = _g._staged_doc_added_text(["notes.md"])
        except SystemExit as e:
            _doc = "SYSTEMEXIT: %s" % e
        check("docs_feed_survives_color_diff_always", "MARKER-EV031-added-doc-line" in _doc
              and "\x1b" not in _doc, repr(_doc[:120]))
        os.environ["GIT_EXTERNAL_DIFF"] = "no-such-diff-driver-ev031"
        try:
            _doc = _g._staged_doc_added_text(["notes.md"])
        except SystemExit as e:
            _doc = "SYSTEMEXIT: %s" % e
        check("docs_feed_survives_external_diff_env", "MARKER-EV031-added-doc-line" in _doc, repr(_doc[:120]))
    finally:
        os.environ.pop("GIT_EXTERNAL_DIFF", None)
        os.chdir(_cwd)
    git(tmp, "config", "--unset", "color.diff")
    git(tmp, "reset", "-q", "notes.md")
    os.remove(os.path.join(tmp, "notes.md"))

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
    check("hook_requests_automatic_review",
          "requesting automatic independent review" in (r.stderr + r.stdout))
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
    # 15a. ROOT (armed at birth) is a SENTINEL, never a revision (gate round 2,
    # gate_20260908-224532, LOW): a ref literally named ROOT at HEAD must not exclude anything
    open(os.path.join(hooks, "adversary_baseline"), "w").write("ROOT\n")
    git(tmp, "tag", "ROOT", "HEAD")
    r = git(tmp, "push", "origin", "HEAD:refs/heads/main", expect_ok=False)
    check("push_guard_root_baseline_is_not_a_ref", r.returncode != 0
          and "PUSH GUARD" in (r.stderr + r.stdout), (r.stderr + r.stdout)[:200])
    git(tmp, "tag", "-d", "ROOT")
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
    rc = git(tmp, "commit", "-m", "post-baseline cleared", expect_ok=False)
    # assert the CLEARED commit actually landed: without this a regression that refuses it
    # leaves HEAD unchanged, the push is "up-to-date" (rc 0), and the check below false-passes.
    check("post_baseline_commit_ok", rc.returncode == 0, (rc.stderr + rc.stdout)[:150])
    gate(tmp, "record")
    r = git(tmp, "push", "origin", "HEAD:refs/heads/main", expect_ok=False)
    check("push_guard_remote_plus_baseline", r.returncode == 0,
          (r.stderr + r.stdout)[:200])

    # 15c. A NEW BRANCH must not re-scan history the remote already holds (push-guard catch
    # 2026-09-09: a four-commit docs branch on Nexusmill was refused for a chunk in a doc
    # published two days earlier - with the remote tip unknown the guard excluded only the
    # baseline and re-fed 124 published commits to the docs model, whose chunk boundaries had
    # shifted). Commits reachable from the remote's OWN tracking refs are published there.
    open(os.path.join(tmp, "pub.md"), "w").write("published prose the fake docscan will BLOCK later\n")
    git(tmp, "add", "pub.md")
    rc = git(tmp, "commit", "-m", "published doc", expect_ok=False)
    check("published_doc_commit_ok", rc.returncode == 0, (rc.stderr + rc.stdout)[:150])
    r = git(tmp, "push", "origin", "HEAD:refs/heads/main", expect_ok=False)
    check("published_doc_push_ok", r.returncode == 0, (r.stderr + r.stdout)[:200])
    open(os.path.join(tmp, "codeonly.py"), "w").write("co = 1\n")
    git(tmp, "add", "codeonly.py")
    gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    rc = git(tmp, "commit", "-m", "code only on a new branch", expect_ok=False)
    check("codeonly_commit_ok", rc.returncode == 0, (rc.stderr + rc.stdout)[:150])
    gate(tmp, "record")
    env_block = dict(os.environ); env_block["ADVERSARY_SELFTEST"] = "1"; env_block["DOCSCAN_FAKE"] = "BLOCK"
    r = subprocess.run([GIT, "push", "origin", "HEAD:refs/heads/feature-new"], capture_output=True, text=True,
                       encoding="utf-8", errors="replace", cwd=tmp, env=env_block)
    check("new_branch_skips_published_docs", r.returncode == 0,
          "rc=%d %s" % (r.returncode, (r.stderr + r.stdout)[-300:]))
    check("new_branch_published_skip_is_loud", "already on origin's tracking refs" in (r.stderr + r.stdout)
          and "docs model" in (r.stderr + r.stdout), (r.stderr + r.stdout)[-300:])
    open(os.path.join(tmp, "newdoc.md"), "w").write("a fresh outgoing doc line\n")
    git(tmp, "add", "newdoc.md")
    git(tmp, "commit", "-q", "-m", "new doc on a new branch")
    r = subprocess.run([GIT, "push", "origin", "HEAD:refs/heads/feature-new2"], capture_output=True, text=True,
                       encoding="utf-8", errors="replace", cwd=tmp, env=env_block)
    check("new_branch_new_doc_still_scanned", r.returncode != 0 and "PUSH GUARD" in (r.stderr + r.stdout),
          "rc=%d %s" % (r.returncode, (r.stderr + r.stdout)[-300:]))
    git(tmp, "reset", "-q", "--hard", "HEAD~1")
    # 15d. (gate round 1 on this change, gate_20260909-151127) a DANGLING tracking symref - the
    # remote's default branch renamed or deleted server-side leaves refs/remotes/origin/HEAD
    # pointing at nothing, listed with a null id - must not crash the guard on a new-ref push
    git(tmp, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/renamed-away")
    r = subprocess.run([GIT, "push", "origin", "HEAD:refs/heads/feature-new3"], capture_output=True, text=True,
                       encoding="utf-8", errors="replace", cwd=tmp, env=env_block)
    check("new_branch_dangling_tracking_ref_no_crash", r.returncode == 0 and "Traceback" not in (r.stderr + r.stdout)
          and "failed:" not in (r.stderr + r.stdout), "rc=%d %s" % (r.returncode, (r.stderr + r.stdout)[-300:]))
    git(tmp, "symbolic-ref", "--delete", "refs/remotes/origin/HEAD")
    # 15e. the hard-literal recipe on a NEW ref anchors at the FORK POINT (the merge-base with the
    # remote's tips), not at an arbitrary tracking tip, and no longer claims the tip is unknown
    fork = git(tmp, "rev-parse", "HEAD").stdout.strip()
    aws_15e = "AKIA" + "ABCDEFGHIJKLMNOP"                 # built from parts, never a literal
    open(os.path.join(tmp, "leak_new.py"), "w").write("k = '%s'\n" % aws_15e)
    git(tmp, "add", "leak_new.py")
    gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    git(tmp, "commit", "-q", "-m", "literal on a new branch", expect_ok=False)
    gate(tmp, "record")
    r = subprocess.run([GIT, "push", "origin", "HEAD:refs/heads/feature-leak"], capture_output=True, text=True,
                       encoding="utf-8", errors="replace", cwd=tmp, env=env_block)
    out = r.stderr + r.stdout
    check("new_branch_recipe_anchors_at_fork_point", r.returncode != 0 and "REFUSED" in out
          and ("rebase -i " + fork[:12]) in out and "tip is unknown" in out,
          "rc=%d %s" % (r.returncode, out[-400:]))
    git(tmp, "reset", "-q", "--hard", "HEAD~1")
    # 15f. (gate round 2 on this change, gate_20260909-153226) EIGHT HUNDRED tracking refs: a
    # sha-per-ref exclusion would exceed the Windows command-line ceiling (~790 refs) and crash
    # the guard on every new-ref push; the exclusion must be a ref glob, one argv token
    for start in range(0, 1500, 100):
        git(tmp, "fetch", "-q", ".", *["HEAD:refs/remotes/origin/bulk/%d" % k for k in range(start, start + 100)])
    n_refs = git(tmp, "for-each-ref", "--count=3000", "--format=x", "refs/remotes/origin/").stdout.count("x")
    check("bulk_tracking_refs_fixture", n_refs >= 1500, "refs=%d" % n_refs)
    r = subprocess.run([GIT, "push", "origin", "HEAD:refs/heads/feature-new4"], capture_output=True, text=True,
                       encoding="utf-8", errors="replace", cwd=tmp, env=env_block)
    check("new_branch_many_tracking_refs_no_crash", r.returncode == 0 and "Traceback" not in (r.stderr + r.stdout)
          and "WinError" not in (r.stderr + r.stdout), "rc=%d %s" % (r.returncode, (r.stderr + r.stdout)[-300:]))
    main_branch = git(tmp, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip()
    git(tmp, "checkout", "-q", "--orphan", "orphan-hist")
    git(tmp, "rm", "-rfq", "--cached", ".")
    open(os.path.join(tmp, "orphan.md"), "w").write("orphan prose the fake docscan would BLOCK\n")
    git(tmp, "add", "orphan.md")
    git(tmp, "commit", "-q", "-m", "orphan doc")
    git(tmp, "fetch", "-q", ".", "HEAD:refs/remotes/origin/bulk/orphan")      # nested tracking ref
    open(os.path.join(tmp, "orphan_code.py"), "w").write("oc = 1\n")
    git(tmp, "add", "orphan_code.py")
    gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    rc = git(tmp, "commit", "-q", "-m", "code on the orphan history", expect_ok=False)
    check("orphan_code_commit_ok", rc.returncode == 0, (rc.stderr + rc.stdout)[:150])
    gate(tmp, "record")
    r = subprocess.run([GIT, "push", "origin", "HEAD:refs/heads/feature-orphan"], capture_output=True, text=True,
                       encoding="utf-8", errors="replace", cwd=tmp, env=env_block)
    check("new_branch_nested_tracking_ref_excludes_docs", r.returncode == 0 and "REFUSED" not in (r.stderr + r.stdout),
          "rc=%d %s" % (r.returncode, (r.stderr + r.stdout)[-300:]))
    git(tmp, "checkout", "-q", "-f", main_branch)
    git(tmp, "branch", "-q", "-D", "orphan-hist")

    # 16. push-guard edge cases straight through the stdin protocol
    def push_stdin(payload, env_extra=None):
        env = dict(os.environ)
        env["ADVERSARY_SELFTEST"] = "1"
        if env_extra:
            env.update(env_extra)
        return subprocess.run([PY, GATE, "check-push", "origin"], input=payload,
                              capture_output=True, text=True, encoding="utf-8",
                              errors="replace", cwd=tmp, env=env)
    head = git(tmp, "rev-parse", "HEAD").stdout.strip()
    r = push_stdin("refs/heads/x %s refs/heads/x %s\n" % ("0" * 40, head))
    check("push_guard_skips_deletion", r.returncode == 0, r.stderr[:120])
    r = push_stdin("refs/notes/adversary %s refs/notes/adversary %s\n" % (head, "0" * 40))
    check("push_guard_skips_notes_ref", r.returncode == 0, r.stderr[:120])

    # P1-P5. PUSH-TIME SECRET BARRIER (EV-046, owner ruling 2026-09-07: "instead of blocking
    # on commit, force a git scan before each push"). Commits now carry warned secrets; the
    # push guard scans every outgoing commit's ADDED lines: a HARD literal REFUSES the push
    # with the rewrite recipe, the soft assignment heuristic warns, and the docs model re-runs
    # over the outgoing doc lines (the fake stub here) and refuses on a block. Values built at
    # runtime (aws / gwpw from row 19) and never printed by the guard.
    aws_p = "AKIA" + "ABCDEFGHIJKLMNOP"
    gwpw_p = "D1204" + "-l0723!"

    def cleared_commit(fname, content, msg):
        open(os.path.join(tmp, fname), "w").write(content)
        git(tmp, "add", fname)
        gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
        rc = git(tmp, "commit", "-q", "-m", msg, expect_ok=False)
        gate(tmp, "record")
        return rc.returncode
    prev = git(tmp, "rev-parse", "HEAD").stdout.strip()
    rc1 = cleared_commit("leak.py", "aws = '%s'\n" % aws_p, "hard literal (warned at commit)")
    head = git(tmp, "rev-parse", "HEAD").stdout.strip()
    r = push_stdin("refs/heads/main %s refs/heads/main %s\n" % (head, prev))
    check("push_refused_on_hard_literal",
          rc1 == 0 and r.returncode == 1 and "REFUSED" in r.stderr and "leak.py:1" in r.stderr
          and "rebase" in r.stderr and aws_p not in r.stderr, "rc1=%s %s" % (rc1, r.stderr[:300]))
    git(tmp, "reset", "-q", "--hard", prev)               # the unpushed rewrite the recipe asks for
    rc2 = cleared_commit("cfg2.py", "password = '%s'\n" % gwpw_p, "soft heuristic value")
    head = git(tmp, "rev-parse", "HEAD").stdout.strip()
    r = push_stdin("refs/heads/main %s refs/heads/main %s\n" % (head, prev))
    check("push_warns_on_soft_heuristic",
          rc2 == 0 and r.returncode == 0 and "WARNING" in r.stderr and "cfg2.py:1" in r.stderr
          and gwpw_p not in r.stderr, "rc2=%s %s" % (rc2, r.stderr[:300]))
    prev2 = head
    open(os.path.join(tmp, "guide2.md"), "w").write(
        "# guide\nthe shop wifi password is spelled out here in prose\n")
    git(tmp, "add", "guide2.md")
    git(tmp, "commit", "-q", "-m", "docs prose", expect_ok=False)
    head = git(tmp, "rev-parse", "HEAD").stdout.strip()
    r = push_stdin("refs/heads/main %s refs/heads/main %s\n" % (head, prev2),
                   env_extra={"DOCSCAN_FAKE": "BLOCK"})
    check("push_refused_on_docs_model_block",
          r.returncode == 1 and "docs reviewer" in r.stderr, r.stderr[:300])
    r = push_stdin("refs/heads/main %s refs/heads/main %s\n" % (head, prev2),
                   env_extra={"DOCSCAN_FAKE": "CLEAR"})
    check("push_allowed_when_docs_model_clear", r.returncode == 0, r.stderr[:300])
    # P5: a MERGE commit bringing a hard literal in from a side branch (first-parent diff)
    docs_head = head
    git(tmp, "checkout", "-q", "-b", "side")
    cleared_commit("leak2.py", "aws2 = '%s'\n" % aws_p, "side leak")
    git(tmp, "checkout", "-q", "-")
    git(tmp, "merge", "-q", "--no-ff", "-m", "merge side", "side", expect_ok=False)
    head = git(tmp, "rev-parse", "HEAD").stdout.strip()
    r = push_stdin("refs/heads/main %s refs/heads/main %s\n" % (head, docs_head))
    check("push_refused_on_merged_literal",
          r.returncode == 1 and "REFUSED" in r.stderr and "leak2.py:1" in r.stderr, r.stderr[:300])
    git(tmp, "reset", "-q", "--hard", docs_head)
    git(tmp, "branch", "-q", "-D", "side")
    # P6. GATE CATCH (gate_20260907-171348, HIGH): a pusher with diff.noprefix=true strips the
    # b/ prefix the parser keys on - without pinned prefixes nothing was scanned, silently.
    git(tmp, "config", "diff.noprefix", "true")
    rc6 = cleared_commit("leak3.py", "aws3 = '%s'\n" % aws_p, "hard literal under noprefix")
    head = git(tmp, "rev-parse", "HEAD").stdout.strip()
    r = push_stdin("refs/heads/main %s refs/heads/main %s\n" % (head, docs_head))
    git(tmp, "config", "--unset", "diff.noprefix")
    check("push_refused_despite_noprefix_config",
          rc6 == 0 and r.returncode == 1 and "leak3.py:1" in r.stderr, "rc6=%s %s" % (rc6, r.stderr[:200]))
    git(tmp, "reset", "-q", "--hard", docs_head)
    # P7. GATE CATCH (gate_20260907-171348, MEDIUM): a content line '++ x' arrives in the diff
    # as '+++ x' - it is content inside a hunk, not a header; a literal AFTER it must still be
    # seen and the path must not be corrupted.
    rc7 = cleared_commit("plus.py", "++ x\n+++ b/phantom.py\ntoken_line = '%s'\n" % aws_p,
                         "plus-plus content then a literal")
    head = git(tmp, "rev-parse", "HEAD").stdout.strip()
    r = push_stdin("refs/heads/main %s refs/heads/main %s\n" % (head, docs_head))
    check("push_refused_after_plusplus_content_line",
          rc7 == 0 and r.returncode == 1 and "plus.py:3" in r.stderr and "phantom" not in r.stderr,
          "rc7=%s %s" % (rc7, r.stderr[:200]))
    git(tmp, "reset", "-q", "--hard", docs_head)
    # P8. GATE CATCH (gate_20260907-171348, advisory): AWS's own documented example key is
    # public by definition - it must not make a tutorial commit unpushable, nor warn at commit.
    ex_key = "AKIA" + "IOSFODNN7EXAMPLE"
    rc8 = cleared_commit("tutorial.md", "example: %s (from the AWS docs)\n" % ex_key, "aws docs example")
    head = git(tmp, "rev-parse", "HEAD").stdout.strip()
    r = push_stdin("refs/heads/main %s refs/heads/main %s\n" % (head, docs_head),
                   env_extra={"DOCSCAN_FAKE": "CLEAR"})
    check("documented_example_key_not_refused", rc8 == 0 and r.returncode == 0
          and "REFUSED" not in r.stderr, "rc8=%s %s" % (rc8, r.stderr[:200]))
    git(tmp, "reset", "-q", "--hard", docs_head)
    # P9. GATE CATCH (gate_20260907-172339, MEDIUM): the tutorial idiom - the NAME of a secret
    # used as its own value (a URL whose credential part is the word password; the ssh
    # password flag given the word secret) - is a placeholder, not a credential: no warning
    # at commit, no refusal at push. (Spelled in prose here so this source never self-trips.)
    open(os.path.join(tmp, "db_notes.md"), "w").write(
        "connect with postgres://user:password@localhost/db\nor: sshpass -p secret ssh box\n")
    git(tmp, "add", "db_notes.md")
    r = gate(tmp, "check")
    check("secret_name_as_value_not_flagged", r.returncode == 0 and "WARNING" not in r.stderr,
          r.stderr[:200])
    git(tmp, "commit", "-q", "-m", "db notes", expect_ok=False)
    head = git(tmp, "rev-parse", "HEAD").stdout.strip()
    r = push_stdin("refs/heads/main %s refs/heads/main %s\n" % (head, docs_head),
                   env_extra={"DOCSCAN_FAKE": "CLEAR"})
    check("push_allows_secret_name_as_value", r.returncode == 0 and "REFUSED" not in r.stderr,
          r.stderr[:200])
    git(tmp, "reset", "-q", "--hard", docs_head)
    # P10. GATE CATCH (gate_20260907-172339, LOW): the owner's OVERRIDE must not dead-end at
    # push - a commit carrying an OVERRIDE note (a provenance-matched ruling) passes the
    # barrier with a warning naming the note.
    open(os.path.join(tmp, "ruled.py"), "w").write("ruled = '%s'\n" % aws_p)
    git(tmp, "add", "ruled.py")
    os.makedirs(os.path.join(tmp, ".adversary"), exist_ok=True)
    open(os.path.join(tmp, ".adversary", "OVERRIDE"), "w").write("owner rules: fixture key")
    git(tmp, "commit", "-q", "-m", "owner-overridden literal", expect_ok=False)
    gate(tmp, "record")
    head = git(tmp, "rev-parse", "HEAD").stdout.strip()
    note = git(tmp, "notes", "--ref", "refs/notes/adversary", "show", head, expect_ok=False)
    r = push_stdin("refs/heads/main %s refs/heads/main %s\n" % (head, docs_head))
    check("push_allows_owner_overridden_literal",
          "OVERRIDE" in note.stdout and r.returncode == 0 and "OVERRIDE note" in r.stderr
          and "REFUSED" not in r.stderr, "note=%s %s" % (note.stdout[:60], r.stderr[:200]))
    git(tmp, "reset", "-q", "--hard", docs_head)
    # P11. GATE CATCH (gate_20260907-172339, MEDIUM): a shallow clone's boundary commit has no
    # parent here - it must be SKIPPED with a loud line (it came from the remote), not diffed
    # against the empty tree; the commit on top is still scanned normally.
    shallow = tempfile.mkdtemp(prefix="advgate_shallow_")
    sc_env = dict(os.environ, ADVERSARY_SELFTEST="1", DOCSCAN_FAKE="CLEAR")
    subprocess.run([GIT, "clone", "-q", "--depth", "1", "file:///" + remote_dir.replace("\\", "/"),
                    shallow], capture_output=True, env=sc_env)
    git(shallow, "config", "user.email", "t@t")
    git(shallow, "config", "user.name", "t")
    open(os.path.join(shallow, "shallow_note.md"), "w").write("# shallow\nplain prose\n")
    git(shallow, "add", "shallow_note.md")
    git(shallow, "commit", "-q", "-m", "on top of a shallow boundary", expect_ok=False)
    s_head = git(shallow, "rev-parse", "HEAD").stdout.strip()
    # 2026-09-09 (new-branch docs-feed exclusion, gate rounds 3-4): the boundary is origin/main's
    # tip. The floor still WALKS it (the full outgoing set) and skips it loudly as before; the
    # docs model is not re-fed it, and that skip is loud too - both lines, no refusal
    r = subprocess.run([PY, GATE, "check-push", "origin"],
                       input="refs/heads/main %s refs/heads/main %s\n" % (s_head, "0" * 40),
                       capture_output=True, text=True, encoding="utf-8", errors="replace",
                       cwd=shallow, env=sc_env)
    check("shallow_boundary_walked_and_docs_feed_narrowed_loudly", r.returncode == 0
          and "shallow-clone boundary" in r.stderr and "already on origin's tracking refs" in r.stderr
          and "REFUSED" not in r.stderr, "rc=%s %s" % (r.returncode, r.stderr[:300]))
    # without the tracking ref (a URL-only remote, a clone that never fetched it) the boundary
    # IS in the range and must be skipped loudly, never diffed against the empty tree
    git(shallow, "branch", "-dr", "origin/main")
    r = subprocess.run([PY, GATE, "check-push", "origin"],
                       input="refs/heads/main %s refs/heads/main %s\n" % (s_head, "0" * 40),
                       capture_output=True, text=True, encoding="utf-8", errors="replace",
                       cwd=shallow, env=sc_env)
    check("shallow_boundary_skipped_loudly", r.returncode == 0 and "shallow-clone boundary" in r.stderr
          and "REFUSED" not in r.stderr, "rc=%s %s" % (r.returncode, r.stderr[:240]))

    # 17. REGRESSION (gate fail-open fix): a non-ASCII code path is GATED, not dropped.
    # Under git's default core.quotepath the path is C-quoted; the old splitlines()/strip()
    # listers skipped it and the commit passed as docs-only. -z parsing closes it.
    git(tmp, "reset", "-q")
    open(os.path.join(tmp, "café.py"), "w", encoding="utf-8").write("x = 1\n")
    git(tmp, "add", "-A")
    r = gate(tmp, "check")
    check("nonascii_path_gated", r.returncode == 1 and "unreviewed" in r.stderr, r.stderr[:150])

    # 18. REGRESSION (gate fail-open fix): a typechange (T) of a code file is GATED.
    # A gated file swapped for a symlink/gitlink was status 'T', invisible to the
    # ACMR/DR listers -> the hook could be neutered ungated. ACMRT closes it.
    git(tmp, "reset", "-q", "--hard")
    open(os.path.join(tmp, "tc.py"), "w").write("t = 1\n")
    git(tmp, "add", "tc.py")
    gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    os.makedirs(hooks, exist_ok=True)
    open(os.path.join(hooks, "pre-commit"), "w", newline="\n").write(
        '#!/bin/sh\nexec "%s" "%s" check\n' % (PY.replace("\\", "/"), GATE.replace("\\", "/")))
    git(tmp, "config", "core.hooksPath", ".githooks")
    git(tmp, "commit", "-m", "add tc.py", expect_ok=False)
    blob = subprocess.run([GIT, "-C", tmp, "hash-object", "-w", "--stdin"],
                          input="target", capture_output=True, text=True).stdout.strip()
    git(tmp, "update-index", "--cacheinfo", "120000,%s,tc.py" % blob)
    r = gate(tmp, "check")
    check("typechange_gated", r.returncode == 1
          and ("stale" in r.stderr or "unreviewed" in r.stderr), r.stderr[:150])

    # 19. LOCAL SECRET PRE-SCAN (layered-enforcement fix 2026-09-02): a secret in a
    # DOCS-ONLY commit is now refused (was waved through), and `run` blocks WITHOUT
    # calling the model. Secrets built at runtime so THIS file carries no trippable literal.
    git(tmp, "reset", "-q", "--hard")
    aws = "AKIA" + "ABCDEFGHIJKLMNOP"
    gwpw = "D1204" + "-l0723!"                       # 12-char mixed = the EV-023 gateway shape
    open(os.path.join(tmp, "leak.md"), "w").write(
        "# notes\naws key %s\nssh password='%s'\n" % (aws, gwpw))
    git(tmp, "add", "leak.md")
    # EV-046 (owner ruling 2026-09-07, the "warn version"): a secret hit at COMMIT time WARNS
    # and never blocks. Values never printed. (The push-time barrier is the NEXT task.)
    r = gate(tmp, "check")
    check("secret_in_docs_warns", r.returncode == 0 and "WARNING" in r.stderr
          and "leak.md:2 " in r.stderr and "leak.md:3 " in r.stderr, r.stderr[:200])
    # 19u. UNIT: _scrub_text redacts every value (literal AND assignment) and keeps the rest;
    # a line with two literals is redacted twice; hits are per line.
    sc, hits = _g._scrub_text("aws %s here\npassword = '%s'\ntwo %s and %s\nplain\n"
                              % (aws, gwpw, aws, aws))
    check("scrub_removes_values", aws not in sc and gwpw not in sc and "plain" in sc, sc[:120])
    check("scrub_labels", "<REDACTED:aws-access-key-id>" in sc
          and "<REDACTED:secret-assignment>" in sc, sc[:160])
    check("scrub_hits_and_multi", len(hits) == 4
          and sc.count("<REDACTED:aws-access-key-id>") == 3, str(hits))
    # 19u2. GATE CATCH (gate_20260907-161313, HIGH): only the LEFTMOST value on a line was
    # redacted - after one redaction the placeholder re-matched, the guard fired and the loop
    # broke, so a SECOND assignment-form secret (or a second sshpass value) on the same line
    # was transmitted verbatim. Every value on the line must be redacted and counted.
    gwpw2 = "R4nd0" + "-m9876!"                      # a second 12-char mixed-class value
    two = ("connect(password=\"%s\", api_key=\"%s\")\n"
           "run sshpass -p %s ssh a && sshpass -p %s ssh b\n" % (gwpw, gwpw2, gwpw, gwpw2))
    sc2, h2 = _g._scrub_text(two)
    check("scrub_all_values_on_a_line",
          gwpw not in sc2 and gwpw2 not in sc2 and sc2.count("<REDACTED:") == 4 and len(h2) == 4,
          "%s | %s" % (sc2[:200], h2))
    # 19u3. GATE CATCH (gate_20260907-162135, HIGH): a private-key BLOCK is many lines - the
    # header matches the literal, the base64 body matches nothing. Every line from BEGIN
    # through END must be redacted (in a diff the body lines carry a '+'/'-' prefix too).
    body = "AAAAB3NzaC1" + hashlib.sha256(b"selftest-pem").hexdigest()
    # markers ASSEMBLED at runtime so this source never carries a key-shaped literal (gate
    # catch gate_20260907-164516: literal markers tripped the floor on the suite's own commits
    # and turned row 23's no-self-trip guard vacuous)
    pb, pe, pk = "-----BEGIN ", "-----END ", "PRIVATE KEY-----"
    pem = ("before\n%sOPENSSH %s\n+%s\n%s\n%sOPENSSH %s\nafter line\n"
           % (pb, pk, body, body[::-1], pe, pk))
    sc3, h3 = _g._scrub_text(pem)
    check("scrub_private_key_whole_block",
          body not in sc3 and body[::-1] not in sc3 and "END OPENSSH" not in sc3
          and sc3.startswith("before\n") and sc3.rstrip("\n").endswith("after line")
          and len(h3) == 4, "%s | %s" % (sc3[:160], h3))
    # 19u4. GATE CATCH (gate_20260907-162135, LOW): the per-pattern iteration cap must bound
    # WORK, never leakage - past the cap the rest of the line is redacted wholesale.
    many = " ".join([aws] * 40)
    sc4, h4 = _g._scrub_text(many + "\n")
    check("scrub_cap_never_leaks", aws not in sc4 and "cap" in sc4, sc4[-120:])
    # 19u5. GATE CATCH (gate_20260907-163011, MEDIUM): a BEGIN marker with no END must not
    # devour the rest of the payload (fail-OPEN: the reviewer would clear a gutted payload).
    # The block is capped, an 'unterminated' hit is recorded, and per-line scrubbing resumes.
    frag = pb + "RSA " + pk + "\n" + "\n".join("body%d" % k for k in range(300)) + "\nafter line\n"
    sc5, h5 = _g._scrub_text(frag)
    check("scrub_unterminated_block_capped",
          "after line" in sc5 and "body299" in sc5 and "body0\n" not in sc5
          and any(lab == "private-key-block:unterminated" for _, lab in h5), h5[-3:])
    # 19u6. GATE CATCH (gate_20260907-163540, HIGH): key material on the header's OWN line -
    # a one-line PEM (BEGIN ... body ... END on one line) and a header glued to its first
    # base64 chunk with continuation lines - must be redacted from the header to the end of
    # the line; the one-line form must NOT arm the block (the next line survives).
    one = "%sRSA %s%s%sRSA %s tail\nnext line\n" % (pb, pk, body, pe, pk)
    sc6, h6 = _g._scrub_text(one)
    check("scrub_one_line_pem", body not in sc6 and "next line" in sc6 and " tail" not in sc6
          and len(h6) == 1, "%s | %s" % (sc6[:120], h6))
    glued = "%sRSA %s%s\n%s\n%sRSA %s\nlater\n" % (pb, pk, body, body[::-1], pe, pk)
    sc7, h7 = _g._scrub_text(glued)
    check("scrub_glued_header_chunk", body not in sc7 and body[::-1] not in sc7
          and "later" in sc7 and len(h7) == 3, "%s | %s" % (sc7[:120], h7))
    # 19u7. GATE CATCH (gate_20260907-165431, MEDIUM): a >4096-char physical line hiding an
    # assignment secret behind a lone CR (or any splitlines() separator) must still be
    # scrubbed - the heuristic gate applies per segment, as the old per-line scanner saw it.
    exotic = "x" * 5000 + "\r" + "password = '%s'\n" % gwpw
    sc8, h8 = _g._scrub_text(exotic)
    check("scrub_exotic_separator_segment", gwpw not in sc8 and len(h8) == 1
          and sc8.startswith("x" * 5000 + "\r"), "%s | %s" % (sc8[-80:], h8))
    # 19u8. GATE CATCH (gate_20260907-165431, LOW): the assignment cap must redact the rest of
    # the line unconditionally - 33 placeholder matches consume the iterations, the real value
    # after them must not ship.
    capline = " ".join(["pwd=changeme"] * 33) + " password='%s'\n" % gwpw   # pwd IS a key word
    sc9, h9 = _g._scrub_text(capline)
    check("scrub_assignment_cap_never_leaks", gwpw not in sc9 and "cap" in sc9, sc9[-100:])
    # 19b. `run` with a secret in a CODE file: the payload is SCRUBBED and transmitted (the
    # fake CLEAR stands in for the reviewer), the run reports what it scrubbed.
    open(os.path.join(tmp, "k.py"), "w").write("aws = '%s'\npassword = '%s'\n" % (aws, gwpw))
    git(tmp, "add", "k.py")
    r = gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    check("run_scrubs_and_transmits",
          r.returncode == 0 and "scrubbed " in r.stdout and "VERDICT: CLEAR" in r.stdout
          and aws not in r.stdout and gwpw not in r.stdout, r.stdout[-220:])

    # 20. the 12-char mixed password (EV-023 shape) in an assignment line is WARNED about;
    # the commit is refused only for the ordinary reason (unreviewed code)
    git(tmp, "reset", "-q", "--hard")
    open(os.path.join(tmp, "cfg.py"), "w").write("password = '%s'\n" % gwpw)
    git(tmp, "add", "cfg.py")
    r = gate(tmp, "check")
    check("ev023_shape_warned", r.returncode == 1 and "WARNING" in r.stderr
          and "cfg.py:1 " in r.stderr and "carries secret" not in r.stderr
          and "unreviewed" in r.stderr, r.stderr[:200])

    # 21. placeholders / low-entropy flags are NOT false-positives
    git(tmp, "reset", "-q", "--hard")
    open(os.path.join(tmp, "ex.md"), "w").write(
        "API_KEY=your-key-here\nPASSWORD=changeme\ntoken_present = yes\nadmin_pw = admin\n")
    git(tmp, "add", "ex.md")
    r = gate(tmp, "check")
    check("placeholders_not_flagged", r.returncode == 0, r.stderr[:160])

    # 21b. COMPLEXITY FLOOR (EV-025, 2026-09-03): the generic two-class branch of
    # _looks_secret must carry a DIGIT class. Identifier-shaped values (env-var names,
    # slash paths, CamelCase, kebab words) are letters + punctuation with no digits -> NOT
    # secrets; machine-generated secrets (hex, base32, base62) virtually always carry digits
    # -> still caught. Values built at runtime so THIS file carries no trippable literal.
    git(tmp, "reset", "-q", "--hard")
    name1 = "GH_" + "COPILOT/CONTAINER_" + "TOKEN"            # 26 chars upper+punct: the EV-025 shape
    name2 = "my-" + "internal-secret-" + "passphrase-name"     # 34 chars lower+punct
    camel = "My" + "CompanyProduction" + "TokenValue"          # 29 chars upper+lower (quoted)
    open(os.path.join(tmp, "names.md"), "w").write(
        "Container token = %s for user\nsecret = %s\napi_key = \"%s\"\n" % (name1, name2, camel))
    git(tmp, "add", "names.md")
    r = gate(tmp, "check")
    check("identifier_shapes_not_flagged", r.returncode == 0, r.stderr[:200])
    # Digit-led hex is the control (caught before and after). LETTER-led unquoted hex was a
    # pre-existing fail-open found by this fixture: the no-self-trip "bare identifier"
    # exemption (^[A-Za-z_][\w.]*$) swallowed `secret = f00d...` whenever the first char
    # was a-f. A 20+ char pure-alphanumeric run WITH digits is hex/base36/base62, never a
    # sane identifier name, so it is shape-tested even when unquoted.
    h = hashlib.sha256(b"selftest-hex").hexdigest()
    hexsec = "7" + h[1:]                                             # 64 hex, digit-led, lower
    lowled = "f" + h[1:]                                             # 64 hex, letter-led, lower
    upled = ("E" + hashlib.sha1(b"selftest-b32").hexdigest().upper()[1:])[:32]  # 32, letter-led, upper
    for label, val in (("hex_secret_still_caught", hexsec),
                       ("letter_led_unquoted_hex_caught", lowled),
                       ("letter_led_unquoted_upper_hex_caught", upled)):
        git(tmp, "reset", "-q", "--hard")
        open(os.path.join(tmp, "hx.md"), "w").write("webhook_secret = %s\n" % val)
        git(tmp, "add", "hx.md")
        r = gate(tmp, "check")
        # (EV-046: detection is proven by the WARNING naming the line; nothing blocks)
        check(label, r.returncode == 0 and "WARNING" in r.stderr and "hx.md:1 " in r.stderr,
              r.stderr[:160])

    # 22. a secret hit no longer blocks, so it must NOT consume the owner's one-shot OVERRIDE
    # (the hatch is for clearance bypasses only)
    git(tmp, "reset", "-q", "--hard")
    open(os.path.join(tmp, "leak2.md"), "w").write("aws key %s\n" % aws)
    git(tmp, "add", "leak2.md")
    os.makedirs(os.path.join(tmp, ".adversary"), exist_ok=True)
    open(os.path.join(tmp, ".adversary", "OVERRIDE"), "w").write("selftest secret FP")
    r = gate(tmp, "check")
    ov_kept = os.path.exists(os.path.join(tmp, ".adversary", "OVERRIDE"))
    check("secret_warn_keeps_override",
          r.returncode == 0 and "OVERRIDDEN" not in r.stderr and "WARNING" in r.stderr and ov_kept,
          r.stderr[:160])
    if ov_kept:
        os.remove(os.path.join(tmp, ".adversary", "OVERRIDE"))

    # 23. NO-SELF-TRIP (brute force, per prove-guarantees-exhaustively): staging the gate's
    # OWN source + this selftest demands CLEARANCE but does NOT trip the secret scanner.
    git(tmp, "reset", "-q", "--hard")
    import shutil as _sh
    _sh.copy(GATE, os.path.join(tmp, "adversary_gate.py"))
    _sh.copy(os.path.abspath(__file__), os.path.join(tmp, "gate_selftest.py"))
    git(tmp, "add", "adversary_gate.py", "gate_selftest.py")
    r = gate(tmp, "check")
    # (asserts on the CURRENT warning wording - the old grep for "secret material" went
    # vacuous when the message was reworded, gate_20260907-164516)
    check("gate_source_no_self_trip",
          r.returncode == 1 and "secret-shaped" not in r.stderr and "WARNING" not in r.stderr
          and "unreviewed" in r.stderr, r.stderr[:200])

    # 24. TRANSMIT GUARD (finding 1): removing a secret-bearing code file must BLOCK `run`
    # - the deletion diff would ship the old secret as '-' lines. Seed it via override.
    git(tmp, "reset", "-q", "--hard")
    os.makedirs(hooks, exist_ok=True)
    open(os.path.join(hooks, "pre-commit"), "w", newline="\n").write(
        '#!/bin/sh\nexec "%s" "%s" check\n' % (PY.replace("\\", "/"), GATE.replace("\\", "/")))
    git(tmp, "config", "core.hooksPath", ".githooks")
    open(os.path.join(tmp, "sekret.py"), "w").write("password = '%s'\n" % gwpw)
    git(tmp, "add", "sekret.py")
    os.makedirs(os.path.join(tmp, ".adversary"), exist_ok=True)
    open(os.path.join(tmp, ".adversary", "OVERRIDE"), "w").write("seed a committed secret for removal test")
    git(tmp, "commit", "-m", "seed secret via override", expect_ok=False)
    git(tmp, "rm", "-q", "sekret.py")
    r = gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    # the deletion diff carries the old secret as a '-' line: it is SCRUBBED, then transmitted
    check("removed_secret_scrubbed_before_transmit",
          r.returncode == 0 and "scrubbed " in r.stdout and "VERDICT: CLEAR" in r.stdout
          and gwpw not in r.stdout, r.stdout[-200:])

    # 24b. ADDED-LINES ONLY (owner ruling 2026-09-03, EV-025): the floor scans the lines a
    # commit ADDS, not the full blob - a secret already in history is not re-flagged on every
    # later edit of that file (a one-line edit to a 4,800-line state file paid for every old
    # line), and a NEW secret line is reported at its NEW-file line number. Seed via override.
    git(tmp, "reset", "-q", "--hard")
    hist = hashlib.sha256(b"selftest-hist").hexdigest()
    open(os.path.join(tmp, "hist.md"), "w").write("# state\nsecret = %s\nmore\n" % hist)
    git(tmp, "add", "hist.md")
    open(os.path.join(tmp, ".adversary", "OVERRIDE"), "w").write("seed a committed secret for the added-lines test")
    git(tmp, "commit", "-m", "seed hist secret via override", expect_ok=False)
    open(os.path.join(tmp, "hist.md"), "a").write("a harmless later edit\n")
    git(tmp, "add", "hist.md")
    r = gate(tmp, "check")
    check("historical_secret_not_rescanned", r.returncode == 0, r.stderr[:200])
    new_secret = "b" + hashlib.sha256(b"selftest-hist-2").hexdigest()[1:]
    open(os.path.join(tmp, "hist.md"), "a").write("notes\nsecret = %s\n" % new_secret)
    git(tmp, "add", "hist.md")
    r = gate(tmp, "check")
    check("added_secret_warned_at_new_line_number",
          r.returncode == 0 and "hist.md:6 " in r.stderr and "hist.md:2 " not in r.stderr,
          r.stderr[:200])

    # 24c. A .gitattributes `-diff` (or `binary`) attribute collapses the file to 'Binary
    # files differ' - no hunks - so an added-lines floor without --text is BLIND, and
    # .gitattributes itself is ungated (gate finding on the added-lines change). --text
    # forces hunks; the floor AND the docscan feed must still see the secret.
    git(tmp, "reset", "-q", "--hard")
    open(os.path.join(tmp, ".gitattributes"), "w").write("*.md -diff\n")
    open(os.path.join(tmp, "n.md"), "w").write(
        "secret = %s\n" % ("c" + hashlib.sha256(b"selftest-attr").hexdigest()[1:]))
    git(tmp, "add", ".gitattributes", "n.md")
    r = gate(tmp, "check")
    check("attr_minus_diff_not_blind", r.returncode == 0 and "WARNING" in r.stderr
          and "n.md:1 " in r.stderr, r.stderr[:200])
    import importlib.util as _ilu
    _spec = _ilu.spec_from_file_location("ag_under_test", GATE)
    _ag = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_ag)
    _cwd = os.getcwd()
    os.chdir(tmp)
    try:
        _txt = _ag._staged_doc_added_text(["n.md"])
    finally:
        os.chdir(_cwd)
    check("doc_added_text_not_blind_to_minus_diff", "secret = " in _txt, repr(_txt[:80]))
    git(tmp, "reset", "-q", "--hard")            # also drops the staged-new .gitattributes + n.md

    # 24d. MID-MERGE the floor still sees added lines: `git diff --cached` is a plain
    # two-way index-vs-HEAD diff during a merge (the combined '@@@' format belongs to
    # worktree `git diff`), so a secret arriving via a cleanly-merged branch is caught at
    # its new-file line. Seed the branch commit via override.
    git(tmp, "checkout", "-q", "-b", "mbranch")
    open(os.path.join(tmp, "mrg.md"), "w").write(
        "# merged\nsecret = %s\n" % ("d" + hashlib.sha256(b"selftest-merge").hexdigest()[1:]))
    git(tmp, "add", "mrg.md")
    open(os.path.join(tmp, ".adversary", "OVERRIDE"), "w").write("seed a branch secret for the merge test")
    git(tmp, "commit", "-m", "branch secret via override", expect_ok=False)
    git(tmp, "checkout", "-q", "-")
    git(tmp, "merge", "--no-commit", "--no-ff", "mbranch", expect_ok=False)
    in_merge = os.path.exists(os.path.join(tmp, ".git", "MERGE_HEAD"))
    r = gate(tmp, "check")
    check("merge_state_added_lines_scanned", in_merge and r.returncode == 0
          and "mrg.md:2 " in r.stderr, "in_merge=%s %s" % (in_merge, r.stderr[:160]))
    git(tmp, "merge", "--abort", expect_ok=False)
    git(tmp, "reset", "-q", "--hard")

    # 25. ReDoS guard (finding 2): a >4096-char single line carrying a secret-word but no
    # '=' must not hang the hook (generic-assign skipped on long lines; literals linear).
    git(tmp, "reset", "-q", "--hard")
    open(os.path.join(tmp, "big.md"), "w").write("token" + ("a" * 200000) + "\n")
    git(tmp, "add", "big.md")
    r = gate(tmp, "check")
    check("long_line_no_hang", r.returncode == 0, r.stderr[:120])

    # 26. sshpass with a shell VARIABLE is safe usage, not a literal secret (finding 3)
    git(tmp, "reset", "-q", "--hard")
    open(os.path.join(tmp, "deploy_notes.md"), "w").write('run: sshpass -p "$PW" ssh user@host\n')
    git(tmp, "add", "deploy_notes.md")
    r = gate(tmp, "check")
    check("sshpass_variable_not_flagged", r.returncode == 0, r.stderr[:150])

    # 27. (EV-046) a docs-only secret never blocks, so no docs-only override record can exist:
    # an armed OVERRIDE survives a docs secret commit untouched and no override_used.json appears
    git(tmp, "reset", "-q", "--hard")
    open(os.path.join(tmp, "leak3.md"), "w").write("aws %s\n" % aws)
    git(tmp, "add", "leak3.md")
    open(os.path.join(tmp, ".adversary", "OVERRIDE"), "w").write("docs override reason X")
    ovu = os.path.join(tmp, ".adversary", "override_used.json")
    if os.path.exists(ovu):          # a stale record from the row-24 override-seeded commits
        os.remove(ovu)
    r = gate(tmp, "check")
    check("docs_secret_no_override_record",
          r.returncode == 0 and not os.path.exists(ovu)
          and os.path.exists(os.path.join(tmp, ".adversary", "OVERRIDE")), r.stderr[:150])
    try:
        os.remove(os.path.join(tmp, ".adversary", "OVERRIDE"))
    except OSError:
        pass

    # 28. a genuine BINARY file (real NUL bytes) is skipped, not scanned/false-flagged -
    # proves the binary guard tests actual NUL bytes now, not the literal text "\\x00".
    git(tmp, "reset", "-q", "--hard")
    with open(os.path.join(tmp, "blob.bin"), "wb") as fb:
        fb.write(b"\x00\x01AKIA" + b"A" * 16 + b"\x00 binary garbage")
    git(tmp, "add", "blob.bin")
    r = gate(tmp, "check")
    check("binary_file_skipped", r.returncode == 0, r.stderr[:120])

    # 29. DOCS SEMANTIC SCAN (docs half of the domain division): a docs commit the LOCAL
    # model flags is REFUSED. The wifi-password prose has no assignment syntax, so the
    # pattern floor misses it - only docscan catches it. Uses the FAKE stub (no real model).
    git(tmp, "reset", "-q", "--hard")
    open(os.path.join(tmp, "guide.md"), "w").write(
        "# guide\nthe wifi password is sunshine-dragon-42 for the shop\n")
    git(tmp, "add", "guide.md")
    r = gate(tmp, "check", env_extra={"DOCSCAN_FAKE": "BLOCK"})
    # EV-046: the docs model's block WARNS at commit time; the push guard re-runs it (row P3)
    check("docs_semantic_warns", r.returncode == 0 and "docs reviewer" in r.stderr
          and "NOT blocked" in r.stderr and "push guard" in r.stderr, r.stderr[:200])

    # 30. a clean docs commit passes (stub CLEAR)
    r = gate(tmp, "check", env_extra={"DOCSCAN_FAKE": "CLEAR"})
    check("docs_semantic_clear", r.returncode == 0, r.stderr[:160])

    # 31. a docscan block must NOT consume an armed OVERRIDE either (it no longer blocks)
    os.makedirs(os.path.join(tmp, ".adversary"), exist_ok=True)
    open(os.path.join(tmp, ".adversary", "OVERRIDE"), "w").write("selftest docs FP")
    r = gate(tmp, "check", env_extra={"DOCSCAN_FAKE": "BLOCK"})
    check("docs_warn_keeps_override", r.returncode == 0 and "OVERRIDDEN" not in r.stderr
          and os.path.exists(os.path.join(tmp, ".adversary", "OVERRIDE")), r.stderr[:160])
    try:
        os.remove(os.path.join(tmp, ".adversary", "OVERRIDE"))
    except OSError:
        pass

    # 32. graceful-degrade: no local model -> docs pass with a LOUD "SKIPPED" warning, not a
    # block, not fail-closed. Force unavailable by pointing the model at a missing path and
    # disabling the stub (empty DOCSCAN_FAKE).
    git(tmp, "reset", "-q", "--hard")
    open(os.path.join(tmp, "d2.md"), "w").write("# notes\njust prose, nothing secret here\n")
    git(tmp, "add", "d2.md")
    r = gate(tmp, "check", env_extra={"DOCSCAN_FAKE": "",
                                      "NEXUSMILL_DOCSCAN_MODEL": os.path.join(tmp, "nope.gguf")})
    check("docs_degrade_when_no_model",
          r.returncode == 0 and "SEMANTIC review SKIPPED" in r.stderr, r.stderr[:160])

    # 33. a CLEAN docs commit must NOT consume an armed OVERRIDE (finding-1 regression guard:
    # the override is one-shot for a REAL bypass, not eaten by a routine README commit).
    git(tmp, "reset", "-q", "--hard")
    open(os.path.join(tmp, "clean.md"), "w").write("# clean\njust ordinary prose, no secrets\n")
    git(tmp, "add", "clean.md")
    os.makedirs(os.path.join(tmp, ".adversary"), exist_ok=True)
    open(os.path.join(tmp, ".adversary", "OVERRIDE"), "w").write("must survive a clean commit")
    r = gate(tmp, "check", env_extra={"DOCSCAN_FAKE": "CLEAR"})
    ov_present = os.path.exists(os.path.join(tmp, ".adversary", "OVERRIDE"))
    check("clean_docs_keeps_override", r.returncode == 0 and ov_present,
          "rc=%d ov_present=%s stderr=%s" % (r.returncode, ov_present, r.stderr[:100]))
    try:
        os.remove(os.path.join(tmp, ".adversary", "OVERRIDE"))
    except OSError:
        pass

    # 34. FINDING (cwd fail-open): a manual `check` from a SUBDIRECTORY must still SEE the
    # staged docs (:(top,literal) anchors to root). Force no-model so the signal is the loud
    # degrade WARNING - the old cwd-relative :(literal) returned "" -> scan clear -> SILENT
    # pass (the fail-open). We assert the warning appears (proves the doc text was found).
    git(tmp, "reset", "-q", "--hard")
    sub = os.path.join(tmp, "sub"); os.makedirs(sub, exist_ok=True)
    open(os.path.join(tmp, "d3.md"), "w").write("# x\nsome ordinary prose content here\n")
    git(tmp, "add", "d3.md")
    env = dict(os.environ)
    env["ADVERSARY_SELFTEST"] = "1"; env["DOCSCAN_FAKE"] = ""
    env["NEXUSMILL_DOCSCAN_MODEL"] = os.path.join(tmp, "no_such_model.gguf")
    r = subprocess.run([PY, GATE, "check"], capture_output=True, text=True,
                       encoding="utf-8", errors="replace", cwd=sub, env=env)
    check("subdir_docs_not_failopen",
          r.returncode == 0 and "SEMANTIC review SKIPPED" in r.stderr,
          "rc=%d %s" % (r.returncode, r.stderr[:150]))

    # 35-38. REMOVED SYMBOL WITH LIVE CALLERS (2026-09-09; the hole Tools 8245433 opened on
    # 2026-09-07): a commit that removed adversary_gate._scan_text_secrets CLEARed while
    # reviewed_write.py still called it - the reviewer only ever sees the staged files, so no
    # prompt can catch an unstaged caller. The gate itself must refuse, deterministically and
    # before any model call: a module-level def/class present in the HEAD blob and absent from
    # the index blob, referenced by a tracked .py outside the staged set.
    git(tmp, "reset", "-q", "--hard")
    open(os.path.join(tmp, "lib.py"), "w").write("def keep():\n    return 1\n\n\ndef gone():\n    return 2\n")
    open(os.path.join(tmp, "caller.py"), "w").write("import lib\n\n\ndef use():\n    return lib.gone() + lib.keep()\n")
    open(os.path.join(tmp, "commenter.py"), "w").write("import lib\n# gone is only mentioned in this comment\n"
                                                        "\"\"\"and gone in a docstring\"\"\"\n\n\ndef other():\n    return lib.keep()\n")
    git(tmp, "add", "lib.py", "caller.py", "commenter.py")
    r = gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    git(tmp, "commit", "-q", "-m", "lib + callers")
    # 35. remove `gone` with caller.py NOT staged -> refused before the reviewer is consulted
    open(os.path.join(tmp, "lib.py"), "w").write("def keep():\n    return 1\n")
    git(tmp, "add", "lib.py")
    r = gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    check("removed_symbol_live_caller_refused",
          r.returncode == 1 and "REFUSED" in r.stdout and "caller.py" in r.stdout and "gone" in r.stdout
          and "VERDICT" not in r.stdout, "rc=%d %s" % (r.returncode, (r.stdout + r.stderr)[-300:]))
    r = gate(tmp, "check")
    check("removed_symbol_no_clearance_written", r.returncode == 1, r.stderr[:120])
    # 36. the caller is staged WITH the reference removed -> the review proceeds
    open(os.path.join(tmp, "caller.py"), "w").write("import lib\n\n\ndef use():\n    return lib.keep()\n")
    git(tmp, "add", "lib.py", "caller.py")
    r = gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    check("removed_symbol_caller_staged_proceeds", r.returncode == 0 and "CLEAR" in r.stdout,
          "rc=%d %s" % (r.returncode, (r.stdout + r.stderr)[-300:]))
    git(tmp, "commit", "-q", "-m", "gone removed with its caller")
    # 37. a name that survives only in a comment / docstring is not a caller
    open(os.path.join(tmp, "lib.py"), "w").write("def keep():\n    return 1\n\n\ndef gone():\n    return 3\n")
    git(tmp, "add", "lib.py")
    r = gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    git(tmp, "commit", "-q", "-m", "gone back, only a comment mentions it")
    open(os.path.join(tmp, "lib.py"), "w").write("def keep():\n    return 1\n")
    git(tmp, "add", "lib.py")
    r = gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    check("removed_symbol_comment_mention_not_a_caller", r.returncode == 0 and "CLEAR" in r.stdout,
          "rc=%d %s" % (r.returncode, (r.stdout + r.stderr)[-300:]))
    git(tmp, "commit", "-q", "-m", "gone removed, commenter untouched")
    # 38. a RENAME compares against the OLD path's HEAD blob: lib.py -> lib2.py dropping `keep`
    #     (the filler keeps git's similarity above the rename threshold) while caller.py still
    #     calls lib.keep() -> refused
    filler = "\n\ndef filler():\n" + "".join("    x%d = %d\n" % (k, k) for k in range(40)) + "    return x0\n"
    open(os.path.join(tmp, "lib.py"), "w").write("def keep():\n    return 1\n" + filler)
    git(tmp, "add", "lib.py")
    r = gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    git(tmp, "commit", "-q", "-m", "lib with filler")
    git(tmp, "mv", "lib.py", "lib2.py")
    open(os.path.join(tmp, "lib2.py"), "w").write(filler.lstrip("\n"))
    git(tmp, "add", "lib2.py")
    st = git(tmp, "diff", "--cached", "--name-status", "-M").stdout
    check("rename_fixture_is_a_rename", st.startswith("R"), st[:80])
    r = gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    check("removed_symbol_rename_uses_old_blob",
          r.returncode == 1 and "REFUSED" in r.stdout and "keep" in r.stdout and "caller.py" in r.stdout,
          "rc=%d %s" % (r.returncode, (r.stdout + r.stderr)[-300:]))
    git(tmp, "reset", "-q", "--hard")
    # 39. a DELETED module removes every symbol it defined: `git rm lib.py` with caller.py live -> refused
    git(tmp, "rm", "-q", "lib.py")
    r = gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    check("removed_symbol_deleted_module_refused",
          r.returncode == 1 and "REFUSED" in r.stdout and "keep" in r.stdout and "caller.py" in r.stdout,
          "rc=%d %s" % (r.returncode, (r.stdout + r.stderr)[-300:]))
    git(tmp, "reset", "-q", "--hard")
    # 40. a run from a SUBDIRECTORY still sees a caller elsewhere (gate catch gate_20260909-140534:
    #     a cwd-scoped `ls-files` listed nothing outside the cwd -> [] -> CLEAR -> fail-open)
    open(os.path.join(tmp, "lib.py"), "w").write(filler.lstrip("\n"))        # `keep` dropped
    git(tmp, "add", "lib.py")
    sub40 = os.path.join(tmp, "sub"); os.makedirs(sub40, exist_ok=True)
    env40 = dict(os.environ); env40["ADVERSARY_SELFTEST"] = "1"; env40["ADVERSARY_FAKE"] = "CLEAR"
    r = subprocess.run([PY, GATE, "run"], capture_output=True, text=True, encoding="utf-8",
                       errors="replace", cwd=sub40, env=env40)
    check("removed_symbol_subdir_run_still_refused",
          r.returncode == 1 and "REFUSED" in r.stdout and "caller.py" in r.stdout,
          "rc=%d %s" % (r.returncode, (r.stdout + r.stderr)[-300:]))
    git(tmp, "reset", "-q", "--hard")
    # 41. a re-export binding is a caller: `from lib import keep` in an unstaged module -> refused
    open(os.path.join(tmp, "reexport.py"), "w").write("from lib import keep\n")
    git(tmp, "add", "reexport.py")
    r = gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    git(tmp, "commit", "-q", "-m", "re-export")
    open(os.path.join(tmp, "caller.py"), "w").write("import lib\n\n\ndef use():\n    return lib.filler()\n")
    open(os.path.join(tmp, "lib.py"), "w").write(filler.lstrip("\n"))
    git(tmp, "add", "lib.py", "caller.py")                                    # caller fixed, re-export not
    r = gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    check("removed_symbol_reexport_is_a_caller",
          r.returncode == 1 and "REFUSED" in r.stdout and "reexport.py" in r.stdout,
          "rc=%d %s" % (r.returncode, (r.stdout + r.stderr)[-300:]))
    git(tmp, "reset", "-q", "--hard")

    # 42. doctrine the reviewer must not re-litigate (2026-09-10): a colibri manifest row keyed by
    #     an ABSOLUTE path with rel/modes is the canonical shape (store.py writes it) - three
    #     archive-mirror commits drew LOW findings on it in one day; the prompt names the canon
    #     and the real defects (second entry, `files` wrapper, relative wrapperless rows)
    import importlib.util
    spec = importlib.util.spec_from_file_location("ag_under_test", GATE)
    ag = importlib.util.module_from_spec(spec); spec.loader.exec_module(ag)
    p = ag.PROMPT
    check("prompt_carries_colibri_manifest_doctrine",
          "_manifest.json" in p and "ABSOLUTE" in p and "not findings" in p
          and "second entry" in p and "files" in p and "wrapperless" in p,
          p[-400:])

    bad = {k: v for k, v in results.items() if not v[0]}
    print("\n%d/%d PASS" % (len(results) - len(bad), len(results)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
