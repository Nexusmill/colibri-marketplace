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
    env = dict(os.environ)
    env["ADVERSARY_SELFTEST"] = "1"
    env.update(env_extra or {})
    return subprocess.run([PY, GATE] + list(args), capture_output=True, text=True,
                          encoding="utf-8", errors="replace", cwd=repo, env=env)


def main():
    tmp = tempfile.mkdtemp(prefix="advgate_")
    os.environ["ADVERSARY_SELFTEST"] = "1"          # inherited by git-spawned hooks too
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
    rc = git(tmp, "commit", "-m", "post-baseline cleared", expect_ok=False)
    # assert the CLEARED commit actually landed: without this a regression that refuses it
    # leaves HEAD unchanged, the push is "up-to-date" (rc 0), and the check below false-passes.
    check("post_baseline_commit_ok", rc.returncode == 0, (rc.stderr + rc.stdout)[:150])
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
    r = gate(tmp, "check")
    check("secret_in_docs_refused", r.returncode == 1 and "secret material" in r.stderr,
          r.stderr[:160])
    r = gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    check("run_blocks_secret_no_model",
          r.returncode == 1 and "NOT sent" in r.stdout
          and "VERDICT: CLEAR" not in r.stdout, r.stdout[-180:])

    # 20. the 12-char mixed password (EV-023 shape) is caught in an assignment line
    git(tmp, "reset", "-q", "--hard")
    open(os.path.join(tmp, "cfg.py"), "w").write("password = '%s'\n" % gwpw)
    git(tmp, "add", "cfg.py")
    r = gate(tmp, "check")
    check("ev023_shape_caught", r.returncode == 1 and "secret material" in r.stderr,
          r.stderr[:160])

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
        check(label, r.returncode == 1 and "secret material" in r.stderr, r.stderr[:160])

    # 22. OVERRIDE escapes a secret hit (owner false-positive path), one-shot
    git(tmp, "reset", "-q", "--hard")
    open(os.path.join(tmp, "leak2.md"), "w").write("aws key %s\n" % aws)
    git(tmp, "add", "leak2.md")
    os.makedirs(os.path.join(tmp, ".adversary"), exist_ok=True)
    open(os.path.join(tmp, ".adversary", "OVERRIDE"), "w").write("selftest secret FP")
    r = gate(tmp, "check")
    ov_gone = not os.path.exists(os.path.join(tmp, ".adversary", "OVERRIDE"))
    check("secret_override_oneshot",
          r.returncode == 0 and "OVERRIDDEN" in r.stderr and ov_gone, r.stderr[:160])

    # 23. NO-SELF-TRIP (brute force, per prove-guarantees-exhaustively): staging the gate's
    # OWN source + this selftest demands CLEARANCE but does NOT trip the secret scanner.
    git(tmp, "reset", "-q", "--hard")
    import shutil as _sh
    _sh.copy(GATE, os.path.join(tmp, "adversary_gate.py"))
    _sh.copy(os.path.abspath(__file__), os.path.join(tmp, "gate_selftest.py"))
    git(tmp, "add", "adversary_gate.py", "gate_selftest.py")
    r = gate(tmp, "check")
    check("gate_source_no_self_trip",
          r.returncode == 1 and "secret material" not in r.stderr and "unreviewed" in r.stderr,
          r.stderr[:200])

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
    check("removed_secret_not_transmitted",
          r.returncode == 1 and "NOT sent" in r.stdout and "VERDICT: CLEAR" not in r.stdout,
          r.stdout[-200:])

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
    check("added_secret_caught_at_new_line_number",
          r.returncode == 1 and "hist.md:6 " in r.stderr and "hist.md:2 " not in r.stderr,
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
    check("attr_minus_diff_not_blind", r.returncode == 1 and "secret material" in r.stderr
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
    check("merge_state_added_lines_scanned", in_merge and r.returncode == 1
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

    # 27. docs-only secret OVERRIDE leaves a DURABLE, docs_only-marked record (finding 5)
    git(tmp, "reset", "-q", "--hard")
    open(os.path.join(tmp, "leak3.md"), "w").write("aws %s\n" % aws)
    git(tmp, "add", "leak3.md")
    open(os.path.join(tmp, ".adversary", "OVERRIDE"), "w").write("docs override reason X")
    r = gate(tmp, "check")
    ovu = os.path.join(tmp, ".adversary", "override_used.json")
    rec = json.loads(open(ovu, encoding="utf-8").read()) if os.path.exists(ovu) else {}
    check("docs_override_durable_record",
          r.returncode == 0 and rec.get("docs_only") is True
          and "docs override reason X" in rec.get("reason", ""), str(rec)[:150])

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
    check("docs_semantic_block", r.returncode == 1 and "local docs reviewer" in r.stderr,
          r.stderr[:160])

    # 30. a clean docs commit passes (stub CLEAR)
    r = gate(tmp, "check", env_extra={"DOCSCAN_FAKE": "CLEAR"})
    check("docs_semantic_clear", r.returncode == 0, r.stderr[:160])

    # 31. a docscan BLOCK is escapable by the owner one-shot OVERRIDE, like other blocks
    os.makedirs(os.path.join(tmp, ".adversary"), exist_ok=True)
    open(os.path.join(tmp, ".adversary", "OVERRIDE"), "w").write("selftest docs FP")
    r = gate(tmp, "check", env_extra={"DOCSCAN_FAKE": "BLOCK"})
    check("docs_block_overridable", r.returncode == 0 and "OVERRIDDEN" in r.stderr, r.stderr[:160])

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

    bad = {k: v for k, v in results.items() if not v[0]}
    print("\n%d/%d PASS" % (len(results) - len(bad), len(results)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
