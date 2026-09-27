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

    # Snapshot must defer blob reads until the bounded payload composer consumes them.
    import ast as _ast_lazy
    _tree_lazy = _ast_lazy.parse(open(GATE, encoding="utf-8").read())
    _fn_lazy = next(n for n in _tree_lazy.body if isinstance(n, _ast_lazy.FunctionDef)
                    and n.name == "_cmd_run_snapshot")
    _reads_lazy = []
    class _StopLazy(Exception):
        pass
    def _read_lazy(args, binary=False):
        _reads_lazy.append(args[-1])
        return b"x"
    def _compose_lazy(diff, blobs, context):
        if _reads_lazy:
            raise AssertionError("all staged blobs were loaded before composing")
        if list(blobs) != [("a.py", b"x"), ("b.py", b"x")]:
            raise AssertionError("staged blob contents or order changed")
        raise _StopLazy()
    _ns_lazy = dict(_g.__dict__)
    _ns_lazy.update(_repo_root=lambda: ".", _scan_staged_secrets=lambda: [],
                    _staged_code_files=lambda: ["a.py", "b.py"], _staged_removals=lambda: [],
                    _removed_symbol_callers=lambda: [], _diff_paths=lambda *a: "",
                    _blob_is_binary=lambda *a: False,
                    _run_git=_read_lazy, _compose_review_payload=_compose_lazy)
    exec(compile(_ast_lazy.Module(body=[_fn_lazy], type_ignores=[]), GATE, "exec"), _ns_lazy)
    try:
        _ns_lazy["_cmd_run_snapshot"]("unused", "")
        _ok_lazy, _why_lazy = False, "composer never invoked"
    except _StopLazy:
        _ok_lazy, _why_lazy = True, ""
    except AssertionError as _exc_lazy:
        _ok_lazy, _why_lazy = False, str(_exc_lazy)
    check("snapshot_defers_staged_blob_reads", _ok_lazy, _why_lazy)

    # A failed evidence write must not enter an unlocked artifact/clearance path.
    import contextlib as _ctx_evidence
    import io as _io_evidence
    def _unavailable_evidence(*args, **kwargs):
        raise RuntimeError("review-round lock busy")
    def _forbidden_evidence(*args, **kwargs):
        raise AssertionError("unlocked fallback touched review evidence")
    _ns_evidence = dict(_ns_lazy)
    _ns_evidence.update(_compose_review_payload=lambda *a: "payload",
                        _scrub_text=lambda p: (p, []),
                        _route_chain=lambda m, p, c: (m, "default"),
                        _call_model_ex=lambda *a: ("VERDICT: CLEAR", {}, "fixture", "fixture"),
                        _staged_sha=lambda p: "fixture-sha",
                        _write_review_round=_unavailable_evidence,
                        _adv_dir=_forbidden_evidence, _save_clear=_forbidden_evidence)
    exec(compile(_ast_lazy.Module(body=[_fn_lazy], type_ignores=[]), GATE, "exec"), _ns_evidence)
    try:
        with _ctx_evidence.redirect_stdout(_io_evidence.StringIO()):
            _rc_evidence = _ns_evidence["_cmd_run_snapshot"]("fixture", "")
        _ok_evidence, _why_evidence = _rc_evidence == 1, str(_rc_evidence)
    except AssertionError as _exc_evidence:
        _ok_evidence, _why_evidence = False, str(_exc_evidence)
    check("snapshot_evidence_failure_refuses_clearance", _ok_evidence, _why_evidence)

    # Even oversized files marked -diff must expose source hunks to the reviewer.
    import unittest.mock as _mock_diff
    import contextlib as _ctx_diff
    import io as _io_diff
    with tempfile.TemporaryDirectory(prefix="adv-text-diff-") as _td:
        git(_td, "init", "-q")
        with open(os.path.join(_td, ".gitattributes"), "w", encoding="utf-8") as _fh:
            _fh.write("*.py -diff\n")
        with open(os.path.join(_td, "large.py"), "w", encoding="utf-8") as _fh:
            _fh.write('VALUE = "' + "a" * 260_000 + '"\n# BINARY_DIFF_MARKER\n')
        git(_td, "add", ".gitattributes", "large.py")
        _payloads_diff = []
        def _review_diff(model, payload):
            _payloads_diff.append(payload)
            return "VERDICT: BLOCK", {}, "fixture", "fixture"
        _cwd_diff = os.getcwd()
        try:
            os.chdir(_td)
            with _mock_diff.patch.object(_g, "_call_model_ex", side_effect=_review_diff):
                with _ctx_diff.redirect_stdout(_io_diff.StringIO()):
                    _rc_diff = _g.cmd_run("fixture", "")
        finally:
            os.chdir(_cwd_diff)
        check("oversized_binary_attribute_still_reviews_text",
              _rc_diff == 1 and len(_payloads_diff) == 1
              and "BINARY_DIFF_MARKER" in _payloads_diff[0],
              "oversized source was hidden from the review payload")

        with open(os.path.join(_td, "large.py"), "wb") as _fh:
            _fh.write(b"\0" + b"a" * 260_000)
        git(_td, "add", "large.py")
        _payloads_diff.clear()
        try:
            os.chdir(_td)
            with _mock_diff.patch.object(_g, "_call_model_ex", side_effect=_review_diff):
                with _ctx_diff.redirect_stdout(_io_diff.StringIO()):
                    _rc_diff = _g.cmd_run("fixture", "")
        finally:
            os.chdir(_cwd_diff)
        check("binary_code_refused_before_review",
              _rc_diff == 1 and not _payloads_diff,
              "opaque binary code reached the external reviewer")

        # Binary content on the removed side must also never reach the reviewer.
        git(_td, "config", "core.hooksPath", os.path.join(_td, "unused-fixture-hooks"))
        git(_td, "config", "user.name", "test")
        git(_td, "config", "user.email", "test@example.invalid")
        git(_td, "commit", "-qm", "binary fixture base")
        with open(os.path.join(_td, "large.py"), "w", encoding="utf-8") as _fh:
            _fh.write("VALUE = 1\n")
        git(_td, "add", "large.py")
        _payloads_diff.clear()
        try:
            os.chdir(_td)
            with _mock_diff.patch.object(_g, "_call_model_ex", side_effect=_review_diff):
                with _ctx_diff.redirect_stdout(_io_diff.StringIO()):
                    _rc_diff = _g.cmd_run("fixture", "")
        finally:
            os.chdir(_cwd_diff)
        check("binary_base_refused_before_review",
              _rc_diff == 1 and not _payloads_diff,
              "removed binary content reached the external reviewer")

    # Corrupt append-only evidence must survive every read-modify-write path.
    for _which in ("adjudication", "stamp", "round"):
        with tempfile.TemporaryDirectory(prefix="adv-corrupt-") as _coroot:
            _coadv = _g._adv_dir(_coroot)
            _copath = os.path.join(_coadv, "adjudications.json") if _which == "adjudication" else os.path.join(_coadv, "reviews", "staged_shas.json")
            with open(_copath, "wb") as _cofh:
                _cofh.write(b"{broken evidence")
            _coraised = False
            try:
                if _which == "adjudication":
                    _g._append_adjudication(_coroot, {"commit": "fixture"})
                elif _which == "stamp":
                    _g._stamp_review_meta(_coroot, "gate_fixture.md", {"a.py": "sha"}, False)
                else:
                    _g._write_review_round(_coroot, "20260927-120000",
                                           "VERDICT: BLOCK", {"a.py": "sha"}, False)
            except RuntimeError:
                _coraised = True
            with open(_copath, "rb") as _cofh:
                _copreserved = _cofh.read() == b"{broken evidence"
            check("corrupt_evidence_preserved_" + _which, _coraised and _copreserved,
                  "corrupt input must not be reset or overwritten")

    # Age alone cannot prove a lock owner is dead (including POSIX unlink semantics).
    with tempfile.TemporaryDirectory(prefix="adv-aged-lock-") as _lkroot:
        _lkpath = os.path.join(_lkroot, "fixture.lock")
        with open(_lkpath, "w", encoding="ascii") as _lkfh:
            _lkfh.write(str(os.getpid()))
        os.utime(_lkpath, (0, 0))
        _lkfd = _g._adv_lock(_lkroot, "fixture", deadline_s=0.01)
        check("aged_lock_not_stolen", _lkfd is None and os.path.exists(_lkpath))
        if _lkfd is not None:
            _g._adv_unlock(_lkroot, "fixture", _lkfd)
        elif os.path.exists(_lkpath):
            os.remove(_lkpath)
        _lkfd = _g._adv_lock(_lkroot, "fixture", deadline_s=0.01)
        check("lock_available_after_cleanup", _lkfd is not None)
        if _lkfd is not None:
            _g._adv_unlock(_lkroot, "fixture", _lkfd)

    # Cache-efficiency tranche R1 (owner order 2026-09-23): the review payload is
    # STABLE-FIRST/DIFF-LAST so consecutive rounds of one landing share the
    # unchanged staged files as a provider-cacheable prefix (OpenRouter prompt
    # caching is strict-prefix; the measured hit ratio under diff-first was ~3%
    # across 237 reviews, with the only real hits on identical retries).
    try:
        _pl = _g._compose_review_payload(
            "DIFFBODY", [("src/a.py", b"AAA BODY"), ("src/b.py", b"BBB BODY")], "NOTES")
        _ok_pl = (_pl.index("FULL STAGED FILE src/a.py") < _pl.index("FULL STAGED FILE src/b.py")
                  < _pl.index("STAGED DIFF") < _pl.index("REBUTTAL")
                  and "DIFFBODY" in _pl.split("STAGED DIFF")[1])
    except Exception as _e:                                   # noqa: BLE001 - a missing
        _ok_pl, _pl = False, repr(_e)                         # helper is a FAIL, not a crash
    check("review_payload_stable_first_diff_last", _ok_pl, str(_pl)[:200])

    # size caps keep their legacy semantics: an oversized blob is omitted by
    # note, in-budget files still ride in full, the diff always lands, and an
    # empty context emits no rebuttal section
    try:
        _big = b"X" * (_g.MAX_FILE_BYTES + 1)
        _pl2 = _g._compose_review_payload("D2", [("huge.py", _big), ("ok.py", b"fine")], "")
        _ok2 = ("OMITTED FOR SIZE" in _pl2 and "XXXX" not in _pl2
                and "FULL STAGED FILE ok.py" in _pl2 and "D2" in _pl2
                and "REBUTTAL" not in _pl2)
    except Exception as _e:                                   # noqa: BLE001
        _ok2, _pl2 = False, repr(_e)
    check("review_payload_omission_and_nocontext", _ok2, str(_pl2)[:200])
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

    # 0c. the serving PROVIDER is recorded (owner order 2026-09-16): OpenRouter spreads glm-5.3-flash over twelve
    # providers; the fleet battery proved they behave differently (some ignore a reasoning budget), and the gate's
    # own empty-content fallbacks to grok have never been traceable to a provider. The completion parser returns it,
    # the review header carries it, and a response without one records None rather than crashing.
    try:
        _ok = (_g._parse_completion({"choices": [{"message": {"content": "VERDICT: CLEAR"}}],
                                     "usage": {"total_tokens": 7}, "provider": "BaseTen"})
               == ("VERDICT: CLEAR", {"total_tokens": 7}, "BaseTen"))
        _ok = _ok and _g._parse_completion({"choices": [{"message": {"content": "x"}}]}) == ("x", {}, None)
        try:
            _g._parse_completion({"error": {"message": "boom"}})
            _ok = False
        except SystemExit:
            pass
    except Exception as _e:  # noqa: BLE001 - a missing helper is a FAIL, not a crashed selftest
        _ok, _e_detail = False, repr(_e)
    else:
        _e_detail = ""
    check("completion_parser_returns_provider", _ok, _e_detail)
    # Owner 2026-09-26: new primary/secondary; retain measured fallback pins.
    try:
        _chain = [m.strip() for m in _g.DEFAULT_CHAIN.split(",")]
        _ok3 = (_chain == ["openai/gpt-6-luna-pro",
                           "qwen/qwen3.8-flash",
                           "deepseek/deepseek-v4-pro-0813@deepinfra/fp8+wafer+ionstream",
                           "z-ai/glm-5.3-flash@parasail/fp8+coreweave/nvfp4+modal/fp8",
                           "deepseek/deepseek-v4-flash@open-inference/fp8+deepinfra/fp8"]
                and "grok" not in _g.DEFAULT_CHAIN
                and _g._split_entry(_chain[0]) == (
                    "openai/gpt-6-luna-pro",
                    [])
                and _g._split_entry("z-ai/glm-5.3-flashx@z-ai/fp8") == (
                    "z-ai/glm-5.3-flashx", ["z-ai/fp8"]))
    except Exception as _e:  # noqa: BLE001 - a missing constant/helper is a FAIL, not a crashed selftest
        _ok3, _e3 = False, repr(_e)
    else:
        _e3 = ""
    check("default_chain_grok_retired_fleet_ladder_pinned", _ok3, _e3)
    try:
        _g._split_entry("z-ai/glm-5.3-flash@")   # empty pin list must fail CLOSED
        _ok3b = False
    except SystemExit:
        _ok3b = True
    except Exception:
        _ok3b = False
    else:
        _ok3b = False
    check("split_entry_empty_pin_fails_closed", _ok3b)
    try:
        _hdr = _g._review_header("z-ai/glm-5.3-flash", {"total_tokens": 7}, "BaseTen", 0, ["a.py"])
        _ok2 = (_hdr.startswith("model: z-ai/glm-5.3-flash | provider: BaseTen | usage: {'total_tokens': 7} | scrubbed: 0"
                                " | files: ['a.py']") and _hdr.endswith("\n\n"))
        _ok2 = _ok2 and "| provider: None |" in _g._review_header("m", {}, None, 0, [])
    except Exception as _e:  # noqa: BLE001
        _ok2, _e_detail = False, repr(_e)
    else:
        _e_detail = ""
    check("review_header_names_the_provider", _ok2, _e_detail)

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
    gate(tmp, "run")                     # a denial first: the override must adjudicate it
    open(os.path.join(tmp, ".adversary", "OVERRIDE"), "w").write("owner emergency")
    r = git(tmp, "commit", "-m", "override commit", expect_ok=False)
    check("override_commit_ok", r.returncode == 0, (r.stderr + r.stdout)[:150])
    r = gate(tmp, "record")
    note = git(tmp, "notes", "--ref", "refs/notes/adversary", "show", "HEAD", expect_ok=False)
    data = json.loads(note.stdout) if note.returncode == 0 else {}
    check("override_note", r.returncode == 0 and data.get("type") == "OVERRIDE"
          and "owner emergency" in data.get("reason", ""), (r.stderr or note.stderr)[:150])
    # 12b. the override's denial cycle RECORDS (gate round 2, 2026-09-21): the episode
    # lands in adjudications.json with the `overridden` outcome - end-to-end through
    # the real cmd_record branch, not a direct _adjudicate_cycle call.
    adjp = os.path.join(tmp, ".adversary", "adjudications.json")
    ov_head = git(tmp, "rev-parse", "HEAD").stdout.strip()
    try:
        eps_ov = json.loads(open(adjp, encoding="utf-8").read())["episodes"]
    except (OSError, ValueError, KeyError):
        eps_ov = []
    ep_ov = next((e for e in eps_ov if e.get("commit") == ov_head), None)
    check("override_adjudication_records_end_to_end",
          ep_ov is not None and ep_ov["type"] == "OVERRIDE"
          and set(ep_ov["outcome_counts"]) == {"overridden"},
          "ep=%s" % (ep_ov or {}).get("outcome_counts"))
    # 12c. the cycle floor falls back to the PARENT COMMIT's time when the parent
    # carries no notary note (a bypassed commit - exactly row 11's shape): the
    # stale-denial bound must never silently vanish (gate round 4, 2026-09-21).
    cwd0 = os.getcwd()
    os.chdir(tmp)                # gate functions resolve the repo from the cwd
    try:
        floor = _g._cycle_floor(ov_head, "refs/notes/adversary")
    finally:
        os.chdir(cwd0)
    pc = git(tmp, "log", "-1", "--date=iso-local", "--format=%cd",
             ov_head + "~1").stdout.strip()
    want = pc[:10].replace("-", "") + "-" + pc[11:19].replace(":", "")
    check("adjudication_cycle_floor_falls_back_to_parent_commit_time",
          floor == want, "floor=%r want=%r" % (floor, want))
    # 12d. the floor PREFERS the parent note's clearing-round timestamps over its
    # top-level record time (round 5 F1): no child denial can predate the parent's
    # clear, and second granularity compares with >= downstream.
    open(os.path.join(tmp, "fl.py"), "w").write("f = 1\n")
    git(tmp, "add", "fl.py")
    git(tmp, "commit", "--no-verify", "-q", "-m", "floor fixture parent")
    fp = git(tmp, "rev-parse", "HEAD").stdout.strip()
    with open(os.path.join(tmp, "n.tmp"), "w", encoding="utf-8") as fh:
        fh.write(json.dumps({"type": "CLEAR", "when": "20260921-190000",
                             "files": {"ov.py": {"when": "20260921-185500"}}}))
    git(tmp, "notes", "--ref", "refs/notes/adversary", "add", "-F", "n.tmp", fp)
    os.remove(os.path.join(tmp, "n.tmp"))
    open(os.path.join(tmp, "fl2.py"), "w").write("g = 2\n")
    git(tmp, "add", "fl2.py")
    git(tmp, "commit", "--no-verify", "-q", "-m", "floor fixture child")
    cwd1 = os.getcwd()
    os.chdir(tmp)
    try:
        floor2 = _g._cycle_floor(git(tmp, "rev-parse", "HEAD").stdout.strip(),
                                 "refs/notes/adversary")
    finally:
        os.chdir(cwd1)
    check("adjudication_floor_prefers_clearing_round_when",
          floor2 == "20260921-185500", "floor2=%r" % floor2)

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
    # 43. a same-named symbol that the bystander BINDS ITSELF is not a caller (gate catch
    #     gate_20260915 on the fleet Atlas deletion: deleting a package that defined `main` was
    #     refused because every other module's own `def main` and a `from deepagents import
    #     create_deep_agent` were reported as callers - a whole-package deletion could never pass).
    #     A module-level def/class of the name shadows it; so does `from X import name` ONLY on
    #     positive proof - X is a tracked, unstaged module at the repo root, the only path with
    #     that suffix anywhere in the non-ignored tree, and its index blob defines the name (the
    #     `from fleet.cli import main` shape: vendored.py's `from mytool import keep`). Everything
    #     unresolvable - an external package, an untracked module, a re-exporter, a duplicate
    #     name - stays a caller (44-51): over-refuse, never under-refuse.
    #     (the fixture repo is ARMED: every commit below needs a faked-CLEAR `gate run` first, and
    #     the real callers of `keep` - caller.py, commenter.py (35), reexport.py (41) - are removed
    #     or re-pointed in the same staged set, so only the shadowed bystanders remain)
    open(os.path.join(tmp, "mytool.py"), "w").write(
        "def keep():\n    return 'own'\n\n\ndef run():\n    return keep()\n")
    open(os.path.join(tmp, "vendored.py"), "w").write("from mytool import keep\n\n\ndef use():\n    return keep()\n")
    open(os.path.join(tmp, "bare.py"), "w").write("x = 1\n")
    open(os.path.join(tmp, "user2.py"), "w").write("def go():\n    return 2\n")
    git(tmp, "add", "mytool.py", "vendored.py", "bare.py", "user2.py")
    r = gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    git(tmp, "commit", "-q", "-m", "bystanders that bind keep themselves")

    def _delete_lib_with_its_real_callers():
        git(tmp, "rm", "-q", "lib.py", "reexport.py", "commenter.py")
        open(os.path.join(tmp, "caller.py"), "w").write("def use():\n    return 1\n")
        git(tmp, "add", "caller.py")

    _delete_lib_with_its_real_callers()
    r = gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    check("removed_symbol_shadowed_by_own_binding_not_a_caller",
          r.returncode == 0 and "CLEAR" in r.stdout and "REFUSED" not in r.stdout,
          "rc=%d %s" % (r.returncode, (r.stdout + r.stderr)[-300:]))
    git(tmp, "reset", "-q", "--hard")
    # 44. fail-closed kept: a bare unbound use of the name in a bystander still refuses, and the
    #     shadowed bystanders are not named
    open(os.path.join(tmp, "bare.py"), "w").write("x = keep\n")
    git(tmp, "add", "bare.py")
    r = gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    git(tmp, "commit", "-q", "-m", "bare unbound use")
    _delete_lib_with_its_real_callers()
    r = gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    check("removed_symbol_bare_unbound_use_still_refused",
          r.returncode == 1 and "REFUSED" in r.stdout and "bare.py" in r.stdout
          and "mytool.py" not in r.stdout and "vendored.py" not in r.stdout,
          "rc=%d %s" % (r.returncode, (r.stdout + r.stderr)[-300:]))
    git(tmp, "reset", "-q", "--hard")
    # 45. fail-closed kept: an import from a RE-EXPORTER that the same change deletes is a caller
    #     (`reexport.py` = `from lib import keep` goes with lib.py; user2.py still does
    #     `from reexport import keep` -> the binding cannot be trusted as the bystander's own)
    open(os.path.join(tmp, "bare.py"), "w").write("x = 1\n")
    open(os.path.join(tmp, "user2.py"), "w").write("from reexport import keep\n\n\ndef go():\n    return keep()\n")
    git(tmp, "add", "bare.py", "user2.py")
    r = gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    git(tmp, "commit", "-q", "-m", "user2 imports keep through the re-exporter")
    _delete_lib_with_its_real_callers()
    r = gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    check("removed_symbol_import_from_deleted_reexporter_still_refused",
          r.returncode == 1 and "REFUSED" in r.stdout and "user2.py" in r.stdout
          and "mytool.py" not in r.stdout and "vendored.py" not in r.stdout,
          "rc=%d %s" % (r.returncode, (r.stdout + r.stderr)[-300:]))
    git(tmp, "reset", "-q", "--hard")
    # 46. fail-closed kept: an import from an UNSTAGED tracked aggregator that re-exports the name
    #     transitively (`agg.py` = `from lib import *`, a pre-existing blind spot of the scan) is a
    #     caller - a tracked source shadows only when its own blob DEFINES the name (vendored.py's
    #     `mytool` does, so it is still not named)
    open(os.path.join(tmp, "agg.py"), "w").write("from lib import *\n")
    open(os.path.join(tmp, "user2.py"), "w").write("from agg import keep\n\n\ndef go():\n    return keep()\n")
    git(tmp, "add", "agg.py", "user2.py")
    r = gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    git(tmp, "commit", "-q", "-m", "user2 imports keep through a star-importing aggregator")
    _delete_lib_with_its_real_callers()
    r = gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    check("removed_symbol_import_via_unstaged_star_reexporter_still_refused",
          r.returncode == 1 and "REFUSED" in r.stdout and "user2.py" in r.stdout
          and "mytool.py" not in r.stdout and "vendored.py" not in r.stdout,
          "rc=%d %s" % (r.returncode, (r.stdout + r.stderr)[-300:]))
    git(tmp, "reset", "-q", "--hard")
    # 47. the import name is resolved from the ROOT and from the BYSTANDER'S OWN DIRECTORY, not by
    #     mangling the definer's path (gate catch gate_20260915-162201: `adversary-gate/x.py` can
    #     never equal an import name, so a sibling `from x import gone` was called external and
    #     vouched). Definer `sub-dir/mylib.py` (keep2), bystander `sub-dir/user3.py`
    #     (`from mylib import keep2`): deleting mylib.py must refuse naming user3.py.
    os.makedirs(os.path.join(tmp, "sub-dir"), exist_ok=True)
    open(os.path.join(tmp, "sub-dir", "mylib.py"), "w").write("def keep2():\n    return 1\n")
    open(os.path.join(tmp, "sub-dir", "user3.py"), "w").write(
        "from mylib import keep2\n\n\ndef go():\n    return keep2()\n")
    git(tmp, "add", "sub-dir/mylib.py", "sub-dir/user3.py")
    r = gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    git(tmp, "commit", "-q", "-m", "a hyphenated directory with a definer and its sibling caller")
    git(tmp, "rm", "-q", "sub-dir/mylib.py")
    r = gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    check("removed_symbol_sibling_import_in_hyphenated_dir_still_refused",
          r.returncode == 1 and "REFUSED" in r.stdout and "user3.py" in r.stdout and "keep2" in r.stdout,
          "rc=%d %s" % (r.returncode, (r.stdout + r.stderr)[-300:]))
    git(tmp, "reset", "-q", "--hard")
    # 48. an UNTRACKED worktree module cannot vouch, and neither can an EXTERNAL one: `ext.py`
    #     does `from third import keep` - refused both with an untracked third.py present in the
    #     worktree and with no third.py anywhere (static resolution cannot prove "external": a
    #     src/ layout or a sys.path entry hides repo code behind such a name - gate catch
    #     gate_20260915-165305); ext.py stays in the fixture as a standing caller from here on
    open(os.path.join(tmp, "ext.py"), "w").write("from third import keep\n\n\ndef use():\n    return keep()\n")
    git(tmp, "add", "ext.py")
    r = gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    git(tmp, "commit", "-q", "-m", "a bystander importing keep from an unknown module")
    open(os.path.join(tmp, "third.py"), "w").write("from lib import keep\n")
    _delete_lib_with_its_real_callers()
    r = gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    check("removed_symbol_untracked_worktree_source_cannot_vouch",
          r.returncode == 1 and "REFUSED" in r.stdout and "ext.py" in r.stdout and "mytool.py" not in r.stdout,
          "rc=%d %s" % (r.returncode, (r.stdout + r.stderr)[-300:]))
    os.remove(os.path.join(tmp, "third.py"))
    r = gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    check("removed_symbol_external_source_cannot_vouch",
          r.returncode == 1 and "REFUSED" in r.stdout and "ext.py" in r.stdout and "vendored.py" not in r.stdout,
          "rc=%d %s" % (r.returncode, (r.stdout + r.stderr)[-300:]))
    git(tmp, "reset", "-q", "--hard")
    # 49. candidate precedence: a bystander's OWN directory wins (Python puts the script's directory
    #     first on sys.path), and a vouch needs EVERY resolvable candidate to define the name -
    #     root `dupname.py` defines keep, but the surviving tracked `sub-dir/dupname.py` only
    #     re-exports the removed one, so `sub-dir/user4.py`'s `from dupname import keep` is a live caller
    open(os.path.join(tmp, "dupname.py"), "w").write("def keep():\n    return 'root'\n")
    open(os.path.join(tmp, "sub-dir", "dupname.py"), "w").write("from lib import keep\n")
    open(os.path.join(tmp, "sub-dir", "user4.py"), "w").write(
        "from dupname import keep\n\n\ndef go():\n    return keep()\n")
    git(tmp, "add", "dupname.py", "sub-dir/dupname.py", "sub-dir/user4.py")
    r = gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    git(tmp, "commit", "-q", "-m", "same module name at the root and beside the caller")
    _delete_lib_with_its_real_callers()                                       # sub-dir/dupname.py survives, unstaged
    r = gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    check("removed_symbol_sibling_candidate_outranks_root_definer",
          r.returncode == 1 and "REFUSED" in r.stdout and "user4.py" in r.stdout,
          "rc=%d %s" % (r.returncode, (r.stdout + r.stderr)[-300:]))
    git(tmp, "reset", "-q", "--hard")
    # 50. a root module that exists but only RE-EXPORTS the name is not proof: `rex.py` =
    #     `from lib import keep`, `user5.py` = `from rex import keep` -> both are callers
    open(os.path.join(tmp, "rex.py"), "w").write("from lib import keep\n")
    open(os.path.join(tmp, "user5.py"), "w").write("from rex import keep\n\n\ndef go():\n    return keep()\n")
    git(tmp, "add", "rex.py", "user5.py")
    r = gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    git(tmp, "commit", "-q", "-m", "a root re-exporter and its user")
    _delete_lib_with_its_real_callers()
    r = gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    check("removed_symbol_root_reexporter_is_not_proof",
          r.returncode == 1 and "REFUSED" in r.stdout and "user5.py" in r.stdout and "rex.py" in r.stdout,
          "rc=%d %s" % (r.returncode, (r.stdout + r.stderr)[-300:]))
    git(tmp, "reset", "-q", "--hard")
    # 51. a plain `import pkg.sub` never shadows a removed name (gate catch gate_20260915-165305):
    #     package `mpk/__init__.py` defines `mpk`; user6.py does `import mpk.helpers` and uses the
    #     bare name `mpk`; deleting the package must refuse naming user6.py (the bare use is the
    #     package object, now gone - an import binding is not the bystander's own definition)
    os.makedirs(os.path.join(tmp, "mpk"), exist_ok=True)
    open(os.path.join(tmp, "mpk", "__init__.py"), "w").write("def mpk():\n    return 1\n")
    open(os.path.join(tmp, "mpk", "helpers.py"), "w").write("X = 1\n")
    open(os.path.join(tmp, "user6.py"), "w").write("import mpk.helpers\n\n\ndef go():\n    return mpk\n")
    git(tmp, "add", "mpk/__init__.py", "mpk/helpers.py", "user6.py")
    r = gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    git(tmp, "commit", "-q", "-m", "a package whose __init__ defines its own name, and a dotted importer")
    git(tmp, "rm", "-q", "-r", "mpk")
    r = gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    check("removed_symbol_plain_import_never_shadows",
          r.returncode == 1 and "REFUSED" in r.stdout and "user6.py" in r.stdout,
          "rc=%d %s" % (r.returncode, (r.stdout + r.stderr)[-300:]))
    git(tmp, "reset", "-q", "--hard")
    # 52. a def that the same module later RE-BINDS is not proof (marketplace gate catch gate_20260915-182919):
    #     `mytool2.py` = `def keep()` + `from lib import keep` (the pure-Python-fallback-then-rebind shape),
    #     `user7.py` = `from mytool2 import keep` + bare use; deleting lib.py must name user7.py as well as
    #     mytool2.py - a name with ANY other module-level binding in the vouch target does not vouch
    open(os.path.join(tmp, "mytool2.py"), "w").write(
        "def keep():\n    return 'fallback'\n\n\nfrom lib import keep  # noqa: E402\n")
    open(os.path.join(tmp, "user7.py"), "w").write("from mytool2 import keep\n\n\ndef go():\n    return keep()\n")
    git(tmp, "add", "mytool2.py", "user7.py")
    r = gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    git(tmp, "commit", "-q", "-m", "a definer that re-binds its own def, and its user")
    _delete_lib_with_its_real_callers()
    r = gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    check("removed_symbol_rebound_def_is_not_proof",
          r.returncode == 1 and "REFUSED" in r.stdout and "user7.py" in r.stdout and "mytool2.py" in r.stdout
          and "vendored.py" not in r.stdout,
          "rc=%d %s" % (r.returncode, (r.stdout + r.stderr)[-300:]))
    git(tmp, "reset", "-q", "--hard")
    # 53. the WILDCARD twin (marketplace gate catch gate_20260915-184551): `mytool3.py` = `def keep()` +
    #     `from lib import *` - the star import re-binds every public name but is itself never a listed
    #     caller, so before the fix NOBODY was named and the deletion CLEARed; `user8.py` =
    #     `from mytool3 import keep` + bare use must be named. A vouch target with a module-level star
    #     import vouches for nothing.
    open(os.path.join(tmp, "mytool3.py"), "w").write(
        "def keep():\n    return 'fallback'\n\n\nfrom lib import *  # noqa: E402,F403\n")
    open(os.path.join(tmp, "user8.py"), "w").write("from mytool3 import keep\n\n\ndef go():\n    return keep()\n")
    git(tmp, "add", "mytool3.py", "user8.py")
    r = gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    git(tmp, "commit", "-q", "-m", "a definer that star-imports over its own def, and its user")
    _delete_lib_with_its_real_callers()
    r = gate(tmp, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
    check("removed_symbol_star_import_over_def_is_not_proof",
          r.returncode == 1 and "REFUSED" in r.stdout and "user8.py" in r.stdout and "vendored.py" not in r.stdout,
          "rc=%d %s" % (r.returncode, (r.stdout + r.stderr)[-300:]))
    git(tmp, "reset", "-q", "--hard")
    # 54. the binding shapes `_sole_module_level_defs` must see, pinned on the function itself: a star import
    #     empties the set; a walrus, an `except ... as`, a `match` capture, a `del`, a second def of the
    #     same name and a def inside `if`/`try` all exclude the name; a METHOD of the same name inside a
    #     class and a function-LOCAL assignment do not (they never re-bind the module attribute)
    sd = _g._sole_module_level_defs
    shapes_ok = (
        sd("def keep():\n    pass\nfrom lib import *\n") == set()
        and sd("def keep():\n    pass\n(keep := 1)\n") == set()
        and sd("def keep():\n    pass\ntry:\n    pass\nexcept Exception as keep:\n    pass\n") == set()
        and sd("def keep():\n    pass\nmatch 1:\n    case keep:\n        pass\n") == set()
        and sd("def keep():\n    pass\ndel keep\n") == set()
        and sd("def keep():\n    pass\ndef keep():\n    pass\n") == set()
        and sd("def keep():\n    pass\nif x:\n    def keep():\n        pass\n") == set()
        and sd("def keep():\n    pass\ntry:\n    from accel import keep\nexcept ImportError:\n    pass\n") == set()
        and sd("def keep():\n    pass\nfor keep in ():\n    pass\n") == set()
        # round 9 (gate_20260915-185436): a match MAPPING-REST capture and a walrus inside a def's or a
        # lambda's DEFAULT arguments (evaluated in module scope at def time) re-bind the name too
        and sd("def keep():\n    pass\nmatch d:\n    case {**keep}:\n        pass\n") == set()
        and sd("def keep():\n    pass\ndef run(x=(keep := 1)):\n    pass\n") == {"run"}
        and sd("def keep():\n    pass\nf = lambda x=(keep := 2): x\n") == set()
        and sd("def keep():\n    pass\nasync def run(*, x=(keep := 1)):\n    pass\n") == {"run"}
        # round 10 (gate_20260915-190345): class bases, class keywords and a def's return annotation are
        # evaluated in module scope at definition time too
        and sd("def keep():\n    pass\nclass C((keep := object)):\n    pass\n") == {"C"}
        and sd("def keep():\n    pass\nclass C(metaclass=(keep := type)):\n    pass\n") == {"C"}
        and sd("def keep():\n    pass\ndef run() -> (keep := int):\n    pass\n") == {"run"}
        and sd("def keep():\n    pass\ndef run(x: (keep := int)):\n    pass\n") == {"run"}
        # round 11 (marketplace gate_20260915-192907): a `global` declaration inside ANY nested body re-binds
        # the module attribute when that body runs - a class body runs at import, a function body when
        # called - so a declared global excludes the name from every body (over-refuse for the function case)
        and sd("def keep():\n    pass\nclass C:\n    global keep\n    keep = 1\n") == {"C"}
        and sd("def keep():\n    pass\ndef run():\n    global keep\n    keep = 2\n") == {"run"}
        and sd("def keep():\n    pass\nclass C:\n    def m(self):\n        global keep\n        del keep\n") == {"C"}
        and sd("def keep():\n    pass\nclass C:\n    def keep(self):\n        pass\n") == {"keep", "C"}
        and sd("def keep():\n    pass\ndef run():\n    keep = 1\n    return keep\n") == {"keep", "run"}
        and sd("def keep(:\n") is None
    )
    check("sole_module_level_defs_binding_shapes", shapes_ok)

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

    # 43. binary blobs never reach the docs model (2026-09-17): a one-PNG brand commit's push was REFUSED - `--text`
    #     forces a diff of the binary and its NUL-free lines (28,881 from one 2 MB image) went to the docs model as
    #     documentation, which flagged secret-shaped garbage in chunk 8. The staged scanner already skips a blob with
    #     a NUL in its first 8 KB (_staged_doc_files); the push audit applies the same rule per path. The doc beside
    #     the image is still fed, so the skip is per blob, never per commit.
    import random
    tmp2 = tempfile.mkdtemp(prefix="advgate_bin_")
    subprocess.run([GIT, "init", "-q", tmp2], capture_output=True)
    git(tmp2, "config", "user.email", "t@t")
    git(tmp2, "config", "user.name", "t")
    rnd = random.Random(7)
    alphabet = b"abcdefghijklmnopqrstuvwxyz0123456789=+/"
    body = b"\n".join(bytes(rnd.choice(alphabet) for _ in range(60)) for _ in range(400))
    with open(os.path.join(tmp2, "art.png"), "wb") as fh:
        fh.write(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + body)  # a NUL in the header, NUL-free lines after
    with open(os.path.join(tmp2, "NOTE.md"), "w", encoding="utf-8") as fh:
        fh.write("a real doc line\n")
    git(tmp2, "add", "art.png", "NOTE.md")
    git(tmp2, "commit", "-q", "-m", "brand image")
    sha = git(tmp2, "rev-parse", "HEAD").stdout.strip()
    # the gate's own round on this fix: the skip is for the DOCS FEED only - a hard literal planted inside a binary
    # asset must still refuse the push (built from parts at runtime, never a literal in these bytes)
    planted = "AK" + "IA" + "ABCDEFGHIJKLMNOP"
    with open(os.path.join(tmp2, "cred.bin"), "wb") as fh:
        fh.write(b"\x00BIN\n" + body[:600] + b"\nkey = " + planted.encode("ascii") + b"\n" + body[600:1200])
    git(tmp2, "add", "cred.bin")
    git(tmp2, "commit", "-q", "-m", "asset with a planted literal")
    sha_bin = git(tmp2, "rev-parse", "HEAD").stdout.strip()
    cwd0 = os.getcwd()
    os.chdir(tmp2)
    try:
        hard2, soft2, docs2 = _g._push_secret_audit([sha])
        hard3, _soft3, docs3 = _g._push_secret_audit([sha_bin])
    finally:
        os.chdir(cwd0)
    check("push_audit_never_feeds_a_binary_blob_to_the_docs_model",
          docs2.strip() == "a real doc line" and not hard2 and not soft2,
          "doc lines %d hard %d soft %d" % (docs2.count("\n") + 1, len(hard2), len(soft2)))
    check("push_audit_floor_still_refuses_a_literal_planted_inside_a_binary",
          any(h[1] == "cred.bin" for h in hard3) and docs3.strip() == "",
          "hard %s docs %d" % (hard3[:2], len(docs3)))

    # --- true-rate adjudication recording (owner order 2026-09-21): the recording must
    # classify every finding of a commit's INITIAL denial - fixed / rebutted-upheld /
    # rebutted-rejected / cleared-unedited / overridden / indeterminate - from evidence
    # the gate itself holds (review artifacts + the staged-shas sidecar + clearance rows).
    tmp3 = tempfile.mkdtemp(prefix="advadj_")
    rvw3 = os.path.join(tmp3, ".adversary", "reviews")
    os.makedirs(rvw3, exist_ok=True)

    def _adj_art(name, files, verdict, findings_text):
        hdr = ("model: m | provider: p | usage: 1 | scrubbed: 0 | files: %s | caller: fixture-agent\n\n"
               % (files,))          # EXACTLY _review_header's list-repr shape, NEW
                                      # format incl. the trailing caller field (the
                                      # gate catch gate_20260923-182445: fixtures must
                                      # mirror the real header or the files-regex
                                      # regression ships uncovered)
        with open(os.path.join(rvw3, name), "w", encoding="utf-8") as fh:
            fh.write(hdr + findings_text + "\nVERDICT: %s\n" % verdict)

    FIND = ("1. HIGH app.py:12 - off-by-one drops the last allocation slot.\n\n"
            "2. MEDIUM app.py:40 - close() races the retry loop.\n\n"
            "3. LOW - the second stage drops the lock twice.")

    def _adj_fixture(denial_name, denial_shas, later=None, sidecar=None, consumed=None):
        for f in os.listdir(rvw3):
            os.remove(os.path.join(rvw3, f))
        for f in os.listdir(os.path.join(tmp3, ".adversary")):
            if f != "reviews":
                os.remove(os.path.join(tmp3, ".adversary", f))
        _adj_art(denial_name, ["app.py", "lib/util.py"], "BLOCK", FIND)
        if later:
            for nm, vd, fl in later:
                _adj_art(nm, fl, vd, "")
        if sidecar is not None:
            with open(os.path.join(rvw3, "staged_shas.json"), "w", encoding="utf-8") as fh:
                json.dump(sidecar, fh)
        if consumed is not None:
            with open(os.path.join(tmp3, ".adversary", "adjudications.json"), "w",
                      encoding="utf-8") as fh:
                json.dump({"version": 1, "episodes": (
                    [{"commit": "c0", "denial_artifact": "reviews/" + denial_name,
                      "rounds": ["reviews/" + denial_name], "findings": []}]
                    if consumed else [])}, fh)

    CHANGED = {"app.py": "shaB"}
    CLEAR_B = {"app.py": {"sha": "shaB", "verdict": "CLEAR",
                          "artifact": "reviews/gate_20260921-100500.md"}}

    _adj_fixture("gate_20260921-100000.md", None,
                 later=[("gate_20260921-100500.md", "CLEAR", ["app.py"])],
                 sidecar={"gate_20260921-100000.md": {"staged": {"app.py": "shaA"},
                                                      "rebuttal": False},
                          "gate_20260921-100500.md": {"staged": {"app.py": "shaB"},
                                                      "rebuttal": False}})
    ep = _g._adjudicate_cycle(tmp3, "c1", CHANGED, CLEAR_B, "CLEAR")
    outs = {f["id"]: f["outcome"] for f in (ep or {}).get("findings", [])}
    check("adjudication_fixed_on_edit",
          ep is not None and outs.get("F1") == "fixed" and outs.get("F3") == "fixed"
          and ep["denial_artifact"] == "reviews/gate_20260921-100000.md",
          "ep=%s outs=%s" % (bool(ep), outs))

    _adj_fixture("gate_20260921-100000.md", None,
                 later=[("gate_20260921-100500.md", "CLEAR", ["app.py"])],
                 sidecar={"gate_20260921-100000.md": {"staged": {"app.py": "shaB"},
                                                      "rebuttal": False},
                          "gate_20260921-100500.md": {"staged": {"app.py": "shaB"},
                                                      "rebuttal": True}})
    ep = _g._adjudicate_cycle(tmp3, "c2", CHANGED, CLEAR_B, "CLEAR")
    outs = {f["id"]: f["outcome"] for f in (ep or {}).get("findings", [])}
    check("adjudication_rebuttal_upheld",
          ep is not None and set(outs.values()) == {"rebutted-upheld"}, "outs=%s" % outs)

    _adj_fixture("gate_20260921-100000.md", None,
                 later=[("gate_20260921-100500.md", "CLEAR", ["app.py"])],
                 sidecar={"gate_20260921-100000.md": {"staged": {"app.py": "shaB"},
                                                      "rebuttal": False},
                          "gate_20260921-100500.md": {"staged": {"app.py": "shaB"},
                                                      "rebuttal": False}})
    ep = _g._adjudicate_cycle(tmp3, "c3", CHANGED, CLEAR_B, "CLEAR")
    outs = {f["id"]: f["outcome"] for f in (ep or {}).get("findings", [])}
    check("adjudication_cleared_unedited",
          ep is not None and set(outs.values()) == {"cleared-unedited"}, "outs=%s" % outs)

    _adj_fixture("gate_20260921-100000.md", None,
                 later=[("gate_20260921-100300.md", "BLOCK", ["app.py"]),
                        ("gate_20260921-100500.md", "CLEAR", ["app.py"])],
                 sidecar={"gate_20260921-100000.md": {"staged": {"app.py": "shaA"},
                                                      "rebuttal": False},
                          "gate_20260921-100300.md": {"staged": {"app.py": "shaA"},
                                                      "rebuttal": True},
                          "gate_20260921-100500.md": {"staged": {"app.py": "shaB"},
                                                      "rebuttal": False}})
    ep = _g._adjudicate_cycle(tmp3, "c4", CHANGED, CLEAR_B, "CLEAR")
    f1 = next((f for f in (ep or {}).get("findings", []) if f["id"] == "F1"), {})
    check("adjudication_rebuttal_rejected_flag",
          ep is not None and f1.get("outcome") == "fixed" and f1.get("rebuttal_rejected"),
          "f1=%s" % f1)

    ep = _g._adjudicate_cycle(tmp3, "c5", CHANGED, CLEAR_B, "OVERRIDE")
    outs = {f["id"]: f["outcome"] for f in (ep or {}).get("findings", [])}
    check("adjudication_overridden",
          ep is not None and set(outs.values()) == {"overridden"}, "outs=%s" % outs)

    _adj_fixture("gate_20260921-100000.md", None,
                 later=[("gate_20260921-100500.md", "CLEAR", ["app.py"])])
    ep = _g._adjudicate_cycle(tmp3, "c6", CHANGED, CLEAR_B, "CLEAR")
    outs = {f["id"]: f["outcome"] for f in (ep or {}).get("findings", [])}
    check("adjudication_indeterminate_without_sidecar",
          ep is not None and set(outs.values()) == {"indeterminate"}, "outs=%s" % outs)

    _adj_fixture("gate_20260921-100000.md", None, consumed=True)
    check("adjudication_dedupes_consumed_artifacts",
          _g._adjudicate_cycle(tmp3, "c7", CHANGED, CLEAR_B, "CLEAR") is None)

    _adj_fixture("gate_20260921-100000.md", None,
                 later=[("gate_20260921-100500.md", "CLEAR", ["app.py"])])
    for f in os.listdir(rvw3):                # wipe EVERY round, then stage a lone CLEAR
        if f.startswith("gate_"):
            os.remove(os.path.join(rvw3, f))
    _adj_art("gate_20260921-100500.md", ["app.py"], "CLEAR", "")
    check("adjudication_none_without_denial",
          _g._adjudicate_cycle(tmp3, "c8", CHANGED, CLEAR_B, "CLEAR") is None)

    _adj_fixture("gate_20260921-100000.md", None,
                 sidecar={"gate_20260921-100000.md": {"staged": {"app.py": "shaA"},
                                                      "rebuttal": False}})
    ep = _g._adjudicate_cycle(tmp3, "c9", CHANGED, {}, "CLEAR")
    _g._append_adjudication(tmp3, ep)
    _g._append_adjudication(tmp3, ep)
    with open(os.path.join(tmp3, ".adversary", "adjudications.json"), encoding="utf-8") as fh:
        eps9 = json.load(fh)["episodes"]
    check("adjudication_append_is_idempotent",
          len(eps9) == 1 and eps9[0]["commit"] == "c9",
          "episodes=%d" % len(eps9))

    for f in os.listdir(rvw3):
        os.remove(os.path.join(rvw3, f))
    a1 = _g._write_review_round(tmp3, "20260921-110000",
                                "model: m | provider: p | usage: 1 | scrubbed: 0 | "
                                "files: %s\n\nok\nVERDICT: CLEAR\n" % (["app.py"],),
                                {"app.py": "shaZ"}, True)
    a2 = _g._write_review_round(tmp3, "20260921-110000",
                                "model: m | provider: p | usage: 1 | scrubbed: 0 | "
                                "files: %s\n\nok\nVERDICT: CLEAR\n" % (["app.py"],),
                                {"app.py": "shaZ"}, False)
    with open(os.path.join(rvw3, "staged_shas.json"), encoding="utf-8") as fh:
        sc = json.load(fh)
    check("adjudication_artifact_and_sidecar_atomic_pair",
          os.path.basename(a1) != os.path.basename(a2)
          and os.path.isfile(a1) and os.path.isfile(a2)
          and sc.get(os.path.basename(a1)) == {"staged": {"app.py": "shaZ"},
                                               "rebuttal": True}
          and sc.get(os.path.basename(a2)) == {"staged": {"app.py": "shaZ"},
                                               "rebuttal": False},
          "a1=%s a2=%s sidecar=%s" % (os.path.basename(a1), os.path.basename(a2), sc))

    _adj_fixture("gate_20260921-100000.md", None,
                 later=[("gate_20260921-100300.md", "BLOCK", ["app.py"]),
                        ("gate_20260921-100500.md", "CLEAR", ["app.py"])],
                 sidecar={"gate_20260921-100000.md": {"staged": {"app.py": "shaB"},
                                                      "rebuttal": False},
                          "gate_20260921-100300.md": {"staged": {"app.py": "shaB"},
                                                      "rebuttal": True},
                          "gate_20260921-100500.md": {"staged": {"app.py": "shaB"},
                                                      "rebuttal": False}})
    ep = _g._adjudicate_cycle(tmp3, "c10", CHANGED, CLEAR_B, "CLEAR")
    outs = {f["id"]: f["outcome"] for f in (ep or {}).get("findings", [])}
    check("adjudication_rejected_rebuttal_not_upheld",
          ep is not None and set(outs.values()) == {"cleared-unedited"}
          and all(f["rebuttal_rejected"] for f in ep["findings"]),
          "outs=%s" % outs)

    _adj_fixture("gate_20260900-090000.md", None,          # weeks-old abandoned denial
                 later=[("gate_20260921-100000.md", "BLOCK", ["app.py"]),
                        ("gate_20260921-100500.md", "CLEAR", ["app.py"])],
                 sidecar={"gate_20260900-090000.md": {"staged": {"app.py": "shaOLD"},
                                                      "rebuttal": False},
                          "gate_20260921-100000.md": {"staged": {"app.py": "shaA"},
                                                      "rebuttal": False},
                          "gate_20260921-100500.md": {"staged": {"app.py": "shaB"},
                                                      "rebuttal": False}})
    ep = _g._adjudicate_cycle(tmp3, "c11", CHANGED, CLEAR_B, "CLEAR",
                              after="20260921-093000")
    check("adjudication_stale_denial_excluded_by_prev_commit",
          ep is not None and ep["denial_artifact"] == "reviews/gate_20260921-100000.md",
          "denial=%s" % (ep or {}).get("denial_artifact"))

    for f in os.listdir(rvw3):
        if f.startswith("gate_"):
            os.remove(os.path.join(rvw3, f))
    with open(os.path.join(rvw3, "gate_20260921-120000.md"), "w", encoding="utf-8") as fh:
        fh.write("model: m | provider: p | usage: 1 | scrubbed: 0 | files: %s\n\n"
                 % (["app.py"],)
                 + "prose quoting VERDICT: BLOCK mid-review\n\nVERDICT: CLEAR\n")
    check("adjudication_verdict_last_line_wins",
          _g._adjudicate_cycle(tmp3, "c12", CHANGED, CLEAR_B, "CLEAR") is None)

    for f in os.listdir(rvw3):
        if f.startswith("gate_"):
            os.remove(os.path.join(rvw3, f))
    _adj_art("gate_20260921-130000.md", [], "BLOCK",
             "1. HIGH D:gone.py - the deleted module still had callers.")
    CHANGED_RM = {"D:gone.py": "shaG"}
    with open(os.path.join(rvw3, "staged_shas.json"), "w", encoding="utf-8") as fh:
        json.dump({"gate_20260921-130000.md": {"staged": {"D:gone.py": "shaH"},
                                               "rebuttal": False}}, fh)
    ep = _g._adjudicate_cycle(tmp3, "c13", CHANGED_RM, {"D:gone.py": {
        "sha": "shaG", "verdict": "CLEAR", "artifact": "reviews/gate_20260921-130500.md"}},
        "CLEAR")
    outs = {f["id"]: f["outcome"] for f in (ep or {}).get("findings", [])}
    check("adjudication_removals_only_denial",
          ep is not None and set(outs.values()) == {"fixed"}, "outs=%s" % outs)

    for f in os.listdir(rvw3):
        if f.startswith("gate_"):
            os.remove(os.path.join(rvw3, f))
    _adj_art("gate_20260921-140000.md", ["app.py"], "BLOCK",
             "1. HIGH app.py:12 - off-by-one drops the last slot.\n\n"
             "2. The retry loop may follow stale state and lose the write.")
    with open(os.path.join(rvw3, "staged_shas.json"), "w", encoding="utf-8") as fh:
        json.dump({"gate_20260921-140000.md": {"staged": {"app.py": "shaA"},
                                               "rebuttal": False}}, fh)
    ep = _g._adjudicate_cycle(tmp3, "c14", CHANGED, CLEAR_B, "CLEAR")
    check("adjudication_severity_word_boundary",
          ep is not None and len(ep["findings"]) == 1
          and ep["findings"][0]["outcome"] == "fixed",
          "findings=%s" % (ep or {}).get("findings"))

    _adj_fixture("gate_20260921-100000.md", None,
                 sidecar={"gate_20260921-100000.md": {"staged": {"app.py": "shaA"},
                                                      "rebuttal": False}})
    ep = _g._adjudicate_cycle(tmp3, "c15", {"D:app.py": "sha0"}, {}, "CLEAR")
    outs = {f["id"]: f["outcome"] for f in (ep or {}).get("findings", [])}
    check("adjudication_delete_remediation_is_fixed",
          ep is not None and set(outs.values()) == {"fixed"}, "outs=%s" % outs)

    for f in os.listdir(rvw3):
        if f.startswith("gate_"):
            os.remove(os.path.join(rvw3, f))
    _adj_art("gate_20260921-150000.md", ["app.py"], "CLEAR",
             "1. HIGH app.py:12 - boom.\n\nVERDICT: BLOCK\n\nVERDICT: CLEAR")
    ep = _g._adjudicate_cycle(tmp3, "c16", CHANGED, CLEAR_B, "CLEAR")
    check("adjudication_conflicting_verdicts_count_as_denial", ep is not None)

    _adj_fixture("gate_20260921-100000.md", None,
                 later=[("gate_20260921-100500.md", "CLEAR", ["app.py"])],
                 sidecar={"gate_20260921-100000.md": {"staged": {"app.py": "shaB"},
                                                      "rebuttal": False}})
    ep = _g._adjudicate_cycle(tmp3, "c17", CHANGED, CLEAR_B, "CLEAR")
    outs = {f["id"]: f["outcome"] for f in (ep or {}).get("findings", [])}
    check("adjudication_clearing_without_sidecar_is_indeterminate",
          ep is not None and set(outs.values()) == {"indeterminate"},
          "outs=%s" % outs)

    _adj_fixture("gate_20260921-100000.md", None,
                 later=[("gate_20260921-100500.md", "CLEAR", ["a.py"]),
                        ("gate_20260921-100600.md", "CLEAR", ["b.py"])])
    for f in os.listdir(rvw3):                   # rebuild the denial two-file body
        if f.startswith("gate_"):
            os.remove(os.path.join(rvw3, f))
    _adj_art("gate_20260921-100000.md", ["a.py", "b.py"], "BLOCK",
             "1. HIGH a.py:1 - the allocator drops the tail.\n\n"
             "2. MEDIUM b.py:2 - the retry loop re-enters.")
    _adj_art("gate_20260921-100500.md", ["a.py"], "CLEAR", "")
    _adj_art("gate_20260921-100600.md", ["b.py"], "CLEAR", "")
    with open(os.path.join(rvw3, "staged_shas.json"), "w", encoding="utf-8") as fh:
        json.dump({"gate_20260921-100000.md": {"staged": {"a.py": "shaA",
                                                          "b.py": "shaB"},
                                               "rebuttal": False},
                   "gate_20260921-100500.md": {"staged": {"a.py": "shaA"},
                                               "rebuttal": False},
                   "gate_20260921-100600.md": {"staged": {"b.py": "shaB"},
                                               "rebuttal": True}}, fh)
    CLEAR_TWO = {"a.py": {"sha": "shaA", "verdict": "CLEAR",
                          "artifact": "reviews/gate_20260921-100500.md"},
                 "b.py": {"sha": "shaB", "verdict": "CLEAR",
                          "artifact": "reviews/gate_20260921-100600.md"}}
    ep = _g._adjudicate_cycle(tmp3, "c18", {"a.py": "shaA", "b.py": "shaB"},
                              CLEAR_TWO, "CLEAR")
    outs = {f["id"]: f["outcome"] for f in (ep or {}).get("findings", [])}
    check("adjudication_per_finding_upheld",
          ep is not None and outs.get("F1") == "cleared-unedited"
          and outs.get("F2") == "rebutted-upheld", "outs=%s" % outs)

    _adj_fixture("gate_20260921-100000.md", None,
                 later=[("gate_20260921-100500.md", "CLEAR", ["app.py"])],
                 sidecar={"gate_20260921-100000.md": {"staged": {"app.py": "shaB"},
                                                      "rebuttal": False},
                          "gate_20260921-100500.md": {"staged": {"app.py": "shaB"},
                                                      "rebuttal": False}})
    ep = _g._adjudicate_cycle(tmp3, "c19", CHANGED,
                              {"app.py": {"sha": "shaB", "verdict": "CLEAR",
                                          "artifact": "reviews/gate_20260921-100500.md"}},
                              "CLEAR", after="20260921-100000")
    outs = {f["id"]: f["outcome"] for f in (ep or {}).get("findings", [])}
    check("adjudication_same_second_denial_included",
          ep is not None and set(outs.values()) == {"cleared-unedited"},
          "outs=%s" % outs)
    ep = _g._adjudicate_cycle(tmp3, "c20", CHANGED,
                              {"app.py": {"sha": "shaB", "verdict": "CLEAR"}},
                              "CLEAR")
    outs = {f["id"]: f["outcome"] for f in (ep or {}).get("findings", [])}
    check("adjudication_no_clearing_artifact_is_indeterminate",
          ep is not None and set(outs.values()) == {"indeterminate"},
          "outs=%s" % outs)

    _adj_fixture("gate_20260921-100000.md", None,
                 later=[("gate_20260921-100500.md", "CLEAR", ["util.py", "x_util.py"])])
    for f in os.listdir(rvw3):
        if f.startswith("gate_"):
            os.remove(os.path.join(rvw3, f))
    _adj_art("gate_20260921-100000.md", ["util.py", "x_util.py"], "BLOCK",
             "1. HIGH x_util.py:9 - the wrapper leaks its handle.")
    _adj_art("gate_20260921-100500.md", ["util.py", "x_util.py"], "CLEAR", "")
    with open(os.path.join(rvw3, "staged_shas.json"), "w", encoding="utf-8") as fh:
        json.dump({"gate_20260921-100000.md": {"staged": {"util.py": "shaU",
                                                          "x_util.py": "shaX"},
                                               "rebuttal": False},
                   "gate_20260921-100500.md": {"staged": {"util.py": "shaU2",
                                                          "x_util.py": "shaX"},
                                               "rebuttal": False}}, fh)
    CLEAR_TOK = {"util.py": {"sha": "shaU2", "verdict": "CLEAR",
                             "artifact": "reviews/gate_20260921-100500.md"},
                 "x_util.py": {"sha": "shaX", "verdict": "CLEAR",
                               "artifact": "reviews/gate_20260921-100500.md"}}
    ep = _g._adjudicate_cycle(tmp3, "c21", {"util.py": "shaU2", "x_util.py": "shaX"},
                              CLEAR_TOK, "CLEAR")
    outs = {f["id"]: f["outcome"] for f in (ep or {}).get("findings", [])}
    check("adjudication_token_citation_no_substring",
          ep is not None and outs.get("F1") == "cleared-unedited"
          and ep["findings"][0]["files"] == ["x_util.py"],
          "outs=%s" % outs)

    for f in os.listdir(rvw3):
        if f.startswith("gate_"):
            os.remove(os.path.join(rvw3, f))
    with open(os.path.join(rvw3, "gate_20260921-160000.md"), "w",
              encoding="utf-8") as fh:      # NO files: header - a parse miss
        fh.write("1. HIGH gone.py - broken.\n\nVERDICT: BLOCK\n")
    check("adjudication_unparsed_header_not_adopted_by_removals",
          _g._adjudicate_cycle(tmp3, "c22", {"D:gone.py": "shaG"}, {}, "CLEAR") is None)

    _adj_fixture("gate_20260921-100000.md", None,
                 later=[("gate_20260921-100000-2.md", "BLOCK", ["app.py"]),
                        ("gate_20260921-100500.md", "CLEAR", ["app.py"])],
                 sidecar={"gate_20260921-100000.md": {"staged": {"app.py": "shaB"},
                                                      "rebuttal": False},
                          "gate_20260921-100000-2.md": {"staged": {"app.py": "shaB"},
                                                        "rebuttal": False},
                          "gate_20260921-100500.md": {"staged": {"app.py": "shaB"},
                                                      "rebuttal": False}})
    ep = _g._adjudicate_cycle(tmp3, "c23", CHANGED, CLEAR_B, "CLEAR",
                              after="20260921-100000")
    outs = {f["id"]: f["outcome"] for f in (ep or {}).get("findings", [])}
    check("adjudication_suffixed_same_second_denial_included",
          ep is not None and set(outs.values()) == {"cleared-unedited"}
          and ep["denial_artifact"] == "reviews/gate_20260921-100000.md",
          "denial=%s outs=%s" % ((ep or {}).get("denial_artifact"), outs))

    _adj_fixture("gate_20260921-100000.md", None,
                 later=[("gate_20260921-100500.md", "CLEAR", ["app.py"])])
    for f in os.listdir(rvw3):
        if f.startswith("gate_"):
            os.remove(os.path.join(rvw3, f))
    _adj_art("gate_20260921-100000.md", ["app.py"], "BLOCK",
             "1. HIGH app.py:12. - the loop drops the tail element.")
    _adj_art("gate_20260921-100500.md", ["app.py"], "CLEAR", "")
    with open(os.path.join(rvw3, "staged_shas.json"), "w", encoding="utf-8") as fh:
        json.dump({"gate_20260921-100000.md": {"staged": {"app.py": "shaB"},
                                               "rebuttal": False},
                   "gate_20260921-100500.md": {"staged": {"app.py": "shaB"},
                                               "rebuttal": False}}, fh)
    ep = _g._adjudicate_cycle(tmp3, "c24", CHANGED, CLEAR_B, "CLEAR")
    f1 = next((f for f in (ep or {}).get("findings", [])), {})
    check("adjudication_period_citation",
          ep is not None and f1.get("files") == ["app.py"]
          and f1.get("outcome") == "cleared-unedited", "f1=%s" % f1)

    _adj_fixture("gate_20260921-100000.md", None)
    for f in os.listdir(rvw3):
        if f.startswith("gate_"):
            os.remove(os.path.join(rvw3, f))
    _adj_art("gate_20260921-100000.md", ["m.py"], "BLOCK",
             "1. HIGH m.py:3 - the mixed round leaves a dangling removal.")
    with open(os.path.join(rvw3, "staged_shas.json"), "w", encoding="utf-8") as fh:
        json.dump({"gate_20260921-100000.md": {"staged": {"m.py": "s1",
                                                          "D:del.py": "s2"},
                                               "rebuttal": False}}, fh)
    ep = _g._adjudicate_cycle(tmp3, "c25", {"D:del.py": "shaNEW"}, {}, "CLEAR")
    outs = {f["id"]: f["outcome"] for f in (ep or {}).get("findings", [])}
    check("adjudication_mixed_round_removal_touch",
          ep is not None and set(outs.values()) == {"fixed"}, "outs=%s" % outs)

    _adj_fixture("gate_20260921-100000.md", None,
                 later=[("gate_20260921-100500.md", "CLEAR", ["app.py"])])
    for f in os.listdir(rvw3):
        if f.startswith("gate_"):
            os.remove(os.path.join(rvw3, f))
    with open(os.path.join(rvw3, "gate_20260921-170000.md"), "w",
              encoding="utf-8") as fh:
        fh.write("model: m | provider: p | usage: 1 | scrubbed: 0 | files: %s\n\n"
                 % (["app.py"],)
                 + "1. HIGH app.py:1 - lowercase marker.\n\nverdict: block\n")
    ep = _g._adjudicate_cycle(tmp3, "c26", CHANGED, CLEAR_B, "CLEAR")
    check("adjudication_lowercase_verdict_is_a_denial", ep is not None)

    adjp3 = os.path.join(tmp3, ".adversary", "adjudications.json")
    if os.path.isfile(adjp3):
        os.remove(adjp3)
    _adj_fixture("gate_20260921-100000.md", None,
                 sidecar={"gate_20260921-100000.md": {"staged": {"app.py": "shaA"},
                                                      "rebuttal": False}})
    ep = _g._adjudicate_cycle(tmp3, "c27", CHANGED, {}, "CLEAR")
    orig_lock = _g._adv_lock            # busy lock stubbed: the F3 contract under
    _g._adv_lock = lambda adv, name, deadline_s=10: None   # test is _append's
    try:                                # None-handling, not the 10 s stall itself
        busy = _g._append_adjudication(tmp3, ep)
    finally:
        _g._adv_lock = orig_lock
    persisted = _g._append_adjudication(tmp3, ep)
    with open(adjp3, encoding="utf-8") as fh:
        eps27 = json.load(fh)["episodes"]
    check("adjudication_append_reports_persistence",
          busy is False and persisted is True and len(eps27) == 1,
          "busy=%s persisted=%s eps=%d" % (busy, persisted, len(eps27)))

    _adj_fixture("gate_20260921-100000.md", None,
                 later=[("gate_20260921-100500.md", "CLEAR", ["app.py"])])
    for f in os.listdir(rvw3):
        if f.startswith("gate_"):
            os.remove(os.path.join(rvw3, f))
    _adj_art("gate_20260921-100000.md", ["app.py", "ghost.py"], "BLOCK",
             "1. HIGH ghost.py:7 - the uncited path leaks.")
    _adj_art("gate_20260921-100500.md", ["app.py"], "CLEAR", "")
    _adj_art("gate_20260921-090000.md", ["ghost.py"], "CLEAR", "")   # a STALE older
    with open(os.path.join(rvw3, "staged_shas.json"), "w", encoding="utf-8") as fh:
        json.dump({"gate_20260921-100000.md": {"staged": {"app.py": "shaB",
                                                          "ghost.py": "shaX"},
                                               "rebuttal": False},
                   "gate_20260921-100500.md": {"staged": {"app.py": "shaB"},
                                               "rebuttal": False},
                   "gate_20260921-090000.md": {"staged": {"ghost.py": "shaX"},
                                               "rebuttal": True}}, fh)
    CLEAR_STALE = {"app.py": {"sha": "shaB", "verdict": "CLEAR",
                              "artifact": "reviews/gate_20260921-100500.md"},
                   "ghost.py": {"sha": "shaX", "verdict": "CLEAR",
                                "artifact": "reviews/gate_20260921-090000.md"}}
    ep = _g._adjudicate_cycle(tmp3, "c28", CHANGED, CLEAR_STALE, "CLEAR")
    outs = {f["id"]: f["outcome"] for f in (ep or {}).get("findings", [])}
    check("adjudication_stale_cited_clearance_ignored",
          ep is not None and set(outs.values()) == {"cleared-unedited"}
          # the NEW header format (trailing caller field) must parse cleanly:
          # no file name carries the leaked caller text, and the episode
          # carries the denial's caller (gate catch gate_20260923-182445 net)
          and all(" " not in f and "|" not in f and "caller" not in f
                  for fl in (ep or {}).get("findings", [])
                  for f in fl.get("files", []))
          and ep.get("caller") == "fixture-agent",
          "outs=%s caller=%s" % (outs, (ep or {}).get("caller")))

    # Workload routing + Jev typed-decision refinement (owner order 2026-09-23,
    # typesafe/jev-1.13): the deterministic floor promotes the deepseek-v4-pro-0813
    # rung to PRIMARY for cache-heavy workloads (payload >= threshold - those pins
    # are the proven cache-readers - or a rebuttal round, where the stable-first
    # prefix repeats). Jev sees METRICS ONLY (counts, never staged bytes) and may
    # only ADD promotions in the gray zone; it can never demote the rule, forge a
    # verdict, or touch secrets/push barriers. Every failure is fail-open.
    _RC = _g.DEFAULT_CHAIN
    _saved_env = {k: os.environ.get(k) for k in
                  ("OPENROUTER_API_KEY", "ADVERSARY_JEV_OFF", "ADVERSARY_JEV_FAKE",
                   "ADVERSARY_PROMOTE_OFF", "ADVERSARY_PROMOTE_MIN_CHARS")}
    try:
        for _k in _saved_env:
            os.environ.pop(_k, None)
        # Without opt-in, every workload preserves the owner's primary/secondary.
        for _payload, _context in (("small", ""), ("x" * 900000, ""), ("small", "REBUT")):
            _fixed = _g._route_chain(_RC, _payload, _context)
            check("route_fixed_default_" + str(len(_payload)) + "_" + str(bool(_context)),
                  _fixed == (_RC, "off"), str(_fixed)[:200])
        # Preserve coverage of the explicitly enabled legacy router.
        os.environ["ADVERSARY_PROMOTE_OFF"] = "0"
        try:
            _ro = _g._route_chain(_RC, "x" * (_g.PROMOTE_MIN_CHARS + 1), "")
            _ok_ro = (_ro[1] == "rule"
                      and _ro[0].split(",")[0].startswith("deepseek/deepseek-v4-pro-0813@")
                      and len(_ro[0].split(",")) == len(_RC.split(",")))
        except Exception as _e:                                 # noqa: BLE001
            _ok_ro, _ro = False, repr(_e)
        check("route_promotes_deepseek_on_large_payload", _ok_ro, str(_ro)[:200])

        try:
            _rb = _g._route_chain(_RC, "small", "REBUT: the finding misread the bytes")
            _ok_rb = (_rb[1] == "rule" and _rb[0].split(",")[0].startswith("deepseek/"))
        except Exception as _e:                                 # noqa: BLE001
            _ok_rb, _rb = False, repr(_e)
        check("route_promotes_deepseek_on_rebuttal_round", _ok_rb, str(_rb)[:200])

        try:
            _rd = _g._route_chain(_RC, "small", "")
            _ok_rd = (_rd == (_RC, "default"))
        except Exception as _e:                                 # noqa: BLE001
            _ok_rd, _rd = False, repr(_e)
        check("route_default_below_threshold_first_round", _ok_rd, str(_rd)[:200])

        try:
            _lst0 = _RC.split(",")
            _rp = _g._route_chain(_RC, "x" * (_g.PROMOTE_MIN_CHARS + 1), "")
            _lst1 = _rp[0].split(",")
            _ok_rp = (sorted(_lst0) == sorted(_lst1) and _lst1[0] == _lst0[2]
                      and _g._route_chain(_rp[0], "y" * (_g.PROMOTE_MIN_CHARS + 2), "")[0]
                      == _rp[0])
        except Exception as _e:                                 # noqa: BLE001
            _ok_rp, _rp = False, repr(_e)
        check("route_preserves_order_no_dupes_idempotent", _ok_rp, str(_rp)[:200])

        _rm = _g._route_chain("z-ai/glm-5.3-flash@parasail/fp8", "x" * 900000, "R")
        check("route_manual_model_override_bypasses",
              _rm == ("z-ai/glm-5.3-flash@parasail/fp8", "manual"), str(_rm)[:200])
        os.environ["ADVERSARY_PROMOTE_OFF"] = "1"
        _rk = _g._route_chain(_RC, "x" * (_g.PROMOTE_MIN_CHARS + 1), "R")
        check("route_killswitch_returns_verbatim", _rk == (_RC, "off"), str(_rk)[:200])
        os.environ["ADVERSARY_PROMOTE_OFF"] = "0"
        _no_ds = "openai/gpt-6-luna-pro,z-ai/glm-5.3-flash@parasail/fp8"
        _prev_dc = _g.DEFAULT_CHAIN
        try:
            _g.DEFAULT_CHAIN = _no_ds        # the absent-target branch is reachable
            _ra = _g._route_chain(_no_ds, "x" * (_g.PROMOTE_MIN_CHARS + 1), "R")
        finally:                              # only with the DEFAULT itself patched
            _g.DEFAULT_CHAIN = _prev_dc
        check("route_absent_target_unchanged", _ra == (_no_ds, "default"), str(_ra)[:200])

        # Jev consult rides the OpenRouter DECISIONS API (/api/alpha/decisions, the
        # gate's OWN OPENROUTER_API_KEY - wire contract LIVE-verified 2026-09-23:
        # unwrapped {model, state, questions} body, criteria-shaped questions,
        # answers.<qid> = {type, choice, probabilities, confidence}). Absent key
        # -> None fast; SELFTEST serves only ADVERSARY_JEV_FAKE shaped like a REAL
        # answer; garbage fails open; the gray zone can promote; the rule is never
        # demoted; ADVERSARY_JEV_OFF skips entirely.
        check("jev_failopen_without_key", _g._jev_decide(1234, False, 5) is None,
              "expected None with no key and no fake")
        os.environ["ADVERSARY_JEV_FAKE"] = ('{"promote_deepseek": {"type": "choice", '
                                            '"choice": "deepseek_first", '
                                            '"probabilities": {"default_order": 0.07, '
                                            '"deepseek_first": 0.93}, "confidence": 0.93}}')
        _jf = _g._jev_decide(1234, False, 5)
        check("jev_fake_answers_honored_under_selftest",
              isinstance(_jf, dict) and _jf.get("choice") == "deepseek_first"
              and abs(_jf.get("probabilities", {}).get("deepseek_first", 0) - 0.93) < 1e-9,
              str(_jf))
        os.environ["ADVERSARY_JEV_FAKE"] = "not-json{{"
        check("jev_malformed_answers_failopen", _g._jev_decide(1234, False, 5) is None,
              "expected None on garbage")
        check("jev_transport_targets_openrouter_decisions",
              _g.JEV_API_URL == "https://openrouter.ai/api/alpha/decisions"
              and _g.JEV_MODEL == "typesafe/jev-1.13",
              "%s / %s" % (_g.JEV_API_URL, _g.JEV_MODEL))
        try:
            _jb = _g._jev_request_body("STATE")
            _ok_jb = (_jb.get("model") == "typesafe/jev-1.13"
                      and _jb.get("state") == "STATE"
                      and set(_jb.get("questions", {})) == {"promote_deepseek"}
                      and set(_jb["questions"]["promote_deepseek"]["criteria"])
                      == {"default_order", "deepseek_first"}
                      and "decisionsRequest" not in _jb)
        except Exception as _e:                                 # noqa: BLE001
            _ok_jb, _jb = False, repr(_e)
        check("jev_request_shape_matches_live_contract", _ok_jb, str(_jb)[:300])
        # the parse fixture is the EXACT shape the live 2026-09-23 probe returned
        # (only the id is shortened); an out-of-vocabulary choice fails open
        _live = {"model": "typesafe/jev-1.13-20260917",
                 "answers": {"promote_deepseek": {"type": "choice",
                                                  "choice": "default_order",
                                                  "probabilities": {"default_order": 0.97,
                                                                    "deepseek_first": 0.03},
                                                  "confidence": 0.95}},
                 "id": "gen-dec-probe", "provider": "TypeSafe"}
        _jp = _g._jev_parse_answer(_live)
        check("jev_answer_parse_live_shape",
              _jp == {"choice": "default_order",
                      "probabilities": {"default_order": 0.97, "deepseek_first": 0.03},
                      "confidence": 0.95}
              and _g._jev_parse_answer({"answers": {"promote_deepseek":
                                                    {"type": "choice",
                                                     "choice": "weird"}}}) is None,
              str(_jp))
        os.environ["ADVERSARY_JEV_FAKE"] = ('{"promote_deepseek": {"type": "choice", '
                                            '"choice": "deepseek_first", '
                                            '"probabilities": {"deepseek_first": 0.9}, '
                                            '"confidence": 0.9}}')
        _jg = _g._route_chain(_RC, "small", "")
        _ok_jg = (_jg[1] == "jev" and _jg[0].split(",")[0].startswith("deepseek/"))
        check("jev_promotes_only_in_gray_zone", _ok_jg, str(_jg)[:200])
        os.environ["ADVERSARY_JEV_FAKE"] = ('{"promote_deepseek": {"type": "choice", '
                                            '"choice": "default_order", '
                                            '"probabilities": {"default_order": 0.99}, '
                                            '"confidence": 0.99}}')
        _jn = _g._route_chain(_RC, "x" * (_g.PROMOTE_MIN_CHARS + 1), "")
        check("jev_never_demotes_deterministic_rule",
              _jn[1] == "rule" and _jn[0].split(",")[0].startswith("deepseek/"),
              str(_jn)[:200])
        os.environ["ADVERSARY_JEV_OFF"] = "1"
        _jo = _g._route_chain(_RC, "small", "")
        check("jev_killswitch_skips_consult", _jo == (_RC, "default"), str(_jo)[:200])
        os.environ.pop("ADVERSARY_JEV_OFF", None)
        os.environ.pop("ADVERSARY_JEV_FAKE", None)
        # a selftest with a REAL key set must still never touch the network
        os.environ["OPENROUTER_API_KEY"] = "sk-selftest-never-real"
        check("jev_selftest_hermetic_even_with_key", _g._jev_decide(1234, False, 5) is None,
              "SELFTEST=1 with a key and no fake must consult nothing")
    finally:
        for _k, _v in _saved_env.items():
            if _v is None:
                os.environ.pop(_k, None)
            else:
                os.environ[_k] = _v

    # e2e: a large staged payload routes the chain deepseek-first AND still
    # clears through the fake reviewer; a small one leaves the default order
    # (no routing line at all)
    tmpR = tempfile.mkdtemp(prefix="advgate_")
    subprocess.run([GIT, "init", "-q", tmpR], capture_output=True)
    git(tmpR, "config", "user.email", "t@t")
    git(tmpR, "config", "user.name", "t")
    with open(os.path.join(tmpR, "big.py"), "w", encoding="utf-8") as fh:
        fh.write("X = \"" + "a" * 300 + "\"\n" * 40)
    git(tmpR, "add", "big.py")
    _e1 = gate(tmpR, "run", env_extra={"ADVERSARY_FAKE": "CLEAR",
                                       "ADVERSARY_PROMOTE_OFF": "0",
                                       "ADVERSARY_PROMOTE_MIN_CHARS": "100",
                                       "ADVERSARY_JEV_OFF": "1"})
    check("route_e2e_large_run_emits_routing_line",
          _e1.returncode == 0 and "workload routing" in _e1.stdout
          and "deepseek/deepseek-v4-pro-0813" in _e1.stdout,
          "rc=%s out=%s err=%s" % (_e1.returncode, _e1.stdout[:200], _e1.stderr[-200:]))
    _e2 = gate(tmpR, "run", env_extra={"ADVERSARY_FAKE": "CLEAR",
                                       "ADVERSARY_PROMOTE_OFF": "0",
                                       "ADVERSARY_PROMOTE_MIN_CHARS": "999999999",
                                       "ADVERSARY_JEV_OFF": "1"})
    check("route_e2e_small_run_no_routing_line",
          _e2.returncode == 0 and "workload routing" not in _e2.stdout,
          "rc=%s out=%s" % (_e2.returncode, _e2.stdout[:200]))

    # Calling-agent attribution (owner order 2026-09-23: "record if we are not the
    # calling agent for every scan ... error rate of each agent as well"): every
    # review artifact carries caller: <id> - explicit ADVERSARY_CALLER env wins,
    # then harness sniffing (CLAUDECODE=1 / ZCODE_APP_VERSION / CODEX_HOME),
    # else unknown. Old artifacts simply lack the field.
    _saved_caller_env = {k: os.environ.get(k) for k in
                         ("ADVERSARY_CALLER", "CLAUDECODE", "ZCODE_APP_VERSION", "CODEX_HOME")}
    try:
        for _k in _saved_caller_env:
            os.environ.pop(_k, None)
        os.environ["ADVERSARY_CALLER"] = "test-agent"

        def _latest_artifact(repo):
            rvw = os.path.join(repo, ".adversary", "reviews")
            cands = [f for f in os.listdir(rvw) if _g._GNAME_RE.fullmatch(f)]
            def order(name):
                match = _g._GNAME_RE.fullmatch(name)
                return match.group(1), int(match.group(2) or 0)
            return open(os.path.join(rvw, max(cands, key=order)), encoding="utf-8",
                        errors="replace").read()[:400]

        tmpC = tempfile.mkdtemp(prefix="advgate_")
        subprocess.run([GIT, "init", "-q", tmpC], capture_output=True)
        git(tmpC, "config", "user.email", "t@t")
        git(tmpC, "config", "user.name", "t")
        with open(os.path.join(tmpC, "a.py"), "w", encoding="utf-8") as fh:
            fh.write("x = 1\n")
        git(tmpC, "add", "a.py")
        with tempfile.TemporaryDirectory(prefix="adv-latest-") as _lroot:
            _lrvw = os.path.join(_lroot, ".adversary", "reviews")
            os.makedirs(_lrvw)
            for _lname, _ltext in (("gate_20260927-120000.md", "first"),
                                    ("gate_20260927-120000-2.md", "second"),
                                    ("gate_20260927-120000-10.md", "tenth")):
                with open(os.path.join(_lrvw, _lname), "w", encoding="utf-8") as _lfh:
                    _lfh.write(_ltext)
            check("latest_artifact_uses_numeric_suffix", _latest_artifact(_lroot) == "tenth")

        _c1 = gate(tmpC, "run", env_extra={"ADVERSARY_FAKE": "CLEAR",
                                           "ADVERSARY_CALLER": "test-agent"})
        _h1 = _latest_artifact(tmpC)
        check("caller-recorded-in-artifact-header",
              _c1.returncode == 0 and "caller: test-agent" in _h1, _h1[:200])
        os.environ.pop("ADVERSARY_CALLER", None)
        _c2 = gate(tmpC, "run", env_extra={"ADVERSARY_FAKE": "CLEAR"})
        _h2 = _latest_artifact(tmpC)
        check("caller-unknown-fallback",
              _c2.returncode == 0 and "caller: unknown" in _h2, _h2[:200])
        _c3 = gate(tmpC, "run", env_extra={"ADVERSARY_FAKE": "CLEAR",
                                           "ZCODE_APP_VERSION": "9.9"})
        _h3 = _latest_artifact(tmpC)
        check("caller-env-sniff-zcode",
              _c3.returncode == 0 and "caller: zcode" in _h3, _h3[:200])
        # Exercise production header parsing and finding attribution, not a regex copy.
        try:
            with tempfile.TemporaryDirectory(prefix="adv-bracket-") as _br:
                os.environ["ADVERSARY_CALLER"] = "fixture agent"
                _bt = (_g._review_header("m", {}, "p", 0, ["we]ird.py"])
                       + "1. HIGH we]ird.py:7 - a finding citing the bracket name.\n"
                       + "VERDICT: BLOCK\n")
                _g._write_review_round(_br, "20260921-100000", _bt,
                                       {"we]ird.py": "old"}, False)
                _clear_br = _g._write_review_round(
                    _br, "20260921-100500", _bt.replace("VERDICT: BLOCK", "VERDICT: CLEAR"),
                    {"we]ird.py": "new"}, False)
                _ep_br = _g._adjudicate_cycle(
                    _br, "bracket-commit", {"we]ird.py": "new"},
                    {"we]ird.py": {"sha": "new", "verdict": "CLEAR",
                                    "artifact": os.path.relpath(_clear_br, _br)}}, "CLEAR")
                _bfiles = (_ep_br or {}).get("findings", [])
                _ok_b = (bool(_bfiles) and _bfiles[0].get("files") == ["we]ird.py"]
                         and _bfiles[0].get("outcome") == "fixed"
                         and _ep_br.get("caller") == "fixture%20agent")
        except Exception as _e:
            _ok_b, _bfiles = False, repr(_e)
        check("caller-header-bracket-name-survives", _ok_b, str(_bfiles))
    finally:
        for _k, _v in _saved_caller_env.items():
            if _v is None:
                os.environ.pop(_k, None)
            else:
                os.environ[_k] = _v

    bad = {k: v for k, v in results.items() if not v[0]}
    print("\n%d/%d PASS" % (len(results) - len(bad), len(results)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
