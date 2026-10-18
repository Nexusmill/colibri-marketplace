r"""tests/test_zcode_twin.py - the colibri-marketplace repo's ZCode twin must keep its contracts.

Repo-by-repo port of the colibri-code-review twin test (itself via the Tools twin test /
Nexusmill arming twin; owner order 2026-10-18). Covers the five mounts wired in .zcode/config.json:
  zcode/zcode_grounding.ps1    SessionStart grounding (pure-ASCII strict JSON)
  zcode/zcode_jcm_guard.ps1    PreToolUse G6 guard (colibri-marketplace-scoped)
  zcode/zcode_jcm_mark.ps1     PostToolUse marker (releases the guard)
  zcode/zcode_repo_guards.ps1  PreToolUse G42 fail-arm + G43 cross-repo ledger
  zcode/zcode_stop_gate.mjs    Stop gate (exit 2 while edits outrun verification)
plus zcode/session_health.py (assess/ingest) and the config wiring.

Every test runs the REAL script under the REAL interpreter the hook config invokes
(powershell.exe / node / python). Guard tests run with a per-test session id, and the G6
guard's non-session-keyed one-shot OVERRIDE is STASHED ASIDE for the duration of each
test and restored after, so the suite can never consume the owner's live escape or flip
on an ambient escape (ZSKILL_GATE_OFF is stripped from the child env; the stop gate is
sandboxed via ZSKILL_GATE_STATE_DIR).
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
Z = REPO / "zcode"
GROUNDING = Z / "zcode_grounding.ps1"
GUARD = Z / "zcode_jcm_guard.ps1"
MARK = Z / "zcode_jcm_mark.ps1"
REPO_GUARDS = Z / "zcode_repo_guards.ps1"
STOP = Z / "zcode_stop_gate.mjs"
HEALTH = Z / "session_health.py"
CONFIG = REPO / ".zcode" / "config.json"
PS = "powershell.exe"
NEXUS = Path("C:/Users/User/source/repos/Nexusmill")
LOG_EXTERNAL = NEXUS / "tools" / "repo_health" / "log_external.py"


def _run(cmd, stdin_text="", sid=None, env_extra=None, cwd=None, timeout=90):
    env = dict(os.environ)
    env.pop("ZSKILL_GATE_OFF", None)
    if sid is not None:
        cmd = cmd + ["-SessionId", sid]
    if env_extra:
        env.update(env_extra)
    return subprocess.run(cmd, input=stdin_text.encode("utf-8"), capture_output=True,
                          env=env, timeout=timeout, cwd=str(cwd or REPO))


def _ps(script, stdin_text="", sid=None, env_extra=None, cwd=None):
    return _run([PS, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script)],
                stdin_text, sid, env_extra, cwd)


def _node(script, env_extra=None, cwd=None):
    return _run(["node", str(script)], "", None, env_extra, cwd)


def _payload(tool, **tool_input):
    return json.dumps({"tool_name": tool, "tool_input": tool_input})


def _deny_json(stdout):
    text = stdout.decode("utf-8", "replace").strip()
    if not text:
        return None
    try:
        data = json.loads(text)
    except ValueError:
        return None
    hso = data.get("hookSpecificOutput", {})
    if hso.get("permissionDecision") != "deny":
        return None
    return hso.get("permissionDecisionReason", "")


@unittest.skipUnless(sys.platform == "win32", "hooks are Windows scripts")
class GroundingTests(unittest.TestCase):
    def _assert_contract(self, raw):
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError as e:
            self.fail("grounding stdout is not pure ASCII: %s" % e)
        body = text.rstrip("\r\n")
        bad = sorted({hex(ord(c)) for c in body if ord(c) < 0x20})
        self.assertFalse(bad, "raw control characters in JSON payload: %s" % bad)
        data = json.loads(body, strict=True)
        hso = data["hookSpecificOutput"]
        self.assertEqual(hso["hookEventName"], "SessionStart")
        ctx = hso["additionalContext"]
        self.assertTrue(ctx.startswith("COLIBRI-MARKETPLACE SESSION GROUNDING"), ctx[:80])
        self.assertLessEqual(len(ctx), 10000)
        return ctx

    def test_emits_strict_ascii_json_with_contract_blocks(self):
        r = _ps(GROUNDING, "")
        self.assertEqual(r.returncode, 0, r.stderr[:500])
        ctx = self._assert_contract(r.stdout)
        self.assertIn("GLOBAL_MEMORY", ctx)                     # G-MEM pointer rides the directive
        self.assertIn("colibri_marketplace-memory", ctx)        # the store pointer (G40)
        self.assertIn("MARKETPLACE REPO HEALTH", ctx)           # marketplace-owned health verdict
        self.assertIn("FORCED INGESTION (G44)", ctx)
        self.assertIn("AGENTS.md", ctx)                         # snapshot source named

    def test_health_precedes_snapshot(self):
        r = _ps(GROUNDING, "")
        self.assertEqual(r.returncode, 0, r.stderr[:500])
        ctx = self._assert_contract(r.stdout)
        self.assertLess(ctx.find("MARKETPLACE REPO HEALTH"), ctx.find("snapshot from AGENTS.md"))
        self.assertLess(ctx.find("FORCED INGESTION (G44)"), ctx.find("snapshot from AGENTS.md"))

    def test_missing_state_file_still_grounded(self):
        missing = os.path.join(tempfile.gettempdir(), "twin-no-such-state.md")
        if os.path.exists(missing):
            os.remove(missing)
        r = _ps(GROUNDING, "", env_extra={"MARKETPLACE_AGENT_STATE": missing})
        self.assertEqual(r.returncode, 0, r.stderr[:500])
        ctx = self._assert_contract(r.stdout)
        self.assertIn("not found", ctx)  # explicit note, payload intact

    def test_huge_state_file_keeps_snapshot_within_budget(self):
        # the display caps can never push the snapshot out of the payload - a 20KB state
        # override still yields a bounded payload whose snapshot header AND truncation
        # marker survive (never silently dropped).
        big = os.path.join(tempfile.gettempdir(), "twin-huge-state.md")
        with open(big, "w", encoding="utf-8") as f:
            f.write("S" * 20000)
        try:
            r = _ps(GROUNDING, "", env_extra={"MARKETPLACE_AGENT_STATE": big})
            self.assertEqual(r.returncode, 0, r.stderr[:500])
            ctx = self._assert_contract(r.stdout)
            self.assertIn("snapshot from AGENTS.md", ctx)
            self.assertIn("snapshot truncated", ctx)
        finally:
            os.remove(big)


@unittest.skipUnless(sys.platform == "win32", "hooks are Windows scripts")
class JcmGuardTests(unittest.TestCase):
    SID = "twin-mguard-1"
    OVERRIDE = os.path.join(tempfile.gettempdir(), "zskill-gate", "OVERRIDE")

    def _guard(self, payload, env_extra=None):
        return _ps(GUARD, payload, sid=self.SID, env_extra=env_extra)

    def _stash_live_escape(self, override_path):
        # the G6 guard's one-shot OVERRIDE is NOT session-keyed (unlike the stop gate's
        # state dir). Stash/restore lives in HELPERS so the cycle test can exercise them
        # against a TEMP CLONE - the suite never writes the real OVERRIDE path outside
        # setUp/tearDown's single well-defined stash.
        stash = override_path + ".twin-test-stash"
        if os.path.exists(override_path):
            os.replace(override_path, stash)
        return stash

    def _restore_escape(self, override_path, stash):
        if stash and os.path.exists(stash):
            os.replace(stash, override_path)

    def setUp(self):
        marker = os.path.join(tempfile.gettempdir(), "jcmz_used_%s.flag" % self.SID)
        if os.path.exists(marker):
            os.remove(marker)
        # stash a live escape aside and restore it after every test, so the suite can
        # never consume it or flip a deny into an allow
        self._my_stash = self._stash_live_escape(self.OVERRIDE)

    def tearDown(self):
        self._restore_escape(self.OVERRIDE, getattr(self, "_my_stash", None))

    def test_denies_source_read_before_jcm_use(self):
        r = self._guard(_payload("Read", file_path=str(Z / "zcode_jcm_guard.ps1")))
        reason = _deny_json(r.stdout)
        self.assertIsNotNone(reason)
        self.assertIn("G6", reason)

    def test_allows_doc_read(self):
        r = self._guard(_payload("Read", file_path=str(REPO / "README.md")))
        self.assertIsNone(_deny_json(r.stdout))

    def test_denies_bash_search_until_released(self):
        r = self._guard(_payload("Bash", command="rg foo zcode/"))
        self.assertIsNotNone(_deny_json(r.stdout))
        # release: the mark hook records a jcodemunch call for this session
        r = _ps(MARK, json.dumps({"tool_name": "mcp__plugin_jcodemunch_jcodemunch__search_symbols"}), sid=self.SID)
        self.assertEqual(r.returncode, 0)
        r = self._guard(_payload("Bash", command="rg foo zcode/"))
        self.assertIsNone(_deny_json(r.stdout))

    def test_outside_repo_source_read_allowed(self):
        r = self._guard(_payload("Read", file_path="C:/Users/User/source/repos/Blink/tools/x.py"))
        self.assertIsNone(_deny_json(r.stdout))

    def test_sibling_colibri_repo_source_read_allowed(self):
        # PORT NOTE: 'colibri' alone is ambiguous (colibri-code-review / bare colibri dir) -
        # those siblings are OUTSIDE this repo and must never be caught by the in-repo scope.
        r = self._guard(_payload("Read", file_path="C:/Users/User/source/repos/colibri-code-review/analyzer.py"))
        self.assertIsNone(_deny_json(r.stdout))

    def test_fail_open_on_garbage(self):
        r = self._guard("not json at all")
        self.assertEqual(r.returncode, 0)
        self.assertFalse(r.stdout.strip())

    def test_live_override_stash_restore_cycle(self):
        # the cycle must never WRITE the real OVERRIDE path. The real machinery (the same
        # helpers setUp/tearDown call) runs against a TEMP CLONE; the deny below is
        # deterministic because the class setUp already stashed any live real escape, and
        # the round-trip assertion reads the clone.
        with tempfile.TemporaryDirectory() as td:
            fake = os.path.join(td, "OVERRIDE")
            Path(fake).write_text("owner", encoding="utf-8")
            stash = self._stash_live_escape(fake)
            self.assertFalse(os.path.exists(fake))
            r = self._guard(_payload("Read", file_path=str(Z / "zcode_jcm_guard.ps1")))
            self.assertIsNotNone(_deny_json(r.stdout))  # deterministic: real OVERRIDE is stashed
            self._restore_escape(fake, stash)
            self.assertEqual(Path(fake).read_text(encoding="utf-8"), "owner")
            self.assertFalse(os.path.exists(stash))

    def test_override_directory_does_not_release(self):
        # gate round 2 finding 1 (the stop gate's M2 class): an OVERRIDE that is a
        # DIRECTORY must NOT fail the guard open - the would-be-denied Read still denies
        # and the directory survives (nothing was burned). TEMP is redirected to a
        # per-test sandbox (r4 LOW): a LIVE production guard - another session's G6 deny
        # or the stop gate - reads the same machine-global path and could otherwise
        # consume what this test plants (the concurrent-consume variant of EV-230).
        sb = tempfile.mkdtemp(prefix="twin-ovd-")
        self.addCleanup(shutil.rmtree, sb, True)
        env = {"TEMP": sb, "TMP": sb}
        ovd = os.path.join(sb, "zskill-gate", "OVERRIDE")
        os.makedirs(ovd, exist_ok=True)
        r = self._guard(_payload("Read", file_path=str(Z / "zcode_jcm_guard.ps1")), env_extra=env)
        self.assertIsNotNone(_deny_json(r.stdout))
        self.assertTrue(os.path.isdir(ovd))

    def test_override_regular_file_burns_and_releases(self):
        # positive control for the same block: a REGULAR deletable OVERRIDE burns exactly
        # once and releases the guard. Same per-test TEMP sandbox as the directory test
        # (r4 LOW) + unconditional cleanup so nothing can strand (EV-230).
        sb = tempfile.mkdtemp(prefix="twin-ovf-")
        self.addCleanup(shutil.rmtree, sb, True)
        env = {"TEMP": sb, "TMP": sb}
        ovd = os.path.join(sb, "zskill-gate", "OVERRIDE")
        os.makedirs(os.path.dirname(ovd), exist_ok=True)
        Path(ovd).write_text("owner", encoding="utf-8")
        try:
            r = self._guard(_payload("Read", file_path=str(Z / "zcode_jcm_guard.ps1")), env_extra=env)
            self.assertIsNone(_deny_json(r.stdout))
            self.assertFalse(os.path.exists(ovd))
        finally:
            if os.path.exists(ovd):
                os.remove(ovd)


@unittest.skipUnless(sys.platform == "win32", "hooks are Windows scripts")
class SessionHealthTests(unittest.TestCase):
    def test_assess_pass_on_real_repo(self):
        with tempfile.TemporaryDirectory() as td:
            state = os.path.join(td, "colibri_marketplace_ledger.json")
            r = _run([sys.executable, "-B", str(HEALTH), "assess"],
                     env_extra={"MARKETPLACE_HEALTH_STATE": state})
            self.assertEqual(r.returncode, 0, r.stderr[:400])
            out = r.stdout.decode("utf-8", "replace")
            self.assertIn("MARKETPLACE REPO HEALTH: PASS", out)
            data = json.loads(Path(state).read_text(encoding="utf-8"))
            self.assertFalse(data["current_fail"])
            self.assertEqual(data["repo"], str(REPO))

    def test_assess_fail_on_broken_root(self):
        with tempfile.TemporaryDirectory() as td:
            state = os.path.join(td, "colibri_marketplace_ledger.json")
            r = _run([sys.executable, "-B", str(HEALTH), "assess"],
                     env_extra={"MARKETPLACE_HEALTH_STATE": state, "MARKETPLACE_HEALTH_REPO": td})
            self.assertEqual(r.returncode, 1)
            out = r.stdout.decode("utf-8", "replace")
            self.assertIn("MARKETPLACE REPO HEALTH: FAIL", out)
            data = json.loads(Path(state).read_text(encoding="utf-8"))
            self.assertTrue(data["current_fail"])
            self.assertTrue(data["failings"])

    def test_ingest_prints_g44_block(self):
        r = _run([sys.executable, "-B", str(HEALTH), "ingest"], timeout=90)
        self.assertEqual(r.returncode, 0, r.stderr[:400])
        out = r.stdout.decode("utf-8")   # the child emits UTF-8 (reconfigure) - strict decode pins it
        # success-SHAPED markers only: the failure note shares the bare prefix, so asserting
        # the prefix alone stays green while ingestion is permanently broken
        self.assertTrue(("HIGH summaries, required context" in out) or
                        ("no HIGH-rated summaries" in out), out[:200])

    def test_ingest_decodes_utf8_grandchild_strict_bytes(self):
        # EV-230 (caught on the colibri twin port): the repo-memory server's stdout is
        # UTF-8, but the subprocess was read with the LOCALE codec - cp1252-strict on
        # Windows hosts WITHOUT the UTF-8 system locale (THIS machine measures utf-8 via
        # getpreferredencoding, so the loss is latent here and the revert is only RED on
        # cp1252 hosts - this test pins the contract locally, it cannot express the red)
        # - 0x8D-class continuation bytes (U+200D et al) then raise UnicodeDecodeError,
        # which the fail-open handler swallows it, and G44 ingestion is silently lost every
        # session start. A stub server pins the explicit UTF-8 decode.
        import importlib.util
        import io as _io
        from contextlib import redirect_stdout
        from unittest import mock
        stub_dir = tempfile.mkdtemp(prefix="twin-rm-stub-")
        pkg = os.path.join(stub_dir, "repo_memory")
        os.makedirs(pkg)
        with open(os.path.join(pkg, "__init__.py"), "w", encoding="utf-8"):
            pass
        with open(os.path.join(pkg, "server.py"), "w", encoding="utf-8") as f:
            f.write(
                "import sys\n"
                "sys.stdout.buffer.write(('\\u200d ok\\n"
                '{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"### [HIGH] t\\u200d decision"}]}}\\n'
                "').encode('utf-8'))\n")
        try:
            spec = importlib.util.spec_from_file_location("twin_session_health", str(HEALTH))
            sh = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(sh)
            buf = _io.StringIO()
            with mock.patch.object(sh, "RM_ROOT", Path(stub_dir)), \
                 mock.patch.object(sh, "RM_PY", Path(sys.executable)), \
                 redirect_stdout(buf):
                rc = sh.ingest()
            self.assertEqual(rc, 0)
            self.assertIn("HIGH summaries, required context", buf.getvalue())
        finally:
            shutil.rmtree(stub_dir, ignore_errors=True)


@unittest.skipUnless(sys.platform == "win32", "hooks are Windows scripts")
class RepoGuardsTests(unittest.TestCase):
    SID = "twin-mguards-1"

    def setUp(self):
        self.sd = tempfile.mkdtemp(prefix="zsg-twin-")
        self._wipe_flags()

    def tearDown(self):
        shutil.rmtree(self.sd, ignore_errors=True)
        self._wipe_flags()

    def _wipe_flags(self):
        d = os.path.join(tempfile.gettempdir(), "zskill-gate")
        if os.path.isdir(d):
            for n in os.listdir(d):
                if n.startswith("repo_mem_pending_%s" % self.SID):
                    try:
                        os.remove(os.path.join(d, n))
                    except OSError:
                        pass

    def _guards(self, payload, env_extra=None):
        env = {"MARKETPLACE_HEALTH_STATE": os.path.join(self.sd, "no-ledger.json")}
        if env_extra:
            env.update(env_extra)
        return _ps(REPO_GUARDS, payload, sid=self.SID, env_extra=env)

    def test_g43_denies_unlogged_outside_git(self):
        r = self._guards(_payload("Bash", command="git -C C:/Users/User/source/repos/Blink add x.py"))
        reason = _deny_json(r.stdout)
        self.assertIsNotNone(reason)
        self.assertIn("G43", reason)

    def test_g43_allows_declared_log_external(self):
        cmd = ('python %s --repo-path C:/Users/User/source/repos/Blink --topic t --decision d --rationale r ; '
               'git -C C:/Users/User/source/repos/Blink add x.py') % LOG_EXTERNAL
        r = self._guards(_payload("Bash", command=cmd))
        self.assertIsNone(_deny_json(r.stdout))

    def test_g43_one_shot_unlock_for_write(self):
        target = "C:/Users/User/source/repos/Blink/x.py"
        r = self._guards(_payload("Write", file_path=target, content="x"))
        reason = _deny_json(r.stdout)
        self.assertIsNotNone(reason)
        self.assertIn("G43", reason)
        r2 = self._guards(_payload("Write", file_path=target, content="x"))
        self.assertIsNone(_deny_json(r2.stdout))  # flag consumed by the retry

    def test_g43_hash_collision_does_not_unlock(self):
        # gate round 2 finding 2: the unlock flag is bound by its stored CONTENT, not the
        # 15-bit path hash alone - a DIFFERENT path colliding on the hash must be denied
        # its own one-shot dance, never ride another target's unlock.
        def ph(s):
            # hash the GUARD-NORMALIZED form (GetFullPath: backslashes, case preserved) -
            # the flag filename is derived from $paths AFTER normalization
            s = s.replace('/', '\\')
            h = 0
            for ch in s:
                h = ((h * 31) + ord(ch)) % 32003
            return h
        a = "C:/Users/User/source/repos/Blink/a.py"
        target_ph = ph(a)
        b = None
        for i in range(100000):
            cand = "C:/Users/User/source/repos/Blink/b%d.py" % i
            if ph(cand) == target_ph:
                b = cand
                break
        self.assertIsNotNone(b, "no hash collision found in 100k candidates")
        r = self._guards(_payload("Write", file_path=a, content="x"))    # plants A's flag
        self.assertIsNotNone(_deny_json(r.stdout))
        r2 = self._guards(_payload("Write", file_path=b, content="x"))   # same hash, different path
        reason = _deny_json(r2.stdout)
        self.assertIsNotNone(reason, "collision path rode another target's unlock")
        self.assertIn("G43", reason)

    def test_in_repo_write_allowed(self):
        r = self._guards(_payload("Write", file_path=str(REPO / "junk" / "x.txt"), content="x"))
        self.assertIsNone(_deny_json(r.stdout))

    def test_g42_fail_arm_shapes(self):
        led = os.path.join(self.sd, "colibri_marketplace_ledger.json")
        Path(led).write_text(json.dumps({"current_fail": True, "failings": ["test"]}), encoding="utf-8")
        g42 = {"MARKETPLACE_HEALTH_STATE": led}
        r = self._guards(_payload("Bash", command="python -c \"print(1)\""), env_extra=g42)
        self.assertIsNotNone(_deny_json(r.stdout))  # mutating, not remediation-shaped
        r = self._guards(_payload("Write", file_path=str(REPO / "junk" / "y.txt"), content="y"), env_extra=g42)
        self.assertIsNone(_deny_json(r.stdout))     # in-repo Write IS remediation-shaped (reference semantics)
        r = self._guards(_payload("Bash", command="git commit -m \"fix: x\""), env_extra=g42)
        self.assertIsNone(_deny_json(r.stdout))     # sanctioned commit shape
        r = self._guards(_payload("Bash", command="python zcode/session_health.py assess"), env_extra=g42)
        self.assertIsNone(_deny_json(r.stdout))     # the deny message's own recovery command
        r = self._guards(_payload("Bash", command="python C:/evil/zcode/session_health.py assess"), env_extra=g42)
        self.assertIsNotNone(_deny_json(r.stdout))  # planted copy outside the repo stays denied
        # every fail-trigger has an in-band remediation shape. The guard only DECIDES here -
        # nothing executes, so these rows are decision-level.
        r = self._guards(_payload("Bash", command="mkdir E:\\repo-memory\\colibri_marketplace"), env_extra=g42)
        self.assertIsNone(_deny_json(r.stdout))     # store-missing is remediable (scoped to the store root)
        r = self._guards(_payload("Bash", command="mkdir C:\\evil"), env_extra=g42)
        self.assertIsNotNone(_deny_json(r.stdout))  # mkdir anywhere else stays denied
        r = self._guards(_payload("Bash", command="mkdir E:\\repo-memory\\..\\..\\other"), env_extra=g42)
        self.assertIsNotNone(_deny_json(r.stdout))  # traversal suffix stays denied
        r = self._guards(_payload("Bash", command="mkdir E:\\repo-memory\\colibri_marketplace && python zcode/session_health.py assess"), env_extra=g42)
        self.assertIsNone(_deny_json(r.stdout))     # trailing whitespace after the split must not break the sanctioned shape
        r = self._guards(_payload("Bash", command="mkdir E:\\repo-memory\\colibri_marketplace ..\\evil"), env_extra=g42)
        self.assertIsNotNone(_deny_json(r.stdout))  # a second mkdir operand stays denied (mkdir creates both)
        r = self._guards(_payload("Bash", command="git init"), env_extra=g42)
        self.assertIsNone(_deny_json(r.stdout))     # repo-gitless is remediable
        # .git IS the gate surface here (plain-git commits)
        r = self._guards(_payload("Write", file_path=str(REPO / ".git" / "hooks" / "pre-push"), content="exit 0"), env_extra=g42)
        self.assertIsNotNone(_deny_json(r.stdout))  # .git is apparatus, never direct-writable mid-FAIL
        r = self._guards(_payload("Write", file_path=str(REPO / ".gitignore"), content="x"), env_extra=g42)
        self.assertIsNone(_deny_json(r.stdout))     # .gitignore is a normal in-repo file (separator-anchored)
        # staging precedes every sanctioned commit
        r = self._guards(_payload("Bash", command="git add AGENTS.md && git commit -m \"fix: x\""), env_extra=g42)
        self.assertIsNone(_deny_json(r.stdout))
        r = self._guards(_payload("Write", file_path=str(REPO / "zcode" / "zcode_repo_guards.ps1"), content="x"), env_extra=g42)
        self.assertIsNotNone(_deny_json(r.stdout))  # apparatus: never direct-writable mid-FAIL
        for apparatus in ("zcode_stop_gate.mjs", "zcode_jcm_guard.ps1", "zcode_jcm_mark.ps1", "session_health.py"):
            # EVERY shipped mount is apparatus - a fail-locked agent must not be able to
            # defang the stop gate or the G6 guard with one silent Write
            r = self._guards(_payload("Write", file_path=str(REPO / "zcode" / apparatus), content="x"), env_extra=g42)
            self.assertIsNotNone(_deny_json(r.stdout), apparatus)

    def test_fail_open_on_garbage(self):
        r = self._guards("{bad json")
        self.assertEqual(r.returncode, 0)
        self.assertFalse(r.stdout.strip())


@unittest.skipUnless(sys.platform == "win32", "hooks are Windows scripts")
class StopGateTests(unittest.TestCase):
    def _ledger(self, sd, edits_after_verify):
        now = 1730000000.0
        skills = {"superpowers:verification-before-completion": now}
        last_edit = now + (10 if edits_after_verify else -10)
        root = str(REPO)
        p = os.path.join(sd, hashlib.sha1(root.encode()).hexdigest() + ".json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump({"lastSrcEditTs": last_edit, "skills": skills}, f)

    def test_blocks_when_edits_outrun_verification(self):
        with tempfile.TemporaryDirectory() as sd:
            self._ledger(sd, True)
            r = _node(STOP, env_extra={"ZSKILL_GATE_STATE_DIR": sd})
            self.assertEqual(r.returncode, 2)
            self.assertIn("verification-before-completion", r.stderr.decode("utf-8", "replace"))

    def test_allows_when_verified_after_edits(self):
        with tempfile.TemporaryDirectory() as sd:
            self._ledger(sd, False)
            r = _node(STOP, env_extra={"ZSKILL_GATE_STATE_DIR": sd})
            self.assertEqual(r.returncode, 0)


@unittest.skipUnless(sys.platform == "win32", "hooks are Windows scripts")
class ConfigTests(unittest.TestCase):
    def test_config_registers_all_five_mounts(self):
        data = json.loads(CONFIG.read_text(encoding="utf-8"))
        events = data["hooks"]["events"]
        self.assertIn("SessionStart", events)
        self.assertIn("Stop", events)
        pre = [blk.get("matcher", "") for blk in events.get("PreToolUse", [])]
        self.assertTrue(any(m.startswith("Read|Bash") for m in pre))
        self.assertTrue(any(m.startswith("Write|Edit|Bash") for m in pre))
        self.assertIn("PostToolUse", events)
        for ev in ("SessionStart", "PreToolUse", "PostToolUse", "Stop"):
            for blk in events.get(ev, []):
                for h in blk.get("hooks", []):
                    for a in h.get("args", []):
                        if str(a).endswith((".ps1", ".mjs")) and str(a) != "-File":
                            self.assertTrue(Path(a).exists(), "hook script missing: %s" % a)

    def test_no_mcp_section(self):
        data = json.loads(CONFIG.read_text(encoding="utf-8"))
        self.assertNotIn("mcp", data)  # per-repo .zcode mcp mounts are flaky; the store rides the machine-wide repo-memory plugin (ZCode) + the root .mcp.json (Claude)


if __name__ == "__main__":
    unittest.main()
