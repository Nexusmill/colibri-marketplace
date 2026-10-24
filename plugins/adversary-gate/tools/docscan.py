"""docscan.py - the LOCAL semantic secret-scan for DOCUMENTATION, the docs half of the
layered gate's domain division (2026-09-03).

WHY: the adversary gate reviews CODE by sending the staged diff to an EXTERNAL model
(OpenRouter). Doing that to DOCS would be the leak we are trying to prevent - a doc's
primary risk is a secret pasted into prose, and transmitting it to review it exfiltrates
it. So the division is:
  * CODE  -> external independent adversary review (adversary_gate.cmd_run).
  * DOCS  -> THIS local model, on-machine, NEVER transmitted.
  * the deterministic pattern pre-scan (adversary_gate._scan_staged_secrets) is the floor
    under BOTH, catching pattern-shaped secrets with zero dependencies.

The local model catches what the regex floor cannot: a bare dictionary-word or prose
password ("password makerbase", "wifi password is sunshine-dragon-42", "root / X9k2-mQ7p!zL")
that has no key-prefix and no assignment syntax. Validated 2026-09-03: Qwen3-4B-Instruct-2507
Q4_K_M scored 13/13 on the calibration battery (0 missed secrets, 0 false alarms), runs on
CPU (-ngl 0, ~18 tok/s) as well as GPU (~120+); the 1.5B was retired for missing real
secrets. Model choice is CONFIGURABLE (env) so a CPU-only adopter can trade recall for speed
- the pattern floor still runs regardless.

Runs via one-shot llama-cli (Caliper's binary by default). A persistent llama-server would
cut per-commit reload cost on CPU-only machines; that is a documented future optimization,
not built here (one-shot is simplest and correct; this machine is GPU-fast).

HONEST LIMITS: (1) a model is required for the SEMANTIC layer - absent, docs get the pattern
floor only, LOUDLY (graceful-degrade, not a silent pass, and not fail-closed which would
block every adopter without a model). (2) a model/subprocess ERROR or timeout also degrades
loudly, never a silent clear. (3) very large doc diffs are scanned up to a chunk cap; the
tail beyond it is reported as pattern-floor-only, never silently skipped.
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile

# ---- config (env-overridable for portability) --------------------------------------------
_HOME = os.path.expanduser("~")


def _first_existing(*cands):
    for c in cands:
        if c and os.path.isfile(c):
            return c
    return None


def _cli():
    """llama-cli path: explicit env, Caliper's bin, then PATH."""
    import shutil
    env = os.environ.get("NEXUSMILL_LLAMA_CLI")
    if env and os.path.isfile(env):
        return env
    hit = _first_existing(
        r"E:/AI/Caliper/bin/llama-cli.exe",
        os.path.join(_HOME, "llama.cpp", "llama-cli.exe"),
        os.path.join(_HOME, ".nexusmill", "llama", "llama-cli.exe"),
    )
    return hit or shutil.which("llama-cli")


def _model():
    """docscan model path: explicit env, then the vendored/Caliper default."""
    env = os.environ.get("NEXUSMILL_DOCSCAN_MODEL")
    if env:
        return env
    return _first_existing(
        r"E:/AI/Caliper/models-llm/Qwen_Qwen3-4B-Instruct-2507-Q4_K_M.gguf",
        os.path.join(_HOME, ".nexusmill", "docscan", "Qwen_Qwen3-4B-Instruct-2507-Q4_K_M.gguf"),
    ) or ""


def model_fingerprint():
    """T4.4 (owner order 2026-10-09): cheap cache-key fingerprint of the ACTIVE
    model - env override path, else the default's pinned sha prefix. Two runs
    with the same fingerprint scan with byte-identical model weights for cache
    purposes (the pin check inside scan() still enforces true integrity).
    Carries SCAN_LOGIC_VERSION: bump it whenever scan()/scan_segmented's LOGIC
    changes (prompt, chunking, post-processing) so cached clears produced by
    older logic drop (gate round gate_20261009-085308 LOW)."""
    env = os.environ.get("NEXUSMILL_DOCSCAN_MODEL")
    if env:
        try:
            st = os.stat(env)
            return "env:%s:%d:v%s" % (env, st.st_size, SCAN_LOGIC_VERSION)
        except OSError:
            return "env:%s:absent:v%s" % (env, SCAN_LOGIC_VERSION)
    return "pinned:%s:v%s" % (_DEFAULT_MODEL_SHA[:16], SCAN_LOGIC_VERSION)


SCAN_LOGIC_VERSION = "1"


# Pinned identity of the DEFAULT model (G17). An adopter pointing NEXUSMILL_DOCSCAN_MODEL at
# their own GGUF sets NEXUSMILL_DOCSCAN_MODEL_SHA (or leaves it blank to skip the pin).
_DEFAULT_MODEL_SHA = "2fde00ce69dd4899c70d020845e2638353015bba0fdf161b3eb965f2bca4464e"
_DEFAULT_MODEL_SIZE = 2497280736  # bytes; cheap per-commit integrity check, full sha cached

_NGL = os.environ.get("NEXUSMILL_DOCSCAN_NGL", "99")   # GPU layers; adopters set 0 for CPU
_MAX_CHUNK = 6000        # chars per model call (fits a 4096-token ctx with headroom)
_MAX_CHUNKS = 24         # cap per commit; tail beyond is reported pattern-floor-only
_TIMEOUT = int(os.environ.get("NEXUSMILL_DOCSCAN_TIMEOUT", "300"))

_SYS = (
    "You are a strict secret-detector guarding commits to a PUBLIC code repository. You are "
    "given the ADDED text of a documentation file. Decide whether it contains at least one "
    "REAL secret credential VALUE: an actual password, API key, access token, private key, or "
    "login credential where a concrete value is written in the text.\n\n"
    "Treat as a REAL secret (=> BLOCK) any concrete value, INCLUDING:\n"
    "- a password given after \"password\", \"pwd\", \"passwd\", \"pass\", \"login\", or a "
    "\"user / VALUE\" or \"user:VALUE\" pair - EVEN IF it is a dictionary word or hyphenated "
    "words (e.g. makerbase, sunshine-dragon-42).\n"
    "- a high-entropy string used as a credential (e.g. X9k2-mQ7p!zL, S3cr3tP@ss).\n"
    "- an API key / token with its value (sk-ant-..., ghp_..., AKIA..., a long random value "
    "after KEY=/TOKEN=).\n"
    "- a private key block.\n\n"
    "Treat as NOT a secret (=> CLEAR):\n"
    "- placeholders: your-key, your-password, xxx, changeme, example, or ANYTHING inside angle "
    "brackets like <your-password-here>.\n"
    "- variable / interpolation references: $PW, ${PRINTER_PW}, %TOKEN%, os.environ[...].\n"
    "- a bare NAME or env-var name with no value beside it: \"set REPLICATE_API_TOKEN in the "
    "vault\", \"the API_KEY variable\".\n"
    "- a MENTION with no value: \"see the manual for the admin password\".\n"
    "- a security INVENTORY or audit that DESCRIBES credentials without writing one: which "
    "file holds keys, which env vars exist, how many password-assignment patterns a script "
    "has, that a key-shaped string exists somewhere, that a dump must never be published. "
    "Describing where secrets live is not a secret.\n"
    "- a SHAPE with no value: \"an AIza...-shaped string\", \"sk-ant-...\", \"a 12-char mixed "
    "password\" - an ellipsis or a description is not a value.\n\n"
    "THE TEST: you may answer BLOCK only if you can QUOTE the concrete secret value on the "
    "REASON line. If you cannot quote a value, the verdict is CLEAR.\n\n"
    "A NAME IS NEVER A VALUE: an env-var name (FIRMS_MAP_KEY, X_TOKEN), the phrase \"X api-key "
    "variable\" / \"X token variable\", a provider name (Replicate, Tavily, LangSmith) and the "
    "words creds / key / token / workspace id are names or descriptions, not values. A document "
    "that lists MANY such names is still an inventory => CLEAR. If the only thing you could write "
    "on the REASON line is a name or a list of names, the verdict is CLEAR.\n\n"
    "BLOCK examples:\n"
    "- \"user mks, password makerbase\"            -> real password (dictionary word)\n"
    "- \"Router admin: root / X9k2-mQ7p!zL\"       -> real password after user/ pair\n"
    "- \"wifi password is sunshine-dragon-42\"     -> real password (hyphenated words)\n"
    "- \"ANTHROPIC_API_KEY set to a value like sk-ant-api03-XXXX\" -> real API key value\n"
    "- \"mysql -u root -pS3cr3tDbP@ss\"            -> real inline password\n\n"
    "CLEAR examples:\n"
    "- \"export API_KEY=your-key-here\"            -> placeholder\n"
    "- \"password: <your-password-here>\"          -> placeholder in angle brackets\n"
    "- sshpass -p $PRINTER_PW                     -> variable reference (not a secret)\n"
    "- \"see the router manual for the admin password\" -> mention, no value\n"
    "- \"store REPLICATE_API_TOKEN in the vault\"  -> a name, no value\n"
    "- \".env holds Google, Tavily and Postgres entries; q2/restore.py has 11 password "
    "patterns\" -> an inventory, no value\n"
    "- \"one AIza...-shaped string in gallery.html\" -> a shape, no value\n"
    "- \"REPLICATE_API token variable, TAVILY api-key variable, FIRMS_MAP_KEY, Postgres creds\" "
    "-> names only, no value\n\n"
    "Output EXACTLY two lines, nothing else:\n"
    "REASON: <the actual secret value if any, else \"none\">\n"
    "VERDICT: BLOCK   or   VERDICT: CLEAR"
)


class DocscanError(RuntimeError):
    pass


def model_available():
    """True when both the llama-cli binary and a model file are present."""
    return bool(_cli()) and os.path.isfile(_model())


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for blk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(blk)
    return h.hexdigest()


def _pin_ok(path):
    """Cheap per-commit integrity gate for the DEFAULT model: size must match the pin, and the
    full sha is verified once and cached by (size, mtime) so we do not re-hash 2.5GB every
    commit. A caller-supplied model (NEXUSMILL_DOCSCAN_MODEL set) with no *_SHA env skips the
    pin. Returns (ok, detail)."""
    want_sha = os.environ.get("NEXUSMILL_DOCSCAN_MODEL_SHA")
    if os.environ.get("NEXUSMILL_DOCSCAN_MODEL") and want_sha is None:
        return True, "custom model, no pin configured"
    want_sha = want_sha or _DEFAULT_MODEL_SHA
    try:
        st = os.stat(path)
    except OSError as e:
        return False, "stat failed: %s" % e
    if not os.environ.get("NEXUSMILL_DOCSCAN_MODEL") and st.st_size != _DEFAULT_MODEL_SIZE:
        return False, "size %d != pinned %d" % (st.st_size, _DEFAULT_MODEL_SIZE)
    cdir = os.path.join(_HOME, ".nexusmill")
    try:
        os.makedirs(cdir, exist_ok=True)
    except OSError:
        pass
    cache = os.path.join(cdir, "docscan_verified.json")   # neutral, not the model's own dir
    key = {"path": os.path.abspath(path), "size": st.st_size,
           "mtime": int(st.st_mtime), "sha": want_sha}
    try:
        prev = json.loads(open(cache, encoding="utf-8").read())
        if prev == key:
            return True, "sha verified (cached)"
    except (OSError, ValueError):
        pass
    if _sha256(path) != want_sha:
        return False, "sha256 mismatch (model is not the pinned build)"
    try:
        tmp = cache + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(key, f)
            f.flush(); os.fsync(f.fileno())
        os.replace(tmp, cache)
    except OSError:
        pass
    return True, "sha verified"


def _run_one(chunk):
    """One llama-cli one-shot over `chunk`; returns 'BLOCK'|'CLEAR' (parsed from the LAST
    VERDICT line) or raises DocscanError on a subprocess/parse failure."""
    return _run_one_full(chunk)[0]


# Words the model uses to DESCRIBE a credential rather than quote one. A REASON made only of
# these, ALL-CAPS identifiers and provider names is a name/description, not a value.
_DESCRIPTIVE = frozenset("""
a an and or of in for to is are was were with as at by on from that this it its no not none
the their there these those value values variable variables var name names named token tokens
key keys api apikey secret secrets cred creds credential credentials password passwords passwd
pass login handle handles id ids project hub owner owners workflow quoted quote real hard coded
hard-coded env entry entries config configuration setting settings bearer placeholder redacted
string strings shaped like eg e.g etc file files line lines mention mentions mentioned describes
described description inventory list lists set stored store vault holds hold reads read via
uses used using workspace space account user username email url endpoint host hostname path
bucket region location database db schema org organization team service provider client
pattern patterns one tracked html prefixed formatted looking style
needs need needed requires require required expects expected expect exports exported defines
defined references referenced refers contains contained includes included has have must should
be model models default reviewer slug fallback
""".split())
# (2026-09-14, push-guard catch on the colibri main landing: the model wrote "needs `OPENROUTER_API_KEY`" -
# a prose VERB the vocabulary lacked held the whole reason as a value and refused a 14-commit
# fast-forward whose lines had already passed in smaller pushes; verbs and the model-id nouns added)
_PROVIDERS = frozenset("""replicate tavily langsmith langchain postgres postgresql google gcp
anthropic openai openrouter moltbook nasa earthdata firms airnow context7 aws azure github
gitlab huggingface hf mysql redis stripe slack discord twilio sendgrid cloudflare vercel""".split())
# Model VENDORS (the left side of an OpenRouter-style slug) and model-FAMILY words. Used by the
# slug rule ONLY: bare, these stay unknown words (a password "nvidia" holds) - gate round 1 of
# the 2026-09-14 fix caught eleven of them widening the provider withdrawal when added to
# _PROVIDERS, and a provider/PASSWORD slug (openai/makerbase) withdrawing on the left side alone
_MODEL_VENDORS = frozenset("""z-ai zai x-ai xai openai anthropic google meta-llama meta mistralai
mistral deepseek qwen nvidia microsoft openrouter cohere perplexity amazon""".split())
_MODEL_WORDS = frozenset("""glm grok gpt claude llama mistral mixtral qwen gemini gemma deepseek phi
sonnet opus haiku flash pro lite instruct chat mini nano turbo preview reasoner coder vision
embed embedding""".split())

# A token the prompt itself calls a placeholder ("export API_KEY=your-key-here -> placeholder") names no
# value: yourpassword, your-key-here, changeme, <redacted>. Push-guard catch 2026-09-08 (the fleet's carried
# AGENT_MEMORY_WIRING.md example DSN, REASON 'yourpassword', held as a value and refused the push).
_VENDOR_PREFIXES = frozenset({"AKIA", "ASIA", "AIza"})  # bare key prefixes with no separator
_PLACEHOLDER_TOKEN = None  # compiled lazily below (re is imported inside _evidence_is_name)


def _evidence_is_name(reason):
    """True when the model's REASON line names NO value-shaped literal: every token is
    descriptive vocabulary, an ALL-CAPS identifier (an env-var NAME: underscored, no 3+ digit
    run), a provider name, a placeholder, or a single ALPHANUMERIC character (never a credential),
    and at least one identifier/provider/placeholder/single-character literal is present. Any other
    token - one with a symbol or a digit run, an un-underscored ALL-CAPS string (an AWS key id), or
    any other word (a dictionary-word password like makerbase) - is treated as a VALUE. Empty,
    'none' or pure filler returns False so a contradictory BLOCK keeps blocking."""
    import re
    global _PLACEHOLDER_TOKEN
    if _PLACEHOLDER_TOKEN is None:
        # FULLMATCH only (gate round 2): a value that merely CONTAINS a placeholder morpheme
        # (sample-key-9f2ac1b8, yourapp-secret, ExamplePass2024!, <sunshine-dragon-42>) stays a
        # value; digits/symbols beyond -_ never qualify except changeme + up to two digits.
        # Round 3 (push-guard catch 2026-09-08): a bare credential ROLE word - the DSN
        # placeholder vocabulary of `user:pw@host` - names no value either (REASON 'pw')
        _PLACEHOLDER_TOKEN = re.compile(
            r"(?:your(?:[-_]?(?:password|passwd|pass|key|api[-_]?key|apikey|token|secret|value|name|"
            r"project|id|handle))?(?:[-_]?here)?|changeme\d{0,2}|placeholder|example|dummy|sample|"
            r"redacted?|x{3,}|\*{3,}|<[A-Za-z][A-Za-z _-]*>|"
            r"user(?:name)?|pw|pwd|pass(?:wd|word)?|secret|token)", re.I)
    # an ellipsis ENDS a token (push-guard catch 2026-09-09: the model wrote `AIza\u2026-shaped`, so
    # the elided prefix was glued to the next word, never reached the prefix rule below, and the
    # whole run held as a value); the stem keeps its ellipsis, the tail becomes its own token
    tokens = re.findall(r"[A-Za-z0-9_'\-.@!$%^&*#+=/\\<>]*?(?:\.\.\.|\u2026)['\"]?|"
                        r"[A-Za-z0-9_'\-.@!$%^&*#+=/\\<>]+", reason or "")
    named = False
    for tok in tokens:
        # Round 4 (push-guard catch 2026-09-08): an ELIDED vendor PREFIX - `lsv2_sk_...`,
        # `sk-ant-...`, `AKIA...` - names no value; the value is exactly what the ellipsis left
        # out. PREFIX-shaped only (gate round 2: `makerbase...` / `hunter2...` - a complete short
        # password before prose ellipsis - must HOLD): the stem ends in `_` or `-` with at most
        # one digit and <= 12 chars, or is a known bare vendor prefix; a truncated real key
        # (`lsv2_sk_9f2ac1b8e4d7...`, `9f2ac1b8e4d7...`) and any bare word fall through.
        if re.search(r"(?:\.\.\.|\u2026)['\"]?$", tok):
            stem = re.sub(r"(?:\.\.\.|\u2026)['\"]?$", "", tok).strip("'\"")
            if (stem.endswith(("_", "-")) and len(stem) <= 12 and sum(c.isdigit() for c in stem) <= 1) \
                    or stem in _VENDOR_PREFIXES:
                named = True
                continue
        bare = tok.strip("'\"-.,;:()[]{}")
        if not bare:
            continue
        if _PLACEHOLDER_TOKEN.fullmatch(bare) and not re.fullmatch(r"[A-Z0-9_]+", bare):
            named = True                  # a placeholder is a name for "no value here"; an
            continue                      # ALL-CAPS value (AKIA...EXAMPLE) stays a value below
        low_whole = bare.lower()[:-2] if bare.lower().endswith("'s") else bare.lower()
        if low_whole in _DESCRIPTIVE:
            continue
        if re.fullmatch(r"[+-]?[0-9]{1,6}\.[0-9]{1,6}", bare):
            # a decimal FLOAT literal (a timeout of 30.0, a price of 0.02) is a quantity, never a credential
            # (push-guard pre-test 2026-09-16 on the model-pins feed: a reviewer response quoting a code
            # fixture's `timeout_s: float = 30.0` drew `30.0` as the value 3/3). Digits.digits ONLY, at most
            # six each side; an integer (a PIN), a dotted triple and anything glued to letters keep their
            # value status below.
            named = True
            continue
        if len(bare) == 1 and bare.isalnum():
            # a ONE-CHARACTER literal is never a credential (push-guard catch 2026-09-15 on the fleet
            # probe push: a plan document's embedded test code `setenv("XAI_API_KEY", "k")` was
            # quoted 3/3 as the secret value `"k"`). Exactly one letter or digit - `k7`, `PW`, a lone
            # symbol and every longer token keep their value status below.
            named = True
            continue
        if low_whole in _PROVIDERS:
            named = True                  # ANTHROPIC, GOOGLE - a provider in caps
            continue
        if re.fullmatch(r"[A-Z][A-Z0-9_]{2,}", bare):
            # an env-var / identifier NAME has an underscore and at most short digit runs
            # (CONTEXT7_API_KEY, S3_BUCKET); an ALL-CAPS value has neither (an AWS key id,
            # PASSWORD1, ABC123) or carries a 3+ digit run (MY_SECRET_123) - gate round 1
            if "_" in bare and not re.search(r"[0-9]{3,}", bare):
                named = True
                continue
            return False
        # a vendor-slash-model SLUG names no value (EV-083, 2026-09-14: the reviewer's own
        # default model id was quoted 3/3 as "the secret value"). BOUNDED three ways: the left
        # side is a known MODEL vendor; the right side is lowercase, no 3+ digit run, no 8+ hex
        # run; and the right side carries a MODEL shape - a dotted version (5.3), a parameter
        # size (70b) or a family word (glm, grok, chat). So openai/sk-<hex>, z-ai/<hex>,
        # hunter/two, abc/def123== AND openai/makerbase, postgres/sunshine-dragon-42,
        # openai/hunter2 (gate round 1) all stay values. Residual, accepted: a password built
        # from a family word plus short digits (flash-42) behind a vendor name.
        slug = re.fullmatch(r"([a-z][a-z0-9-]*)/([a-z][a-z0-9.-]*)", bare)
        if slug and slug.group(1) in _MODEL_VENDORS and not re.search(r"[0-9]{3,}|[0-9a-f]{8,}", slug.group(2)):
            segs = slug.group(2).split("-")
            if re.search(r"[0-9]+\.[0-9]+", slug.group(2)) or any(
                    re.fullmatch(r"[0-9]+b", s) or s in _MODEL_WORDS for s in segs):
                named = True
                continue
        # a hyphenated phrase ("api-key", "hard-coded") is judged part by part; any part
        # that is not descriptive vocabulary or a provider name is a VALUE candidate
        for part in bare.split("-"):
            low = part.lower()
            if low.endswith("'s"):
                low = low[:-2]
            if not low or low in _DESCRIPTIVE:
                continue
            if low in _PROVIDERS:
                named = True
                continue
            return False                  # a digit/symbol-bearing part or an unknown word
    return named


def _run_one_full(chunk):
    """One llama-cli one-shot over `chunk`; returns ('BLOCK'|'CLEAR', reason_text)."""
    cli, model = _cli(), _model()
    if not cli or not os.path.isfile(model):
        raise DocscanError("llama-cli or model missing")
    sysfd, syspath = tempfile.mkstemp(suffix=".sys.txt")
    txtfd, txtpath = tempfile.mkstemp(suffix=".doc.txt")
    try:
        os.write(sysfd, _SYS.encode("utf-8")); os.close(sysfd)
        os.write(txtfd, chunk.encode("utf-8")); os.close(txtfd)
        try:
            p = subprocess.run(
                [cli, "-m", model, "-sysf", syspath, "-f", txtpath, "-st",
                 "-c", "4096", "-n", "128", "--temp", "0", "-ngl", str(_NGL),
                 "--no-warmup", "--no-display-prompt"],   # no prompt echo -> parse ONLY the
                capture_output=True, text=True, encoding="utf-8", errors="replace",  # model's
                timeout=_TIMEOUT)                                                    # output
        except subprocess.TimeoutExpired:
            raise DocscanError("model timed out after %ds" % _TIMEOUT)
        except OSError as e:                     # cli path exists but is not runnable
            raise DocscanError("llama-cli spawn failed: %s" % e)
        if p.returncode != 0:                    # a crash/empty run must DEGRADE, never
            raise DocscanError("llama-cli rc=%s: %s" % (p.returncode, (p.stderr or "")[-200:]))
        import re
        v = re.findall(r"VERDICT:\s*(BLOCK|CLEAR)", p.stdout, re.I)   # generated text only now
        if not v:                                # empty/verdict-less generation -> DEGRADE
            raise DocscanError("no VERDICT in generated output")
        reasons = re.findall(r"REASON:\s*(.*)", p.stdout)
        return v[-1].upper(), (reasons[-1].strip() if reasons else "")
    finally:
        for pth in (syspath, txtpath):
            try:
                os.remove(pth)
            except OSError:
                pass


def _fake_verdict():
    """Selftest stub (parity with adversary_gate's guard): returns 'BLOCK'/'CLEAR' ONLY inside
    a selftest repo - ADVERSARY_SELFTEST=1 AND the cwd BASENAME starts with 'advgate_' - else
    None. Checked before model_available so integration tests need no real model."""
    fake = os.environ.get("DOCSCAN_FAKE")
    if not fake or os.environ.get("ADVERSARY_SELFTEST") != "1":
        return None
    if not os.path.basename(os.getcwd()).startswith("advgate_"):
        return None
    return "BLOCK" if fake.upper() == "BLOCK" else "CLEAR"


def scan(text):
    """Semantic secret-scan of `text` (the ADDED doc content). Returns a dict:
      {"status": "clear"|"block"|"degraded", "detail": str, "chunks": n, "capped": bool}
    status 'block' => a real secret was found (refuse the commit).
    status 'degraded' => model absent / error / pin failure (caller warns + falls back to the
      pattern floor; NEVER a silent clear).
    """
    if not text.strip():
        return {"status": "clear", "detail": "empty", "chunks": 0, "capped": False}
    fv = _fake_verdict()
    if fv:
        return {"status": "block" if fv == "BLOCK" else "clear",
                "detail": "selftest stub", "chunks": 0, "capped": False}
    if not model_available():
        return {"status": "degraded", "detail": "no local model/binary", "chunks": 0, "capped": False}
    capped = False
    chunks = []
    try:
        ok, why = _pin_ok(_model())
        if not ok:
            return {"status": "degraded", "detail": "model pin failed: %s" % why,
                    "chunks": 0, "capped": False}
        chunks = _chunk(text, _MAX_CHUNK)
        capped = len(chunks) > _MAX_CHUNKS
        chunks = chunks[:_MAX_CHUNKS]
        for i, ch in enumerate(chunks):
            verdict, reason = _run_one_full(ch)
            if verdict != "BLOCK":
                continue
            if _evidence_is_name(reason):
                # the model "quoted" a variable name / a description as the secret value
                # (2026-09-07: "REPLICATE_API token variable"; a prose description of a
                # project id) - no literal is named, so the block is withdrawn, visibly
                sys.stderr.write("docscan: chunk %d BLOCK withdrawn - the evidence names no "
                                 "value, only: %s\n" % (i + 1, reason[:120]))
                continue
            return {"status": "block", "detail": "chunk %d" % (i + 1),
                    "chunks": len(chunks), "capped": capped}
    except Exception as e:      # BEST-EFFORT: DocscanError, or an OSError from a broken binary
        # / hashing a vanished model / temp-file / an over-long arg list - degrade LOUDLY,
        # NEVER raise out and crash the mandatory pre-commit hook (pattern floor still ran).
        return {"status": "degraded", "detail": "docs scan error: %s" % (str(e)[:150]),
                "chunks": len(chunks), "capped": capped}
    status = "clear"
    detail = "scanned %d chunk(s)" % len(chunks)
    if capped:
        detail += " (CAPPED at %d - tail is pattern-floor-only, not semantically scanned)" % _MAX_CHUNKS
    return {"status": status, "detail": detail, "chunks": len(chunks), "capped": capped}



def scan_segmented(text, max_chunks=24):
    """T3.2 / hole H2 (gate top-to-bottom), BOUNDED (gate round gate_20261009-041145,
    HIGH): scan added doc text of ANY size within a hard per-invocation CHUNK budget
    (model-call granularity - the old single scan() call capped at _MAX_CHUNKS and
    >25MB files were excluded outright). Splits at line boundaries into 6000-char
    chunks, scans via the same pipeline in <=24-chunk scan() groups, stops at
    max_chunks total: block wins, degraded propagates, capped=True (loud,
    pattern-floor-only tail) when the text exceeds the budget - the commit path
    NEVER multiplies model invocations beyond the budget (no local DoS)."""
    chunks = _chunk(text or "", _MAX_CHUNK)
    capped = len(chunks) > max_chunks
    chunks = chunks[:max_chunks]
    seg_size = _MAX_CHUNK * _MAX_CHUNKS          # per scan() call
    total = 0
    for start in range(0, len(chunks), _MAX_CHUNKS):
        segment = "".join(chunks[start:start + _MAX_CHUNKS])
        res = scan(segment)
        total += res.get("chunks", 0)
        if res["status"] == "block":
            return dict(res, chunks=total,
                        detail="segment %d: %s" % (start // _MAX_CHUNKS + 1,
                                                   res.get("detail", "")))
        if res["status"] == "degraded":
            return dict(res, chunks=total)
        capped = capped or bool(res.get("capped"))
    detail = "scanned %d chunk(s) within the %d-chunk budget" % (total, max_chunks)
    if capped:
        detail += " (CAPPED - tail is pattern-floor-only, not semantically scanned)"
    return {"status": "clear", "detail": detail, "chunks": total, "capped": capped}

def _chunk(text, size):
    """Line-boundary chunks <= `size` chars. A single line LONGER than `size` (pasted blob /
    minified JSON / base64) is HARD-SPLIT into <= size pieces with a 200-char overlap, so a
    secret straddling a split is still wholly visible in at least one piece - the old
    'whole lines stay together' invariant was false for such lines and left the tail past
    the context window unscanned."""
    pieces = []
    for line in text.splitlines(keepends=True):
        if len(line) <= size:
            pieces.append(line)
            continue
        step = max(1, size - 200)
        i = 0
        while i < len(line):
            pieces.append(line[i:i + size])
            if i + size >= len(line):
                break
            i += step
    out, cur, n = [], [], 0
    for line in pieces:
        if n + len(line) > size and cur:
            out.append("".join(cur)); cur, n = [], 0
        cur.append(line); n += len(line)
    if cur:
        out.append("".join(cur))
    return out or [text]


# =============================================================================
# RECURRENCE SCREEN (owner order 2026-10-22: "I dont want any more lessons
# gone unlearned anymore"). Lives in THIS file (the gate's local-scanner
# module) by design, twice over: as a NEW catalog file it could never
# reach the installed generation (gate round 3 finding 1 - the active
# generation builds the next from its OWN catalog), and folded into
# adversary_gate.py it pushed that CERTIFIED_CATALOG file over
# MAX_FILE_BYTES, which the Tools-repo runtime-catalog coupling refuses
# outright (round 4). Here it ships with every generation of the gate -
# docscan.py is already cataloged - and stays far under every budget.
# Abstract lessons are centralized below (_RS_LESSONS); each repo binds
# them to its concrete coupled sites in <repo>/recurrence_screen.json;
# the gate's cmd_check enforces the screen before anything else for
# every repo the machine-wide hooks reach. Local, deterministic, no
# network, no model calls.
# =============================================================================

_RS_LESSONS = [
    {"id": "RL-0001", "class": "coupled-duplicate drift",
     "statement": (
         "Any value maintained in more than one place by design - a "
         "mirror, a test expectation, a fixture catalog, a selftest pin - "
         "drifts when one site changes and the others do not. Notes, "
         "parity tests, and good intentions do not count: they are part "
         "of the same coupling they fail to check. The coupling must be "
         "verified mechanically against primary bytes at a forced "
         "chokepoint (the commit gate), or it WILL drift."),
     "detector": "parity",
     "provenance": [
         "2026-10-20 -> 2026-10-22: the flash-1017 repin updated the gate "
         "chain constants but not the coupled sites - the tier-2 pin test "
         "(retired baidu expectation), the autoland GATE_LADDER hand-mirror, "
         "and fleet_selftest's fixture catalog + order tuple went stale the "
         "same day; two batteries were red and one green-hollow, all "
         "unnoticed until the audit-drain artifact fix ran them (docket "
         "EV-269, Tools 6d75be7).",
         "Same class, earlier: the per-session canon copies drifted until "
         "propagation (G34); the jCodemunch mirrors were RETIRED because "
         "maintaining them drifted (JCM-RETIRE-MIRRORS, 2026-08-12); the "
         "RSI clustering RCA fields drifted from the rule texts until the "
         "payload bound every reviewed byte (AGENT_STATE session 10j p2)."],
     "landed": "2026-10-22"},
    {"id": "RL-0002", "class": "guarantee claim without a machine-held test",
     "statement": (
         "A docstring, comment, or doc that STATES a guarantee is a "
         "coupling to the test that proves it. Claims survive their tests: "
         "the test is deleted, renamed, or weakened while the claim keeps "
         "asserting - and the next fix restores the claim only against the "
         "exact probe that caught it. Every stated guarantee must be bound "
         "to its property test, and removing or rewording either side must "
         "fail the commit until the binding is consciously updated."),
     "detector": "guarantee",
     "provenance": [
         "2026-10-21/22: w6.py claimed 'the blinding is STRUCTURAL, not "
         "procedural' while no test held the property - the audit lane "
         "broke it twice (key co-location, EV-262; marker ineffective, "
         "EV-263), each fix restoring the claim against only the last "
         "probe, until the guarantee was rewritten to what is held.",
         "2026-10-21/22: the s5 module docstring enumerated three dedup "
         "tiers after TIER_PRIORITY gained a fourth (audit-lane WARN "
         "20261021-002638, docket EV-264); the STRAT-4 docstrings "
         "overclaimed 'reserves'/'executes' vs the code (EV-268 r2)."],
     "landed": "2026-10-22"},
    {"id": "RL-0003", "class": "coordinated rotation with coupled stragglers",
     "statement": (
         "When a value that exists in several places must change (a pin "
         "rotation, a chain reorder, a protocol bump), rotating one site "
         "and leaving stragglers is not a partial success - it is a silent "
         "split-brain. The rotation is complete only when every coupled "
         "site moves together, and only a mechanical parity check at "
         "commit proves that."),
     "detector": "parity",
     "provenance": [
         "Canon G37's 'pins rotate only together' clause predates and did "
         "not prevent the 2026-10-20 stragglers (EV-269) - a behavioral "
         "rule that recurred anyway until it gained a machine check.",
         "The gate ladder order 2026-10-12 -> 2026-10-20 rotated the "
         "chains while four coupled sites held the old era (test_ladder, "
         "fleet_config, fleet_selftest fixture, fleet_selftest order)."],
     "landed": "2026-10-22"},
]

_RS_DEFAULT_VALUES = r'"[^"]*"'
_RS_DEFAULT_END = r"\n\)"


def _rs_fail(msg):
    return False, [msg]


def _rs_slug_set(raw_values):
    """Normalize captured raw quoted values into a comparable slug set:
    strip quotes -> split comma-joined rungs -> strip provider pins ->
    drop empties. Order-insensitive by construction (a set)."""
    out = set()
    for raw in raw_values:
        for part in raw.strip('"').split(","):
            part = part.strip()
            if "@" in part:
                part = part.split("@", 1)[0]
            if part and " " not in part:
                out.add(part)
    return out


def _rs_region(text, site, where):
    anchor = site.get("anchor", "")
    if not anchor:
        return None, "%s: binding site has no anchor" % where
    m = re.search(anchor, text)
    if m is None:
        return None, ("%s: region anchor not found - the coupled site "
                      "moved (update the binding in recurrence_screen.json)"
                      % where)
    end = re.compile(site.get("end", _RS_DEFAULT_END)).search(text, m.start())
    # INCLUSIVE end: the end pattern is typically the region's own closing
    # token (a quote-paren, a bracket); excluding it truncated the final
    # value out of every set (caught live on the gate's own bindings)
    stop = end.end() if end else len(text)
    return text[m.start():stop], None


def _rs_wt_reader(root):
    """Working-tree reader (the CLI/manual-audit default). A root that
    does not exist raises RuntimeError (round 5 finding 2: a mistyped
    --repo path read as 'nothing bound' and printed a false PASS)."""
    if not os.path.isdir(root):
        raise RuntimeError("repo root does not exist: %s" % root)
    def read(rel):
        with open(os.path.join(root, rel), encoding="utf-8",
                  errors="replace") as fh:
            return fh.read()
    return read


def _rs_index_reader(root, git_bin="git"):
    """Index reader (the GATE path): read the state a commit would LAND -
    the index entry, which is the staged blob for staged paths and the
    HEAD blob for tracked-but-unchanged paths. Working-tree reads let
    partial staging split a coupled pair past the screen (only one side
    staged -> tree agrees, the commit lands the stale side), and unstaged
    WIP edits in any bound file refused totally unrelated commits (gate
    round 1 finding 2). The git child carries the same hardenings as the
    gate's _run_git (round 2 finding 1): GIT_NO_REPLACE_OBJECTS (a local
    git replace must not substitute the screened bytes), timeout=60 (a
    stalled git fails closed, never wedges the machine-wide hook),
    stdin=DEVNULL. A path genuinely absent from the index raises
    FileNotFoundError; ANY other git failure raises RuntimeError so the
    caller degrades LOUDLY instead of reading it as "nothing bound"
    (round 2 finding 2)."""
    def read(rel):
        env = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1")
        try:
            r = subprocess.run(
                [git_bin, "-C", root, "show", ":" + rel.replace("\\", "/")],
                capture_output=True, text=True, errors="replace",
                stdin=subprocess.DEVNULL, timeout=60, env=env, shell=False)
        except subprocess.TimeoutExpired:
            raise RuntimeError("git show %s timed out" % rel)
        if r.returncode == 0:
            return r.stdout
        err = (r.stderr or "")
        if ("does not exist" in err or "invalid object name" in err
                or ("not in" in err and "index" in err)):
            raise FileNotFoundError(rel)
        raise RuntimeError("git show %s failed: %s" % (rel, err.strip()[:120]))
    return read


def _rs_site_set(site, lesson_id, name, reader):
    where = "%s %s [%s]" % (lesson_id, name, site.get("file", "?"))
    rel = site.get("file", "")
    if not rel:
        return None, "%s: binding site has no file" % where
    try:
        text = reader(rel)
    except FileNotFoundError:
        return None, ("%s: declared file missing (not in the screened "
                      "state)" % where)
    except OSError as exc:
        return None, "%s: unreadable (%s)" % (where, str(exc)[:80])
    region, err = _rs_region(text, site, where)
    if err:
        return None, err
    values = re.findall(site.get("values", _RS_DEFAULT_VALUES), region)
    exclude = site.get("exclude")
    if exclude:
        values = [v for v in values if not re.search(exclude, v)]
    return _rs_slug_set(values), None


def _rs_screen_parity(binding, lesson_id, reader):
    name = binding.get("name", "?")
    mode = binding.get("mode", "equal")
    groups = binding.get("groups") or []
    if len(groups) < 2:
        return _rs_fail("%s %s: a parity binding needs >=2 groups" %
                        (lesson_id, name))
    sets_, errs = [], []
    for gi, group in enumerate(groups):
        # round 6 finding 2: a group with no sites (typo'd key, scaffold)
        # yields an empty set - two empty sets compare EQUAL and the
        # binding checks nothing while passing silently
        if not group.get("sites"):
            return _rs_fail("%s %s: group %d has no sites (typo'd key or "
                            "scaffold?) - refusing" % (lesson_id, name, gi))
        union = set()
        for site in group.get("sites", []):
            val, err = _rs_site_set(site, lesson_id, name, reader)
            if err:
                errs.append(err)
            else:
                union |= val
        sets_.append(union)
    if errs:
        return False, errs
    if all(not s for s in sets_):
        return _rs_fail("%s %s: every group extracted ZERO values - the "
                        "binding checks nothing (values regex never "
                        "matched?)" % (lesson_id, name))
    if mode == "superset":
        if len(sets_) != 2:
            return _rs_fail("%s %s: superset mode needs exactly 2 groups" %
                            (lesson_id, name))
        if not sets_[1] >= sets_[0]:
            return _rs_fail("%s %s: superset violated - group2 %s is missing %s"
                            % (lesson_id, name, sorted(sets_[1]),
                               sorted(sets_[0] - sets_[1])))
        return True, []
    first = sets_[0]
    for other in sets_[1:]:
        if other != first:
            return _rs_fail("%s %s: coupled sites disagree - %s vs %s "
                            "(fix the drift in the cited sites, or rotate "
                            "ALL coupled sites together)" %
                            (lesson_id, name, sorted(first), sorted(other)))
    return True, []


def _rs_screen_guarantee(binding, lesson_id, reader):
    name = binding.get("name", "?")
    # round 5 finding 1: an empty pattern matches EVERYTHING - a typo'd
    # key ("regexp"/"nameregex") or a claims/tests-less binding checked
    # nothing and passed silently. Validate the shape up front; anything
    # that would check nothing is a malformed binding refusal.
    claims = binding.get("claims") or []
    tests = binding.get("tests") or []
    if not claims or not tests:
        return _rs_fail("%s %s: a guarantee binding needs >=1 claim and "
                        ">=1 test (nothing to check otherwise)" %
                        (lesson_id, name))
    for claim in claims:
        if not claim.get("file") or not claim.get("regex"):
            return _rs_fail("%s %s: malformed claim entry (needs file + "
                            "regex; check for typo'd keys)" %
                            (lesson_id, name))
    for test in tests:
        if not test.get("file") or not test.get("name_regex"):
            return _rs_fail("%s %s: malformed test entry (needs file + "
                            "name_regex; check for typo'd keys)" %
                            (lesson_id, name))
    msgs = []
    for claim in binding.get("claims", []):
        where = "%s %s [%s]" % (lesson_id, name, claim.get("file", "?"))
        try:
            text = reader(claim.get("file", ""))
        except FileNotFoundError:
            msgs.append("%s: claim file missing" % where)
            continue
        except OSError as exc:
            msgs.append("%s: unreadable (%s)" % (where, str(exc)[:80]))
            continue
        if not re.search(claim.get("regex", ""), text):
            msgs.append("%s: claim text not found - the guarantee was "
                        "reworded or removed; restore it or consciously "
                        "update the binding" % where)
    for test in binding.get("tests", []):
        where = "%s %s [%s]" % (lesson_id, name, test.get("file", "?"))
        try:
            text = reader(test.get("file", ""))
        except FileNotFoundError:
            msgs.append("%s: TEST FILE MISSING - the guarantee's property "
                        "test is gone" % where)
            continue
        except OSError as exc:
            msgs.append("%s: unreadable (%s)" % (where, str(exc)[:80]))
            continue
        if not re.search(test.get("name_regex", ""), text):
            msgs.append("%s: property test not found - the guarantee "
                        "outlived its test" % where)
    return (not msgs), msgs


def _rs_screen_repo(root, reader=None):
    """Screen one repo against the centralized lessons. -> (ok, messages).
    reader: file-content accessor (defaults to the working tree; the
    gate's cmd_check passes an index reader so the screen judges the
    state that would land). A repo with no manifest passes (nothing
    bound); a corrupt manifest or a malformed binding REFUSES (never a
    silent pass, never a silent disable - gate rounds 1-3)."""
    if reader is None:
        reader = _rs_wt_reader(root)
    try:
        lessons = {l["id"]: l for l in _RS_LESSONS}
    except (KeyError, TypeError) as exc:
        return _rs_fail("RECURRENCE CONTAINER malformed (%s) - refusing; "
                        "this should be impossible (gate-reviewed code)"
                        % str(exc)[:120])
    try:
        manifest = json.loads(reader("recurrence_screen.json"))
        bindings = manifest["bindings"]
    except FileNotFoundError:
        return True, []                      # nothing bound in this state
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return _rs_fail("recurrence_screen.json manifest corrupt (%s) - "
                        "refusing" % str(exc)[:120])
    # round 6 finding 1: a non-list bindings value iterated zero times
    # (silent pass) or raised TypeError into the caller's engine-failure
    # degrade (gate skips the screen)
    if not isinstance(bindings, list):
        return _rs_fail("recurrence_screen.json manifest corrupt: "
                        "'bindings' must be a list (got %s) - refusing"
                        % type(bindings).__name__)
    ok, msgs = True, []
    for binding in bindings:
        try:
            lesson_id = binding.get("lesson", "?")
            lesson = lessons.get(lesson_id)
            if lesson is None:
                ok = False
                msgs.append("%s: unknown lesson id (not in the centralized "
                            "container)" % lesson_id)
                continue
            detector = lesson.get("detector")
            if detector == "parity":
                b_ok, b_msgs = _rs_screen_parity(binding, lesson_id, reader)
            elif detector == "guarantee":
                b_ok, b_msgs = _rs_screen_guarantee(binding, lesson_id,
                                                    reader)
            else:
                b_ok, b_msgs = _rs_fail(
                    "%s: container declares unknown detector '%s'"
                    % (lesson_id, detector))
        except (AttributeError, TypeError, KeyError, ValueError,
                re.error) as exc:
            # gate round 1 finding 3: a parseable-but-malformed binding
            # must REFUSE, never escape to the caller's engine-failure
            # degrade (that would silently disable the coupling)
            b_ok = False
            b_msgs = ["%s: malformed binding (%s: %s) - refusing" %
                      (binding.get("lesson", "?") if isinstance(binding, dict)
                       else type(binding).__name__,
                       type(exc).__name__, str(exc)[:100])]
        ok = ok and b_ok
        msgs.extend(b_msgs)
    return ok, msgs
