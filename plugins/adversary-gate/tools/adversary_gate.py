"""adversary_gate.py - the MANDATORY pre-commit adversarial review gate (Nexusmill tools).

Born 2026-08-30 from Damien's order after plan-triangulation proved that authors (models AND
the in-session agent) defend invented claims: "every bit of code written, before it's
committed, needs an adversarial review... build it so you have no choice."

NO CHOICE is structural: installed as a git pre-commit hook (core.hooksPath .githooks), it
runs on EVERY commit through every path (CLI git, _git_do.py, IDE). A commit touching CODE
files is REFUSED unless .adversary/clearance.json holds a CLEAR verdict keyed to the exact
sha256 of each staged blob - any re-edit invalidates the clearance automatically. The
reviewer is an INDEPENDENT external model (OpenRouter; default tencent/hy3, sub-cent per
commit) - never the author.

Commands:
  check                       (the pre-commit hook) exit 1 unless every staged code file is cleared
  run [--model M] [--context "rebuttal/notes"]   run the adversary on the staged change;
                              CLEAR -> writes clearances + artifact; BLOCK -> findings, exit 1
  record [--ref R]            (the post-commit hook) notarize HEAD: write a durable git note
                              (refs/notes/adversary) iff every changed code blob matches a
                              fresh CLEAR (or a provenance-matched OVERRIDE); else write
                              NOTHING and exit 1 - the audit tripwire keys on note absence
  status                      show staged files vs clearance state

Escape hatch (auditable, one-shot, for the OWNER's emergencies - not the agent's):
  a file .adversary/OVERRIDE containing a written reason lets ONE commit through (and a commit
  carrying its OVERRIDE note passes the push guard's secret barrier with a warning) with a loud
  warning, then is deleted. Using it without Damien's explicit say-so is a protocol violation.

Key: OPENROUTER_API_KEY env (never printed). Artifacts land in .adversary/reviews/ (the
directory is gitignored - transient gate state, not history; durable verdicts still go to
the repo's review archives by the normal protocol).
"""
# 2026-09-16: incomplete reviews advance the configured chain; one strict final verdict
# governs both commit and pre-write authorization. BLOCK/conflicts never shop for CLEAR.
import argparse
import ast
import datetime
import hashlib
import http.client
import json
import os
import re
import subprocess
import sys
import time
import tempfile
import urllib.error
import urllib.parse
import urllib.request
try:                                  # vendored beside this file: the docs half of the gate
    import docscan                    # (domain division 2026-09-03). Absent -> docs degrade.
except Exception:
    docscan = None

GIT = r"C:\Program Files\Git\cmd\git.exe"
if not os.path.isfile(GIT):
    GIT = "git"                       # relocated/foreign machine: rely on PATH
CODE_EXTS = {".py", ".js", ".json", ".ts", ".jsx", ".tsx", ".html", ".css", ".ps1", ".sh", ".bat",
             ".c", ".cpp", ".h", ".rs", ".go", ".java", ".glsl", ".osl",
             # OWNER RULING 2026-10-02 (reverses the 2026-09-30 "notes.txt not code" pin;
             # closes the EV-179 blind spot where reviewers fabricated about .txt maps they
             # could not see): an agent-modified .txt is mutated content -> it is reviewed.
             ".txt",
             # EV-029 (2026-09-04): Caliper's git-guard.mjs - a security guard - passed a gate run
             # UNREVIEWED because the ES-module / CommonJS / TS-module forms were missing here.
             ".mjs", ".cjs", ".mts", ".cts"}
# .githooks/: a hook edit could neuter the gate (birth review r2). .github/workflows/: the
# CI audit workflow is enforcement config too - editing it un-gated is the same hole
# (layered-enforcement review 2026-08-31).
GATED_PREFIXES = (".githooks/", ".github/workflows/")
# 2026-09-06 (universal arming): an extensionless git HOOK file is code WHEREVER it lives - the
# canonical shims in Tools/adversary-gate/ (the single source of every vendored .githooks/ shim)
# and the machine-wide dispatchers in adversary-gate/hooks/ were never in the staged-code list,
# so the bytes every repo execs could be edited un-reviewed. Mirrored in adversary_audit.py.
HOOK_NAMES = ("pre-commit", "post-commit", "pre-push")
# ...confined to commits strictly AFTER the per-repo rules epoch the installer records when it
# vendors a HOOK_NAMES-aware auditor (`hook-names <sha>`): earlier commits touched hook files
# while they were docs-class and carry no note by design (gate round 2 MEDIUM). Staging (a new
# commit) always applies the rule; only the durable-side walkers consult the epoch.
RULES_EPOCH_FILE = os.path.join(".githooks", "adversary_rules_epoch")
NOTES_REF = "refs/notes/adversary"
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
API_URL = "https://openrouter.ai/api/v1/chat/completions"
XAI_API_URL = "https://api.x.ai/v1/responses"   # xAI-native backup (grok); different API shape
LOCAL_API_URL_DEFAULT = "http://127.0.0.1:11434/v1/chat/completions"   # Ollama OpenAI-compat; the `local:` rung (owner order 2026-09-30). Override per call with ADVERSARY_LOCAL_URL.
# Prompt-side remedy for the MEASURED verdict-first quirk (replay 2026-09-30: 6/6 completed
# local rounds led with the verdict line and scored malformed). This is INPUT shaping -
# exactly what --context already does - never response munging: the single-final-verdict
# invariant stays untouched and still refuses duplicate/leading markers.
LOCAL_FORMAT_SUFFIX = ("\n\nOUTPUT CONTRACT (reminder): your reply must END with exactly one "
                       "final line 'VERDICT: CLEAR' or 'VERDICT: BLOCK' - no other line may "
                       "start with 'VERDICT:'.")


def _local_vram_free_mib():
    """Free VRAM in MiB, or None when it cannot be measured (no nvidia-smi / timeout).
    The FIRST nvidia-smi line is CUDA device 0 - the device Ollama loads on by default
    (CUDA_VISIBLE_DEVICES unset); on this single-CUDA-GPU host that is the 5080."""
    try:
        out = subprocess.run(
            ["nvidia-smi", "--query-gpu=memory.free", "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=15).stdout.strip()
        return int(out.splitlines()[0].strip())
    except Exception:
        return None


def _local_model_loaded(model):
    """True when the local endpoint already has THIS model resident (steady state: no new
    load will occur, so the VRAM floor does not apply - free VRAM is low BECAUSE the model
    is loaded, which is the intended bounded state). Best-effort via /api/ps."""
    base = (os.environ.get("ADVERSARY_LOCAL_URL") or LOCAL_API_URL_DEFAULT)
    base = base.rsplit("/v1/chat/completions", 1)[0]
    try:
        with urllib.request.urlopen(base + "/api/ps", timeout=8) as r:
            d = json.loads(r.read())
        # EXACT match only, deliberately conservative: a tag-less request ("mistral")
        # resolving to a different resident tag ("mistral:7b") must NOT bypass the floor -
        # serving it may still require a NEW load (the CPU-offload case the owner forbade).
        # A missed residency match costs one conservative skip to the external rungs; a
        # wrong bypass can spill to CPU and freeze the desktop. Asymmetric - by design.
        return any((m.get("name") or "") == model for m in d.get("models", []))
    except Exception:
        return False


def _local_vram_guard(model):
    """Owner order 2026-09-30 (restart-and-bound session): the local rung must NEVER spill
    to CPU - Ollama decides GPU-vs-CPU placement at LOAD time from free VRAM, so this runs
    BEFORE any request. Below the floor the rung fails CLOSED with a loud skip (stderr +
    SystemExit; the chain advances to the external rungs) instead of a multi-minute
    offload grind that freezes the desktop. Floor is read per call
    (ADVERSARY_LOCAL_MIN_FREE_MIB, MiB; 0 disables; a non-integer refuses the rung rather
    than guessing). Default 13000 sizes the bounded serving model - Q3_K_M ~10.7GiB
    weights + 8k-ctx KV ~0.65GiB (OLLAMA_NUM_PARALLEL=1) + buffers ~0.8GiB ~= 12.4GiB -
    with ~0.6GiB load margin, leaving the desktop a ~3.9GiB total allowance on the
    5080's 16GiB. Unmeasurable (no nvidia-smi) proceeds - transport rules still apply.
    When the model is ALREADY resident (_local_model_loaded) the floor does not apply:
    placement already happened (100% GPU) and holding the resident model IS the bounded
    steady state - free VRAM is low because the model is loaded, by design."""
    raw = os.environ.get("ADVERSARY_LOCAL_MIN_FREE_MIB", "13000") or "0"
    try:
        floor = int(raw)
    except ValueError:
        raise SystemExit("ADVERSARY GATE: ADVERSARY_LOCAL_MIN_FREE_MIB is not an integer "
                         "(%r) - local rung skipped rather than guess" % raw)
    if floor == 0 or _local_model_loaded(model):
        return
    free = _local_vram_free_mib()
    if free is not None and free < floor:
        sys.stderr.write("ADVERSARY GATE: local rung SKIPPED - %d MiB VRAM free, floor is "
                         "%d MiB (loading now would spill to CPU; falling through to the "
                         "external rungs)\n" % (free, floor))
        raise SystemExit("ADVERSARY GATE: local rung SKIPPED - %d MiB VRAM free, floor is "
                         "%d MiB: loading now would spill to CPU (owner order: never "
                         "offload, warn and fall through to the external rungs)"
                         % (free, floor))
# --model accepts a comma-separated FALLBACK CHAIN: models are tried in order and the
# chain advances only on transport/provider failure (HTTP errors, exhausted 429s, an
# error payload) or an EMPTY-content response (no verdict was rendered - seen live as
# reasoning-token exhaustion) - never on a rendered verdict. The EV-004 invariant that
# survives: an empty response can never CLEAR; if the LAST model in the chain is also
# empty, cmd_run fails closed to BLOCK exactly as before. Owner ruling 2026-09-01:
# glm-5.3-flash primary (similarly priced and it FINISHES). Owner ruling 2026-09-03:
# grok-4.6 (xAI-native - an `xai:` prefix routes a chain entry to api.x.ai, NOT OpenRouter)
# Owner order 2026-09-30 (side-chat, cost control after kimi failover rounds took 59% of
# the day's spend): pinned glm rung 2, pinned deepseek rung 3, kimi LAST RESORT. Pins
# re-ranked reliability-first (10/10 probe answers, then uptime, then fp8-certainty, then
# throughput) from model-pins evidence 2026-09-16: glm = sail-research/fp8 + wafer +
# together (the previous parasail/coreweave/modal pins measured 0/10 answers in that
# probe); ds-flash = digitalocean + deepinfra/fp8 + phala (drops 97.8%-uptime
# open-inference from the lead); ds-pro pins unchanged (owner-confirmed from the
# 2026-09-23 cache-read measurements). kimi version price-checked live 2026-09-30:
# k2.7-code ($0.671/$3.35) is the highest tier at its price - k3 is 4.5x, not same-price;
# unpinned (new model, no measured pins). Probe data is 14 days old; fleet_probe can
# refresh. A `local:` prefix routes an entry to the Ollama-compatible endpoint
# (ADVERSARY_LOCAL_URL, default LOCAL_API_URL_DEFAULT) - same chat-completions shape, no
# auth header, transport failure advances the chain. local-first in DEFAULT_CHAIN is
# PENDING the replay catch-rate bar (owner gates it on data; until then `local:` is
# reachable via ADVERSARY_MODEL/--model only). fleet_selftest validates parity with
# GATE_LADDER and the live catalog. Explicit overrides still win.
# Owner order 2026-10-01 (pricing re-evaluation): prices MUST come from the
# OpenRouter per-provider page / endpoints API for the PINNED endpoint - never
# third-party tables, never another provider's price for the same model (the
# 2026-09-30 table priced ds-pro at deepinfra $1.30/$2.60 while baidu/fp8 is
# $0.2376/$0.7128 with $0.00756/M cache). At that pricing ds-pro-0813 is the
# strongest coder at qwen-adjacent cost (output CHEAPER, cache 9x cheaper,
# 1.05M ctx covers MAX_TOTAL_BYTES) -> PRIMARY. Qwen removed from default
# failover on 2026-10-04: SVG review 390d379059da443fa180bc9cd8dfe92d
# fabricated geometry and returned conflicting/non-final verdicts after primary HTTP 402.
# Explicit owner model selection remains available. Pins
# verified against the live /models/{slug}/endpoints tags; kimi unpinned LAST.
def _env_int(name, default):
    try:
        return int(os.environ.get(name, "") or default)
    except (TypeError, ValueError):
        return default


# --- tiered reviewer structure (owner order 2026-10-08) ---
# Tier 1 (quick rung): deepseek-v4.1-flash pinned primary+failover. Provider pins from
# the live OpenRouter endpoints API 2026-10-08 (owner rule: prices never from
# third-party tables): baidu/fp8 $0.0354 in / $0.1416 out / $0.0007 cache - the
# cheapest completion AND cache of any fp8 host; deepinfra/fp8 $0.14/$0.42/cache
# $0.0042 failover. Owner ruled glm-5.3-flash out (price rise) and ds-pro-0813 off
# the every-commit rung.
TIER1_CHAIN = ("deepseek/deepseek-v4.1-flash@baidu/fp8,"
               "deepseek/deepseek-v4.1-flash@deepinfra/fp8")
# Tier 2 (strong escalation rung): owner pick 2026-10-08 - tencent/hy4-preview, "a
# true escalation model". Pins from the live endpoints API (owner rule: never
# third-party tables): tencent/fp8 PRIMARY - first-party AND cheapest on all three
# axes ($0.7506 in / $2.2509 out / $0.0378 cache; its UTC 0-1600 peak rate merely
# TIES the field); novita/fp8 BACKUP - identical fp8 at field price with the best
# uptime of the alternatives (100% 1-day vs deepinfra 95.87% / siliconflow 94.50%).
# kimi stays the terminal operational failover.
TIER2_CHAIN = ("tencent/hy4-preview@tencent/fp8,"
               "tencent/hy4-preview@novita/fp8,"
               "moonshotai/kimi-k2.7-code")
DEFAULT_CHAIN = TIER1_CHAIN + "," + TIER2_CHAIN
DEFAULT_MODEL = os.environ.get("ADVERSARY_MODEL", DEFAULT_CHAIN)
MAX_FILE_BYTES = 250_000          # per staged file included in full
MAX_TOTAL_BYTES = 1_050_000       # complete runtime + tests + diff; pinned reviewers support this budget
# G-C (owner order 2026-10-08): verdicts are bytes and findings are bounded prose -
# cap completion tokens so no verbose rung can bill unbounded output.
# R3 (owner order 2026-10-08, same day): the ceiling is a DERIVATIVE OF PAYLOAD
# SIZE, not a flat number - a flat cap starves reasoning reviewers on large
# (catalog-coupled) payloads: live evidence, every tier-2 rung returned
# finish_reason=length with 100% reasoning tokens and zero content at flat
# 2000/8000/16000. AMENDED same day (live data): the review TASK's reasoning
# load floors around 20-30k tokens regardless of payload size - budgets of
# 6.5k and 20.5k starved every rung on real payloads, and the only capped-era
# successes were >= 21.9k - so the FLOOR is 32000 (an unused ceiling costs
# nothing: max_tokens bounds, it does not bill) and the hard cap is 64000.
MAX_OUTPUT_TOKENS = _env_int("ADVERSARY_MAX_TOKENS", 32000)
MAX_OUTPUT_TOKENS_CAP = _env_int("ADVERSARY_MAX_TOKENS_CAP", 64000)
OUTPUT_TOKENS_PER_INPUT_PCT = 15
# G-D: per-tier review timeouts - a stalled "quick" rung must never wedge a commit
# for the old uniform 20 minutes.
TIER1_TIMEOUT_S = _env_int("ADVERSARY_TIER1_TIMEOUT", 180)
TIER2_TIMEOUT_S = _env_int("ADVERSARY_TIER2_TIMEOUT", 600)
# Tier-1 eligibility (mirrors the legacy promote boundary): small payloads without
# rebuttals, removals, gated prefixes or oversize blobs ride the quick rung.
TIER1_MAX_CHARS = _env_int("ADVERSARY_TIER1_MAX_CHARS", 40000)
# Sampled batch audit of tier-1 CLEARs: a deterministic tree+day hash selects
# AUDIT_PCT% for a post-hoc tier-2 BATCH re-review (50% off, zero commit latency).
# BATCH POLICY (owner order 2026-10-08): the interactive commit path NEVER routes to
# :batch - ONLY these post-hoc audits do, because nothing waits on their verdict.
AUDIT_PCT = _env_int("ADVERSARY_AUDIT_PCT", 10)
TIER2_AUDIT_MODEL = os.environ.get(
    "ADVERSARY_AUDIT_MODEL",
    # The LIVE batch ladder primary (autoland/fleet_config.py BATCH_LADDER, gate
    # round gate_20261008-150151 HIGH): deepseek-v4-pro-0813:batch was DELISTED
    # from the catalog 2026-09-22 - defaulting the audit to it dead-lettered every
    # sampled audit as REJECTED. Re-pin alongside TIER2_CHAIN after the owner's
    # benchmark pick; ADVERSARY_AUDIT_MODEL overrides.
    "openai/gpt-6-luna-pro:batch")
# selftest fake sequencing: "BLOCK,CLEAR" consumes one verdict per model call.
_FAKE_CALLS = 0

# ---- LOCAL secret pre-scan (layered-enforcement fix 2026-09-02) --------------------------
# WHY: the gate reviews by sending the staged diff to a REMOTE model (OpenRouter), and it
# only triggered when a CODE file was staged - so (a) a docs-only commit got no review at
# all, and (b) any secret in a reviewed diff was transmitted off-machine. Both proven live:
# EV-023 (a gateway root / AP admin / printer password pasted into a memory .md) was caught
# only because .py files were co-staged, and the catch itself shipped the plaintext creds to
# the reviewer API. This pre-scan runs LOCALLY on EVERY staged file first and is not
# extension-gated. Since the owner ruling of 2026-09-07 (EV-046) it WARNS at commit time and
# every matched value is SCRUBBED out of the transmit payload; the push guard is the barrier.
# HONEST LIMIT (no-silent-caps): it is pattern-based - known key prefixes, private-key
# blocks, sshpass/URL creds, and secret-named assignments carrying a high-entropy value. A
# bare dictionary-word password sitting in prose (no assignment, no sshpass/URL context) is
# out of regex reach; the external adversarial review stays the semantic layer for code.
_SECRET_LITERALS = [
    ("private-key-block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("aws-access-key-id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("gcp-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{16,}")),
    ("openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}")),
    ("groq-key", re.compile(r"\bgsk_[A-Za-z0-9]{20,}")),
    ("github-token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{16,}")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
    ("replicate-token", re.compile(r"\br8_[A-Za-z0-9]{30,}")),
    ("hf-token", re.compile(r"\bhf_[A-Za-z0-9]{30,}")),
    ("langsmith-key", re.compile(r"\blsv2_(?:pt|sk)_[A-Za-z0-9]{16,}")),
    ("ssh-password-flag", re.compile(r"sshpass\s+-p\s*['\"]?(?P<v>\S{3,})")),
    ("url-embedded-cred", re.compile(r"://[^:@/\s]+:(?P<v>[^@/\s]{6,})@")),
]
_SECRET_ASSIGN = re.compile(
    r"(?P<key>[A-Za-z0-9_.\-]{0,64}(?:password|passwd|pwd|secret|api[_-]?key|token|bearer)"
    r"[A-Za-z0-9_.\-]{0,64})\s*[=:]\s*(?P<q>['\"])?(?P<v>[^\s'\"#,;)]+)", re.I)
# Vendor-DOCUMENTED example credentials: they match a hard pattern by construction but are
# public by definition (AWS's own docs). Skipped by both scanners so a tutorial cannot become
# permanently unpushable (gate catch gate_20260907-171348, advisory).
_DOCUMENTED_EXAMPLES = {"AKIA" + "IOSFODNN7EXAMPLE"}
_SECRET_PLACEHOLDER = re.compile(
    r"your|example|changeme|placeholder|redact|dummy|sample|<[^>]*>|\.\.\.|xxx|"
    r"^\*+$|^(.)\1{4,}$|^(?:true|false|yes|no|none|null|n/?a|present|set|unset|todo|"
    r"enabled?|disabled?|undefined)$|"
    # the bare NAME of a secret used as its own value is the tutorial idiom (a URL whose
    # credential part is the word password; the ssh password flag given the word secret) -
    # never a real credential; a trailing punctuation char is tolerated
    r"^['\"]?(?:password|passwd|pwd|pass|secret|token|api[_-]?key|user(?:name)?)['\"]?[)\],.;:]?$",
    re.I)


def _looks_secret(v, quoted=False):
    """True if `v` has the shape of a real secret (not a placeholder/flag). A 12-char
    mixed-class value (the EV-023 gateway-password shape) must qualify. An UNQUOTED value
    that is a code expression (bare identifier, dotted path, call, index) is rejected -
    `secret_hits = _scan_staged_secrets()` is code, not a secret (the no-self-trip fix) -
    UNLESS it is a 20+ char pure-alphanumeric run carrying digits: that is hex / base36 /
    base62, never a sane identifier, and the exemption used to swallow every unquoted hex
    secret whose first char was a letter (fail-open found by the EV-025 fixtures).
    The long two-class branch (hex / base32 tokens: one letter case + digits) requires a
    DIGIT class (EV-025, 2026-09-03): letters + punctuation alone is the shape of an env-var
    name, a slash path, a kebab word or a CamelCase identifier, never a machine-generated
    secret - `Container token = GH_X/Y_TOKEN` blocked a docs commit. Accepted cost: a
    letters-only passphrase of 20+ chars in an assignment is left to docscan / the reviewer."""
    if len(v) < 8 or _SECRET_PLACEHOLDER.search(v):
        return False
    has_digit = bool(re.search(r"[0-9]", v))
    alnum_run = len(v) >= 20 and has_digit and re.fullmatch(r"[A-Za-z0-9]+", v) is not None
    if not quoted and not alnum_run and (re.match(r"^[A-Za-z_][\w.]*$", v)
                                         or re.search(r"[()\[\]{}]", v)):
        return False
    classes = ((1 if re.search(r"[a-z]", v) else 0) + (1 if re.search(r"[A-Z]", v) else 0)
               + (1 if has_digit else 0) + (1 if re.search(r"[^A-Za-z0-9]", v) else 0))
    return classes >= 3 or (len(v) >= 20 and classes >= 2 and has_digit)


def _all_staged_files():
    out = _run_git(["diff", "--cached", "--name-only", "-z", "--diff-filter=ACMRT"])
    return [f for f in out.split("\0") if f]


def _scan_one_text(text, max_hits):
    """Per-line secret scan of arbitrary text. Returns [(line_no, label)], NO values. A
    line > 4096 chars runs ONLY the cheap anchored literal patterns (the generic-assign
    regex is skipped there - it has no fixed prefix and would backtrack quadratically on a
    long identifier-class run: a ReDoS on the mandatory hook)."""
    hits = []
    for i, line in enumerate(text.splitlines(), 1):
        matched = None
        for label, rx in _SECRET_LITERALS:
            m = rx.search(line)
            if m:
                v = m.groupdict().get("v")
                # skip placeholders AND shell/env variable references ($PW, ${PW}, %PW%,
                # <PW>) - `sshpass -p "$PW"` is safe usage, not a literal secret.
                if v and (_SECRET_PLACEHOLDER.search(v) or re.match(r"^['\"]?[\$%{<]", v)):
                    continue
                if m.group(0) in _DOCUMENTED_EXAMPLES:
                    continue
                matched = label
                break
        if not matched and len(line) <= 4096:
            m = _SECRET_ASSIGN.search(line)
            if m and _looks_secret(m.group("v"), bool(m.group("q"))):
                matched = "secret-assignment(%s)" % m.group("key")[:24]
        if matched:
            hits.append((i, matched))
            if len(hits) >= max_hits:
                break
    return hits


_HUNK_HEADER = re.compile(r"^@@ -\S+ \+(\d+)(?:,\d+)? @@")


def _staged_added_lines(path):
    """[(new_line_no, text)] - the '+' hunk lines this commit ADDS to one staged `path`,
    numbered in the NEW file (from the `@@ -a,b +c,d @@` headers). One `git diff --cached
    --unified=0` per file (quotepath off, :(top,literal) pathspec) so the file's own name
    never has to be parsed back out of a diff header. `--text` forces hunks even when a
    .gitattributes `-diff`/`binary` attribute would collapse the file to 'Binary files
    differ' (gate finding on this change: without it an UNGATED one-line .gitattributes
    commit blinded the floor for every later doc); --no-textconv / --no-relative stop a
    textconv filter or a subdirectory cwd from hiding lines. Mid-merge, `diff --cached`
    is still a plain two-way index-vs-HEAD diff (probe-verified; selftest 24d), so
    hand-resolved AND cleanly-merged files both yield their '+' lines. Before the first
    hunk, lines are headers; inside hunks every '+' line is content (a content line
    '++ x' arrives as '+++ x' and is kept). Splits on '\\n' only."""
    out = _diff_paths(["-c", "core.quotepath=false", "diff", "--cached", "--unified=0",
                       "--text", "--no-color", "--no-ext-diff", "--no-textconv",
                       "--no-relative"], [path])
    added, in_hunk, cur = [], False, None
    for ln in out.split("\n"):
        m = _HUNK_HEADER.match(ln)
        if m:
            in_hunk, cur = True, int(m.group(1))
        elif in_hunk and ln.startswith("+") and cur is not None:
            added.append((cur, ln[1:]))
            cur += 1
        # '-' (removed) and '\\ No newline at end of file' lines carry no new-file number
    return added


def _scan_staged_secrets(max_hits=50):
    """The ADDED lines of every staged file (any extension) scanned for secret material -
    NOT the full blob (owner ruling 2026-09-03, EV-025): a line already in history is not
    re-flagged on every later edit to that file (a one-line edit to a 4,800-line state
    file paid for every old line). Returns [(path, NEW-file line, label)] with NO values.
    Binary (NUL in the first 8 KB) and >25 MB blobs are skipped exactly as before - the
    bound _staged_doc_files applies - so the '>25MB - NOT scanned by any layer' warning
    stays true and a genuinely binary file is never diffed as text. Runs entirely locally
    - nothing is transmitted. cmd_run additionally SCRUBS the exact payload (removed lines
    included) before transmission - _scrub_text."""
    hits = []
    for path in _all_staged_files():
        try:
            blob = _run_git(["show", ":" + path], binary=True)
        except SystemExit:
            continue
        if b"\x00" in blob[:8192] or len(blob) > 25_000_000:      # binary or pathological
            continue
        try:
            added = _staged_added_lines(path)
        except SystemExit:
            continue
        for ln_no, text in added:
            for _, label in _scan_one_text(text, 1):
                hits.append((path, ln_no, label))
                break
            if len(hits) >= max_hits:
                return hits
    return hits


def _scan_text_secrets(text, max_hits=50):
    """Scan arbitrary text (the EXACT payload about to be transmitted) for secret material.
    Returns [("<payload>", line, label)] - covers removed lines, diff hunks, and an
    oversized-and-omitted file's hunks, none of which appear in _scan_staged_secrets.
    Caller: reviewed_write.py (the pre-write broker) refuses transmission on any hit. Removed by
    8245433 (2026-09-07) while that caller still used it - the gate cleared the removal because
    the caller was not staged; restored 2026-09-09 and guarded by _removed_symbol_callers."""
    return [("<payload>", ln, label) for ln, label in _scan_one_text(text, max_hits)]


_EXOTIC_BREAKS = re.compile("([\r\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029])")   # str.splitlines() minus \n


def _scrub_line(line):
    """(scrubbed_line, [label per redaction]) for one '\\n'-delimited payload line. The line is
    scrubbed per str.splitlines() SEGMENT (a lone CR / VT / FF / NEL / LS / PS / FS-GS-RS also
    ends a segment) so the 4096-char heuristic gate and the value search see the same units
    the old per-line scanner saw - a >4096-char physical line hiding an assignment secret
    behind a lone CR would otherwise skip the heuristic and ship it (gate catch
    gate_20260907-165431)."""
    parts = _EXOTIC_BREAKS.split(line)
    labels = []
    for k in range(0, len(parts), 2):          # even indexes are segments, odd the breaks
        parts[k], labs = _scrub_segment(parts[k])
        labels.extend(labs)
    return "".join(parts), labels


def _scrub_segment(line):
    """(scrubbed_segment, [label per redaction]): EVERY secret-shaped VALUE in `line` replaced by
    <REDACTED:label>, so a false positive costs nothing and a true positive never leaves the
    machine. Literal patterns first (the value group when the pattern has one, else the whole
    match), then the assignment heuristic on lines <= 4096 chars (ReDoS parity with
    _scan_one_text). The search RESUMES after each match - a placeholder / variable reference /
    non-secret value is skipped, a redaction is stepped over - so the second and later values on
    one line are reached too (gate catch gate_20260907-161313: a `break` on the first
    non-secret match left every later value on the line in plaintext). Bounded per pattern."""
    labels = []
    for label, rx in _SECRET_LITERALS:
        pos = 0
        for _ in range(32):
            m = rx.search(line, pos)
            if not m:
                break
            v = m.groupdict().get("v")
            if (v and (_SECRET_PLACEHOLDER.search(v) or re.match(r"^['\"]?[\$%{<]", v))) \
                    or m.group(0) in _DOCUMENTED_EXAMPLES:
                pos = m.end()                      # skip it, keep scanning the line
                continue
            tag = "<REDACTED:%s>" % label
            if label == "private-key-block":
                # key material can follow the header on the SAME line (a one-line PEM, or a
                # header glued to its first base64 chunk): redact the rest of the line (gate
                # catch gate_20260907-163540 - the header alone was replaced, the tail shipped)
                line = line[:m.start()] + tag
                labels.append(label)
                break
            if v:
                line = line[:m.start("v")] + tag + line[m.end("v"):]
                pos = m.start("v") + len(tag)
            else:
                line = line[:m.start()] + tag + line[m.end():]
                pos = m.start() + len(tag)
            labels.append(label)
        else:                                      # cap reached: it bounds WORK, never leakage
            if rx.search(line, pos):
                line = line[:pos] + "<REDACTED:%s:cap - rest of line>" % label
                labels.append(label)
    if len(line) <= 4096:
        pos = 0
        for _ in range(32):
            m = _SECRET_ASSIGN.search(line, pos)
            if not m:
                break
            if not _looks_secret(m.group("v"), bool(m.group("q"))):
                pos = m.end()                      # a placeholder / code expression: skip
                continue
            tag = "<REDACTED:secret-assignment>"
            line = line[:m.start("v")] + tag + line[m.end("v"):]
            pos = m.start("v") + len(tag)
            labels.append("secret-assignment(%s)" % m.group("key")[:24])
        else:                                      # cap: bounds WORK, never leakage - a real
            if _SECRET_ASSIGN.search(line, pos):   # value past the 32nd match must not ship
                line = line[:pos] + "<REDACTED:secret-assignment:cap - rest of line>"
                labels.append("secret-assignment(cap)")
    return line, labels


_PEM_BEGIN = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")
_PEM_END = re.compile(r"-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")
_PEM_MAX_LINES = 200        # the longest real PEM body is ~50 lines (RSA-4096); a BEGIN with no
#                             END within this many lines is a fragment, not a key: redaction
#                             resumes per line so the rest of the review payload survives
#                             (gate catch gate_20260907-163011: an unterminated header devoured
#                             every later hunk, file and note and the reviewer cleared a gutted
#                             payload - over-redaction fails OPEN, so it is bounded and warned)


def _scrub_text(text):
    """(scrubbed_text, [(line_no, label) per redacted VALUE]) over the EXACT payload about to
    be transmitted - removed diff lines, hunks and the author's context included. Newlines
    are preserved verbatim (split on '\\n' only) so the reviewer's line references hold.
    A private-key BLOCK spans lines: once its BEGIN header is seen, every line through the
    matching END line is replaced wholesale - the base64 body is the secret, the header only
    announces it (gate catch gate_20260907-162135) - bounded by _PEM_MAX_LINES, after which a
    'private-key-block:unterminated' hit is recorded and per-line scrubbing resumes."""
    out, hits = [], []
    in_block = 0                                   # lines redacted inside the current block
    for i, line in enumerate(text.split("\n"), 1):
        if in_block:
            if in_block >= _PEM_MAX_LINES:
                hits.append((i, "private-key-block:unterminated"))
                in_block = 0                       # fall through: scrub this line normally
            else:
                out.append("<REDACTED:private-key-block>")
                hits.append((i, "private-key-block"))
                in_block = 0 if _PEM_END.search(line) else in_block + 1
                continue
        s, labels = _scrub_line(line)
        if "private-key-block" in labels:
            # arm the block unless the ORIGINAL line already closes it after its BEGIN (a
            # one-line PEM); the scrubbed line has lost its tail, so judge the original
            b, e = _PEM_BEGIN.search(line), _PEM_END.search(line)
            if not (b and e and e.start() > b.start()):
                in_block = 1
        hits.extend((i, lab) for lab in labels)
        out.append(s)
    return "\n".join(out), hits


def _print_secret_warning(hits, stream, where):
    """Commit-time secret hits WARN (owner ruling 2026-09-07, the 'warn version'): values are
    never printed, the commit is not blocked, the transmit payload is scrubbed, and the push
    guard (_push_secret_barrier) is the barrier: a hard literal refuses the push, the
    heuristic only ever warns."""
    stream.write("\nADVERSARY GATE: WARNING - secret-shaped material in the staged change (%s). "
                 "Values are not printed and the commit is NOT blocked (owner ruling "
                 "2026-09-07); the review payload is scrubbed before transmission. The push "
                 "guard scans every outgoing commit: a secret LITERAL refuses the push, "
                 "heuristic matches only warn - remove a real value before pushing.\n" % where)
    for path, ln, label in hits:
        stream.write("  %s:%s  %s\n" % (path, ln, label))
    stream.write("\n")


PROMPT = (
    "You are the pre-commit ADVERSARY. A change set is about to be committed; your ONLY "
    "job is to try to REFUTE its correctness. Hunt for real defects the change INTRODUCES "
    "or ENABLES: logic errors, broken callers/call sites, wrong line/symbol assumptions, "
    "unhandled paths, state and ordering races, money-safety, security, contract breaks "
    "with the surrounding code visible in the provided files. Verify the change's implicit "
    "claims against the provided bytes - authors of this repo have shipped confident wrong "
    "claims before; assume nothing. IGNORE style, naming, formatting, and pre-existing "
    "issues the change does not touch or worsen. A REBUTTAL section, when present, is the "
    "author's response to a previous BLOCK - weigh it, verify it, and do not re-raise a "
    "point it factually settles. Review the actual operation: a pre-write proposal is not "
    "yet a commit. For documents and fabrication assets, check their stated scope and "
    "supplied evidence; do not invent external specifications or treat missing unrelated "
    "files as defects. SVG cut-sheet coordinates describe independent nested parts, not "
    "their assembled positions. Verify interval arithmetic before alleging overlap or "
    "overflow. Report only findings that survive your own checks, with a concrete trigger "
    "and impact; discard disproved hypotheses. Do not output internal deliberation or "
    "intermediate verdicts. Use exactly one verdict, as the final line. "
    "A finding set of LOW severities and nothing else may instead end with exactly "
    "'VERDICT: WARN' (the commit lands with the findings recorded in its clearance); "
    "any MEDIUM-or-higher finding must end with 'VERDICT: BLOCK'. "
    "Repo doctrine you must not re-litigate: a "
    ".colibri_reviews/_manifest.json row is keyed by the ABSOLUTE source path with a rel "
    "field and a modes table BY DESIGN (colibri store.py writes it that way) - absolute keys, "
    "machine paths inside them and a full sha256 in sha are the canonical shape, not findings; "
    "a second entry for a file that already has one, a files wrapper, or relative-keyed "
    "wrapperless rows ARE findings (they fragment or hide the record). "
    "End with EXACTLY one line: 'VERDICT: CLEAR' if nothing "
    "real was found, or 'VERDICT: BLOCK' preceded by your findings (each: severity, file, "
    "line/symbol, trigger, impact). A confident wrong finding wastes the author's time; an "
    "unearned CLEAR ships a bug. Be exact."
)


# Used only while building a review from an immutable index snapshot in this process.
_REVIEW_BASE = None


def _run_git(args, binary=False):
    args = list(args)
    if _REVIEW_BASE is not None:
        if "diff" in args and "--cached" in args:
            args.insert(args.index("--cached") + 1, _REVIEW_BASE)
        if args and args[0] == "show" and len(args) > 1 and args[1].startswith("HEAD:"):
            args[1] = _REVIEW_BASE + args[1][4:]
    # GIT_NO_REPLACE_OBJECTS: a local `git replace <dirty> <innocent>` otherwise makes
    # diff/show read the substituted object graph, so the gate would hash the innocent
    # blob and clear a dirty commit (audit-probe finding). Ignore replace refs.
    env = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1")
    # A synchronous Git child inside MCP must not inherit the protocol pipe;
    # on Windows that stalls rev-parse while the event loop is blocked here.
    # timeout=60 (marketplace round gate_20261011-093046 MEDIUM): a slow git
    # must fail CLOSED with the gate's message, never crash on a raw
    # TimeoutExpired traceback.
    try:
        p = subprocess.run([GIT] + args, capture_output=True, env=env,
                           stdin=subprocess.DEVNULL, timeout=60)
    except subprocess.TimeoutExpired:
        raise SystemExit("git %s timed out after 60s - failing closed; re-run the "
                         "gate when the repository is responsive."
                         % " ".join(args[:2]))
    if p.returncode != 0:
        raise SystemExit("git %s failed: %s" % (" ".join(args[:2]),
                                                p.stderr.decode("utf-8", "replace")[:300]))
    return p.stdout if binary else p.stdout.decode("utf-8", "replace")


def _repo_root():
    return _run_git(["rev-parse", "--show-toplevel"]).strip()


def _staged_code_files():
    # -z (NUL-delimited) + no strip: under git's default core.quotepath a non-ASCII path
    # is emitted C-quoted, which the old splitlines()/strip() path silently dropped from
    # the gate (fail-open). T = typechange (a code file swapped for a symlink/gitlink) now
    # counts too - the NEW blob at that path must carry a clearance.
    out = _run_git(["diff", "--cached", "--name-only", "-z", "--diff-filter=ACMRT"])
    return [f for f in out.split("\0") if f and _is_code(f)]


def _staged_sha(path):
    return hashlib.sha256(_run_git(["show", ":" + path], binary=True)).hexdigest()


def _is_code(path, hook_names=True, text_files=True):
    ext = os.path.splitext(path)[1].lower()
    return (path.startswith(GATED_PREFIXES) or (ext in CODE_EXTS and (ext != ".txt" or text_files))
            or (hook_names and os.path.basename(path) in HOOK_NAMES))


_EPOCH_ANCHOR_CACHE = {}


def _text_files_apply(rev):
    # The certified runtime includes this sibling auditor; share its ancestry validation
    # so notary/push history and standalone CI agree. Staging always uses current rules.
    import adversary_audit
    return adversary_audit._text_files_apply(_repo_root(), rev)


def _hook_names_apply(rev):
    """Mirror of adversary_audit._hook_names_apply for the push guard and the notary: the
    HOOK_NAMES rule applies to `rev` unless the repo's .githooks/adversary_rules_epoch names a
    `hook-names <sha>` that `rev` is an ancestor of (or equal to). The anchor judgement
    (sha, shallow, adds) is memoized per repo root; only the per-rev ancestry test repeats."""
    root = _repo_root()
    if root in _EPOCH_ANCHOR_CACHE:
        sha = _EPOCH_ANCHOR_CACHE[root]
        if sha is None or sha == "ROOT":
            return True                                 # no / moved / unreadable / ROOT epoch
        env = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1")
        return subprocess.run([GIT, "-C", root, "merge-base", "--is-ancestor", rev, sha],
                              capture_output=True, env=env).returncode != 0
    # read from HEAD's TREE only (Tools E gate round 1, gate_20260906-223831): working-tree
    # reads are case-folded / symlink-following, the anchor is exact; an uncommitted epoch =
    # the rule applies everywhere until it is committed
    env0 = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1")
    p_show = subprocess.run([GIT, "-C", root, "show", "HEAD:" + RULES_EPOCH_FILE.replace("\\", "/")],
                            capture_output=True, env=env0)
    if p_show.returncode != 0:
        _EPOCH_ANCHOR_CACHE[root] = None
        return True
    sha = None
    for ln in p_show.stdout.decode("utf-8", "replace").splitlines():
        parts = ln.split()
        if len(parts) == 2 and parts[0] == "hook-names":
            sha = parts[1]
    if not sha:
        _EPOCH_ANCHOR_CACHE[root] = None
        return True
    if sha == "ROOT":
        _EPOCH_ANCHOR_CACHE[root] = "ROOT"              # armed at birth: applies everywhere
        return True
    # ANCHORED IN HISTORY (mirror of adversary_audit._epoch, deepagents re-vendor gate round 1,
    # gate_20260906-210758): the recorded sha must be an ancestor of EVERY commit that ever
    # added the epoch file (order-independent, --full-history: round 2, gate_20260906-214441),
    # or a later commit could grandfather earlier hook-file commits out of the rule. A moved,
    # shallow or unreadable epoch = the rule applies everywhere (fail closed).
    # Anchored to the repo ROOT (`-C root` + a :(top) pathspec) and replace-ref-proof, like the
    # wrappers (Tools D gate round 1, gate_20260906-212201): a cwd-relative pathspec read
    # nothing from a subdirectory and trusted the moved sha, and a local `git replace` could
    # forge the ancestry the anchor tests.
    env = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1")

    def hist(args):
        return subprocess.run([GIT, "-C", root] + args, capture_output=True, env=env)

    def unsound():
        _EPOCH_ANCHOR_CACHE[root] = None
        return True

    p_sh = hist(["rev-parse", "--is-shallow-repository"])
    if p_sh.returncode != 0 or p_sh.stdout.decode("utf-8", "replace").strip() == "true":
        return unsound()                                # shallow: ancestry unjudgeable
    p_log = hist(["log", "--full-history", "--diff-filter=A", "--format=%H", "--",
                  ":(top)" + RULES_EPOCH_FILE.replace("\\", "/")])
    if p_log.returncode != 0:
        return unsound()
    adds = p_log.stdout.decode("utf-8", "replace").split()
    if not adds:
        return unsound()                                # in HEAD's tree yet no add = truncation
    for add in adds:
        if hist(["merge-base", "--is-ancestor", sha, add]).returncode != 0:
            return unsound()
    _EPOCH_ANCHOR_CACHE[root] = sha
    return hist(["merge-base", "--is-ancestor", rev, sha]).returncode != 0


def _staged_removals():
    """Deleted code files + code files renamed AWAY (old path was code) - removing or
    hiding code is a code change (adversary finding, birth review r3). Keyed as
    'D:<old path>' with the sha of the HEAD blob being removed."""
    out = _run_git(["diff", "--cached", "--name-status", "-M", "-z", "--diff-filter=DR"])
    toks = out.split("\0")
    keys = {}
    i = 0
    while i < len(toks):
        st = toks[i]
        if not st:
            i += 1
            continue
        code = st[0]
        if code == "R":
            old, new = toks[i + 1], toks[i + 2]
            i += 3
            if not (_is_code(old) and not _is_code(new)):
                continue                           # code renamed to a non-code extension
        elif code == "D":
            old = toks[i + 1]
            i += 2
            if not _is_code(old):
                continue
        else:
            i += 2
            continue
        try:
            blob = _run_git(["show", "HEAD:" + old], binary=True)
        except SystemExit:
            blob = b""
        keys["D:" + old] = hashlib.sha256(blob).hexdigest()
    return keys


def _diff_paths(pre_args, paths):
    """git diff over `paths`, BATCHED so a many-hundred-file commit cannot blow the OS
    command-line limit, with :(top,literal) pathspecs - anchored to the REPO ROOT (a manual
    check/run from a SUBDIRECTORY still matches; plain :(literal) is cwd-relative and would
    return an empty diff -> a silent fail-open) and glob-disabled. Concatenated diff text.
    `git diff` does not support --pathspec-from-file, hence the argv batching."""
    if not paths:
        return ""
    specs = [":(top,literal)" + p for p in paths]
    out, batch, blen = [], [], 0
    for s in specs:
        if batch and blen + len(s) + 1 > 28000:      # under the Windows ~32k argv ceiling
            out.append(_run_git(pre_args + ["--"] + batch))
            batch, blen = [], 0
        batch.append(s)
        blen += len(s) + 1
    if batch:
        out.append(_run_git(pre_args + ["--"] + batch))
    return "".join(out)


DOCSCAN_EXTS = {".md", ".txt", ".rst"}
"""Text formats the LOCAL semantic docscan always covers - UNION semantics with
CODE_EXTS (owner ruling 2026-10-02): .txt became reviewable code, but a prose
secret in a .txt must still be caught ON-MACHINE by the docscan, not merely shown
to the external reviewer."""


def _staged_doc_files():
    """(scannable, oversized): staged doc-scan text files split by size.
    DOCSCAN_EXTS code ALSO gets the docscan (union); other code stays reviewer-only. `scannable` (<=25MB,
    non-binary) go to the LOCAL docscan; `oversized` (>25MB) are too big to scan and are
    REPORTED to the user. T3.2: their ADDED lines now ride the segmented docs scan (bounded chunk budget); the pattern floor still skips the >25MB blob (the OLD claim 'NO layer covers them' retired - gate round gate_20261009-041145).
    docs model both skip >25MB, and docs are never sent to the external reviewer)."""
    scannable, oversized = [], []
    for f in _all_staged_files():
        if _is_code(f) and os.path.splitext(f)[1].lower() not in DOCSCAN_EXTS:
            continue          # reviewer-only code; DOCSCAN_EXTS code ALSO docscanned
        try:
            blob = _run_git(["show", ":" + f], binary=True)
        except SystemExit:
            continue
        if bytes([0]) in blob[:8192]:            # binary
            continue
        (oversized if len(blob) > 25_000_000 else scannable).append(f)
    return scannable, oversized


def _staged_doc_added_text(files):
    """The ADDED lines this commit introduces to `files` (the '+' hunk lines), concatenated -
    the new doc content to scan locally. Splits on newlines only (exotic vertical-tab /
    line-separator chars stay in-line, not dropped), uses :(literal) pathspecs so a filename
    with glob chars is not silently missed, and drops ONLY the exact diff headers so a content
    line like '++x' is still kept."""
    if not files:
        return ""
    # --text: a .gitattributes -diff/binary attribute must not blind docscan either (the
    # attribute file is ungated; selftest 24c). textconv/relative are pinned off as well.
    # --no-color / --no-ext-diff (EV-031, caught by the gate reviewing its own distributed
    # copy): `color.diff=always` paints ANSI on a pipe so no line starts with '+', and a
    # GIT_EXTERNAL_DIFF / diff.external driver replaces the diff entirely - either way the docs
    # scan received nothing and passed silently. The code feed already pinned both.
    out = _diff_paths(["-c", "core.quotepath=false", "diff", "--cached", "--unified=0",
                       "--text", "--no-color", "--no-ext-diff", "--no-textconv",
                       "--no-relative"], files)
    headers = {"+++ /dev/null"} | {"+++ b/" + f for f in files}
    added = [ln[1:] for ln in out.split("\n")
             if ln.startswith("+") and ln not in headers]
    return "\n".join(added)


def _adv_dir(root):
    d = os.path.join(root, ".adversary")
    os.makedirs(os.path.join(d, "reviews"), exist_ok=True)
    return d


def _load_clear(root):
    p = os.path.join(_adv_dir(root), "clearance.json")
    if os.path.isfile(p):
        try:
            return json.loads(open(p, encoding="utf-8").read())
        except ValueError:
            return {}
    return {}


def _save_json(root, name, data):
    p = os.path.join(_adv_dir(root), name)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1)
        f.flush(); os.fsync(f.fileno())
    os.replace(tmp, p)


def _save_clear(root, data):
    _save_json(root, "clearance.json", data)


def _git_ok(args):
    """True iff the git command succeeds - for existence probes where failure is an answer.
    Replace refs are ignored like in _run_git: a local `git replace` must not steer a parent
    probe (gate catch gate_20260907-172339)."""
    env = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1")
    return subprocess.run([GIT] + args, capture_output=True, env=env).returncode == 0


def _profile_temp_dirs():
    """The OS temp locations a test harness puts throwaway repos in, resolved WITHOUT reading
    environment variables (TMPDIR/TEMP would let a committer reclassify a real checkout as a
    fixture - the docket-gate refutation of the first EV-045 proposal). Windows: the
    LocalAppData known folder + \\Temp (SHGetKnownFolderPath); POSIX: /tmp and /var/tmp."""
    if os.name == "nt":
        try:
            import ctypes
            # FOLDERID_LocalAppData {F1B32785-6FBA-4FCF-9D55-7B8E7F157091} in GUID byte order
            fid = ctypes.c_char_p(bytes.fromhex("8527B3F1BA6FCF4F9D557B8E7F157091"))
            out = ctypes.c_wchar_p()
            if ctypes.windll.shell32.SHGetKnownFolderPath(fid, 0, None, ctypes.byref(out)) == 0:
                p = out.value
                ctypes.windll.ole32.CoTaskMemFree(out)
                if p:
                    return [os.path.join(p, "Temp")]
        except Exception:
            pass
        # no silent degradation: the gate keeps running everywhere (safe direction), say so
        sys.stderr.write("adversary gate: profile Temp folder could not be resolved - fixture "
                         "repos are NOT skipped this run.\n")
        return []
    return ["/tmp", "/var/tmp"]


def _git_common_dir_abs():
    try:
        d = _run_git(["rev-parse", "--path-format=absolute", "--git-common-dir"]).strip()
    except SystemExit:
        return ""
    return os.path.normcase(os.path.realpath(d)) if d else ""


def _fixture_repo():
    """EV-045 (owner ruling 2026-09-07): a repository whose git dir lives under the profile
    Temp is a test fixture - the pre-commit review is skipped there (no refusal, no model, no
    note). Pre-push still runs everywhere, so nothing pushed from such a repo escapes the
    audit. Disabled under ADVERSARY_SELFTEST=1 (a stricter-only knob) so the selftests' own
    temp repos stay gated."""
    if os.environ.get("ADVERSARY_SELFTEST") == "1":
        return False
    common = _git_common_dir_abs()
    if not common:
        return False
    for t in _profile_temp_dirs():
        t = os.path.normcase(os.path.realpath(t))
        try:
            if os.path.commonpath([t, common]) == t:
                return True
        except ValueError:
            continue
    return False


def cmd_check(auto_review=False):
    if _fixture_repo():
        sys.stderr.write("adversary gate: repository under the profile Temp dir - pre-commit "
                         "review skipped (EV-045, owner ruling 2026-09-07); the push guard "
                         "still audits anything pushed from it.\n")
        return 0
    root = _repo_root()
    _warn_flagged_audits(root)
    files = _staged_code_files()   # merges are NOT exempt: a merge can carry un-gated
    # commits (adversary finding, gate birth review 2026-08-30) - the staged result is
    # reviewable like any other change
    removals = _staged_removals()
    ov = os.path.join(_adv_dir(root), "OVERRIDE")
    override = os.path.isfile(ov)
    # LOCAL secret pre-scan - the ADDED lines of ALL staged files (any extension). It WARNS
    # (owner ruling 2026-09-07): nothing blocks here, the OVERRIDE is not involved, and the
    # review payload is scrubbed before it leaves the machine.
    secret_hits = _scan_staged_secrets()
    if secret_hits:
        _print_secret_warning(secret_hits, sys.stderr, "commit-time pattern floor")
    # DOCS half of the domain division (2026-09-03): staged doc files' ADDED content is
    # reviewed by the LOCAL model (docscan), ON-MACHINE, never sent to the external reviewer.
    # It catches prose / dictionary-word secrets the pattern floor misses. Runs EVEN under
    # OVERRIDE - so a real block is distinguished from a clean commit and the one-shot hatch
    # is consumed only when it truly bypassed a block. Graceful-degrade (loud); never crashes
    # the hook; never a silent pass.
    doc_files, oversized_docs = _staged_doc_files()
    # T3.2 / H2: oversized docs JOIN the semantic scan - the old blob-size split
    # wrongly excluded a >25MB file whose ADDED text was small, and one scan()
    # call caps at 24x6000 chars; scan_segmented covers any size at line bounds.
    for f in oversized_docs:
        sys.stderr.write("adversary gate: doc %s is >25MB - its ADDED lines now ride the "
                         "segmented docs scan (the untracked bulk is not new content).\n" % f)
    if doc_files or oversized_docs:   # T3.2: oversized-only stages scan too (gate round
                                       # gate_20261009-040408: the old doc_files-only guard
                                       # skipped them while the new warning printed anyway)
        # T4.4 (owner order 2026-10-09): version-keyed CLEAR cache - same added
        # text + same model fingerprint + same rules epoch = same clear verdict;
        # block/degraded NEVER cache (they must re-run and stay diagnosable).
        # The ENTIRE block stays inside the try (gate round gate_20261009-080737:
        # hoisting the text computation out broke the "docs layer must NEVER
        # crash the hook" guarantee - _staged_doc_added_text raises SystemExit
        # on git failure and must degrade, not kill cmd_check).
        try:
            _dc_text = _staged_doc_added_text(doc_files + oversized_docs)
            _dc_res = _docscan_cache_lookup(root, _dc_text)
            if _dc_res is not None:
                res = _dc_res
            else:
                res = (docscan.scan_segmented(_dc_text) if docscan
                       else {"status": "degraded", "detail": "docscan module unavailable"})
                _docscan_cache_store(root, _dc_text, res)
        except (Exception, SystemExit) as e:     # incl. _run_git's SystemExit on git failure -
            # the docs layer must NEVER crash the hook: a too-long pathspec / git error /
            # docscan bug degrades loudly (pattern floor + code gate still enforce).
            res = {"status": "degraded", "detail": "docs scan crashed: %s" % (str(e)[:150])}
        if res["status"] == "block":
            sys.stderr.write("\nADVERSARY GATE: WARNING - the local docs reviewer flagged "
                             "possible secret material in staged documentation (%s). Values "
                             "are not printed and the commit is NOT blocked (owner ruling "
                             "2026-09-07); the push guard re-runs the docs reviewer over "
                             "outgoing docs and refuses the push on a block.\n\n"
                             % res.get("detail", ""))
        elif res["status"] == "degraded":
            sys.stderr.write("adversary gate: docs SEMANTIC review SKIPPED (%s) - the pattern "
                             "floor ran, but a prose/dictionary-word secret could pass. Install "
                             "a local model to enable it.\n" % res.get("detail", ""))
        elif res.get("capped"):
            sys.stderr.write("adversary gate: docs scan CAPPED (%s) - the tail was NOT "
                             "semantically scanned.\n" % res.get("detail", ""))
    # Secrets and docs blocks never block a commit any more (owner ruling 2026-09-07), so the
    # OVERRIDE is only ever consumed by a CODE-clearance bypass below; a docs-only commit -
    # clean or warned - leaves the owner's one-shot hatch untouched.
    if not files and not removals:
        return 0                                          # docs/manifests pass free
    if override:
        reason = open(ov, encoding="utf-8", errors="replace").read().strip()
        sys.stderr.write("\n!!! ADVERSARY GATE OVERRIDDEN (one-shot) !!!\nreason on file: %s\n"
                         "This is auditable. Using it without the owner's say-so is a "
                         "protocol violation.\n\n" % (reason[:300] or "(none given)"))
        # provenance for the tripwire: `record` converts this into an OVERRIDE note only
        # while HEAD carries these exact blobs - a lingering file cannot bless a later commit
        staged = {f: _staged_sha(f) for f in files}
        staged.update(removals)
        _save_json(root, "override_used.json",
                   {"reason": reason[:2000],
                    "when": datetime.datetime.now().strftime("%Y%m%d-%H%M%S"),
                    "staged": staged})
        os.remove(ov)
        return 0
    clear = _load_clear(root)
    epoch_now = _current_rules_epoch(root)   # H4: clearances are epoch-bound
    bad = []
    for f in files:
        sha = _staged_sha(f)
        row = clear.get(f)
        if not row or row.get("sha") != sha or row.get("verdict") not in ("CLEAR", "WARN"):
            bad.append((f, "stale" if row else "unreviewed"))
        elif str(row.get("epoch", "0")) != epoch_now:
            bad.append((f, "stale (rules epoch advanced - re-review under current rules)"))
    for key, sha in removals.items():
        row = clear.get(key)
        if not row or row.get("sha") != sha or row.get("verdict") not in ("CLEAR", "WARN"):
            bad.append((key, "stale" if row else "unreviewed (code removal)"))
        elif str(row.get("epoch", "0")) != epoch_now:
            bad.append((key, "stale (rules epoch advanced - re-review under current rules)"))
    if not bad:
        return 0
    if auto_review:
        print("ADVERSARY GATE: requesting automatic independent review of staged changes.",
              file=sys.stderr, flush=True)
        result = cmd_run(DEFAULT_MODEL, "")
        if result != 0:
            return result
        # Never loop/retry after BLOCK or staging drift; recheck the caller's real index.
        return cmd_check()
    sys.stderr.write("\nADVERSARY GATE: commit REFUSED - staged code lacks a fresh "
                     "adversarial clearance:\n")
    for f, why in bad:
        sys.stderr.write("  %-60s %s\n" % (f, why))
    sys.stderr.write("\nRun the adversary, address its findings, then commit:\n"
                     "  python %s run\n"
                     "(re-editing a file after clearance invalidates it by design)\n\n"
                     % os.path.abspath(__file__))
    return 1


def _review_outcome(text):
    """Only a single, final, exact verdict can authorize; conflicts are terminal."""
    lines = [line.strip().upper() for line in text.rstrip().splitlines()]
    markers = [line for line in lines if re.match(r"VERDICT\s*:", line)]
    if not markers:
        return "incomplete"
    final = lines[-1]
    if len(markers) == 1 and final in {"VERDICT: CLEAR", "VERDICT: BLOCK", "VERDICT: WARN"}:
        return final.split(": ")[1]
    return "malformed"


class IncompleteReviewResponse(SystemExit):
    """Provider completion metadata says the response is not a finished review."""
    def __init__(self, text, provider):
        super().__init__("Independent review response incomplete")
        self.text = text
        self.provider = provider


def _completion_guard(text, unfinished, provider):
    # Even a provider-truncated BLOCK is not a reason to shop for CLEAR.
    if unfinished and _review_outcome(text) not in {"BLOCK", "malformed"}:
        raise IncompleteReviewResponse(text, provider)


def _review_attempt(attempts, model, provider, outcome, text=None, error=None):
    def label(value):
        return _scrub_text(str(value))[0][:160] if value is not None else None
    record = {"model": label(model), "provider": label(provider), "outcome": outcome}
    if text is not None:
        raw = text.encode("utf-8", "surrogatepass")
        record.update(response_sha256=hashlib.sha256(raw).hexdigest(), response_bytes=len(raw))
    if error is not None:
        record["error_type"] = type(error).__name__  # never echo provider bodies/credentials
        message = str(error)
        status = re.search(r"HTTP (\d{3})\b", message)
        if status:
            record.update(failure_kind="http", http_status=int(status[1]))
        elif "network/read error" in message:
            record["failure_kind"] = "transport"
        elif "not set" in message or "key unavailable" in message:
            record["failure_kind"] = "credentials"
        elif "unreadable" in message or "invalid" in message:
            record["failure_kind"] = "parse"
        else:
            record["failure_kind"] = "provider_or_configuration"
    attempts.append(record)
    sys.stderr.write("adversary review attempt: " + json.dumps(record) + "\n")


class BatchReviewPending(SystemExit):
    """A paid batch is still pending; resume it rather than paying a fallback."""


def _call_model(model, user_content, timeout=1200, *, attempts=None):
    """Compatibility API: (text, usage, model_used); optional caller-owned attempt log."""
    return _call_model_ex(model, user_content, timeout, attempts=attempts)[:3]


def _call_model_ex(model, user_content, timeout=1200, *, attempts=None):
    """Return (text, usage, model_used, provider); incomplete reviews advance the chain."""
    chain = [m.strip() for m in model.split(",") if m.strip()]
    if not chain:
        raise SystemExit("ADVERSARY GATE: no model given (empty --model / ADVERSARY_MODEL)")
    history = attempts if attempts is not None else []
    for m in chain:
        try:
            text, usage, provider = _call_one_model(m, user_content, timeout)
        except BatchReviewPending as exc:
            _review_attempt(history, m, None, "pending", error=exc)
            raise
        except IncompleteReviewResponse as exc:
            _review_attempt(history, m, exc.provider, "incomplete", text=exc.text)
            continue
        except SystemExit as exc:
            _review_attempt(history, m, None, "provider_error", error=exc)
            continue
        outcome = _review_outcome(text)
        _review_attempt(history, m, provider, outcome, text=text)
        if outcome == "incomplete":
            continue
        # CLEAR, BLOCK, or malformed/conflicting verdict: terminal, never verdict shopping.
        return text, usage, m, provider
    raise SystemExit("ADVERSARY GATE: configured reviewers exhausted without a complete verdict")


def _split_entry(entry):
    """One chain entry -> (model, provider order). `model@tag1+tag2` pins the OpenRouter endpoints
    that may serve the call, in that order, fallbacks off (owner ruling 2026-09-16); a bare entry
    pins nothing. An empty pin (`model@`) fails closed: never sent as an empty order."""
    model, at, pins = entry.partition("@")
    order = [p.strip() for p in pins.split("+") if p.strip()]
    if at and not order:
        raise SystemExit("ADVERSARY GATE: empty provider pin in chain entry %r" % entry)
    return model.strip(), order


# ---- Workload routing (owner order 2026-09-23, typesafe/jev-1.13 workflow) ---------------
# Legacy routing is opt-in (ADVERSARY_PROMOTE_OFF=0) as of 2026-09-26.
# The default preserves the owner-selected primary/secondary for every workload.
# WHEN deepseek leads: the deterministic floor below needs no key and no network -
# it promotes the deepseek-v4-pro-0813 rung to PRIMARY for cache-heavy workloads
# (payload >= ADVERSARY_PROMOTE_MIN_CHARS: those pins are the measured cache-readers,
# fleet_probe 2026-09-23 2560/2699-token readbacks; or a rebuttal round: the
# stable-first payload prefix repeats, so cached input is the cheap input). Jev
# (typesafe/jev-1.13, a TYPED-DECISION model - it returns choices/probabilities,
# never text) refines the gray zone the rule does not decide, over workload
# METRICS ONLY. Jev's action space is bounded to reordering rungs already in the
# chain: it can never demote the deterministic rule, forge a verdict, influence
# the secret scanners or the push guard. Every failure path is fail-open.
PROMOTE_TARGET = "deepseek/deepseek-v4-pro-0813"
PROMOTE_MIN_CHARS = 40_000        # ~10k tokens; above this the input-cache discount on
                                  # the deepseek pins informed the legacy routing threshold
# Jev rides the OpenRouter DECISIONS API (owner-supplied endpoint, corroborated by
# the openrouter SDK's openrouter.alpha.decisions namespace; wire contract
# LIVE-verified 2026-09-23: POST /api/alpha/decisions with the UNWRAPPED
# {model, state, questions} body, criteria-shaped questions, answers.<qid> =
# {type, choice, probabilities, confidence}; $0.042/M input, $0/M output, ~$0.00002
# per consult) and authenticates with the gate's OWN OPENROUTER_API_KEY - no
# separate TypeSafe key exists or is needed.
JEV_API_URL = "https://openrouter.ai/api/alpha/decisions"
JEV_MODEL = os.environ.get("ADVERSARY_JEV_MODEL", "typesafe/jev-1.13")


def _promote_entry(chain_list, target_model):
    """Reorder `chain_list` so the entry whose pin-stripped model is `target_model`
    leads; every other rung keeps its relative order. Pure - returns a NEW list;
    an absent target returns the list unchanged (copied)."""
    hit = next((e for e in chain_list if _split_entry(e)[0] == target_model), None)
    if hit is None:
        return list(chain_list)
    return [hit] + [e for e in chain_list if e != hit]


def _jev_request_body(state):
    """The Decisions API request for one routing consult - factored so the wire
    contract is unit-pinned against the live-verified shape (2026-09-23):
    unwrapped {model, state, questions}; the question is criteria-shaped (the
    options ARE the criteria map keys)."""
    return {"model": JEV_MODEL, "state": state,
            "questions": {"promote_deepseek": {
                "type": "choice",
                "instructions": "Pick which reviewer rung leads this pre-commit review.",
                "criteria": {
                    "default_order": "Luna Pro first - the owner-selected default primary",
                    "deepseek_first": "deepseek first - the large/repeat prefix rides its "
                                      "cache-capable pins"}}}}


def _jev_parse_answer(d):
    """Normalize one Decisions API response to {"choice", "probabilities",
    "confidence"} or None - None on any shape other than the live-verified one
    carrying an in-vocabulary choice (fail-open, never a guess)."""
    if not isinstance(d, dict):
        return None
    answers = d.get("answers")
    if not isinstance(answers, dict):
        return None
    ans = answers.get("promote_deepseek")
    if not (isinstance(ans, dict) and ans.get("choice") in ("default_order", "deepseek_first")):
        return None
    probs = ans.get("probabilities")
    return {"choice": ans["choice"],
            "probabilities": dict(probs) if isinstance(probs, dict) else {},
            "confidence": ans.get("confidence")}


def _jev_decide(payload_chars, rebuttal, rungs):
    """One typed-decision consult with typesafe/jev-1.13 via the OpenRouter
    DECISIONS API (POST /api/alpha/decisions, Bearer OPENROUTER_API_KEY - the
    gate's own key; wire contract LIVE-verified 2026-09-23). One CHOICE question
    over workload METRICS ONLY - size, rebuttal flag, rung count; NO staged byte
    ever leaves the machine. Returns the normalized answer dict or None on absent
    key, kill switch, any error or any unrecognized shape - the caller then falls
    back to the deterministic rule (fail-open). ADVERSARY_JEV_OFF=1 skips the
    consult entirely. Under ADVERSARY_SELFTEST=1 the ONLY thing ever served is
    ADVERSARY_JEV_FAKE (a canned answers map, parsed by the same normalizer) -
    a selftest stays hermetic even on a machine holding a real key, and the
    fake can only pick a routing preference between rungs already in the
    chain, never a verdict."""
    if os.environ.get("ADVERSARY_JEV_OFF") == "1":
        return None
    if os.environ.get("ADVERSARY_SELFTEST") == "1":
        fake = os.environ.get("ADVERSARY_JEV_FAKE", "")
        if not fake:
            return None
        try:
            return _jev_parse_answer({"answers": json.loads(fake)})
        except (ValueError, TypeError):
            return None
    key = os.environ.get("OPENROUTER_API_KEY", "").strip()
    if not key:
        return None
    state = ("pre-commit adversarial review routing. payload_chars=%d rebuttal_round=%s "
             "chain_rungs=%d promote_threshold_chars=%s default_primary=deepseek/deepseek-v4-pro-0813 "
             "candidate_primary=deepseek/deepseek-v4-pro-0813 candidate_rationale=the "
             "deepseek pins have measured prompt-cache reads; promote only when the "
             "cache/cost tradeoff favors deepseek-first for "
             "this workload."
             % (payload_chars, "yes" if rebuttal else "no", rungs,
                os.environ.get("ADVERSARY_PROMOTE_MIN_CHARS", str(PROMOTE_MIN_CHARS))))
    try:
        req = urllib.request.Request(
            JEV_API_URL, data=json.dumps(_jev_request_body(state)).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": "Bearer " + key,
                     "HTTP-Referer": "https://nexusmill.com",
                     "X-Title": "Nexusmill adversary-gate"}, method="POST")
        with urllib.request.urlopen(req, timeout=8) as r:
            d = json.loads(r.read().decode("utf-8"))
        ans = _jev_parse_answer(d)
        if ans is not None:
            sys.stderr.write("adversary routing: jev consult -> %s (confidence %s)\n"
                             % (ans["choice"], ans.get("confidence")))
        return ans
    except (OSError, ValueError, http.client.HTTPException) as e:
        sys.stderr.write("adversary routing: jev consult failed-open (%s) - the "
                         "deterministic rule decides.\n" % type(e).__name__)
        return None


def _route_chain(model, payload, context):
    """The workload router. Returns (chain, why): the chain string to review with
    and the reason it was chosen. An explicit --model / ADVERSARY_MODEL override
    is returned VERBATIM ('manual') - routing only ever reorders the DEFAULT
    chain. Deterministic floor (no network, no key): promote the
    deepseek-v4-pro-0813 rung to primary when the workload is cache-heavy -
    payload >= ADVERSARY_PROMOTE_MIN_CHARS or a rebuttal round. Jev is consulted
    ONLY in the gray zone the rule does not already decide, and may only ADD a
    promotion - never demote one. Routing is OFF by default to honor the owner's
    fixed primary/secondary. ADVERSARY_PROMOTE_OFF=0 opts into legacy routing."""
    if model != DEFAULT_CHAIN:
        return model, "manual"
    if os.environ.get("ADVERSARY_PROMOTE_OFF", "1") == "1":
        return model, "off"
    entries = [m.strip() for m in model.split(",") if m.strip()]
    promoted = _promote_entry(entries, PROMOTE_TARGET)
    if promoted == entries:
        return model, "default"           # target absent: nothing to route
    try:
        min_chars = int(os.environ.get("ADVERSARY_PROMOTE_MIN_CHARS",
                                       str(PROMOTE_MIN_CHARS)))
    except ValueError:
        min_chars = PROMOTE_MIN_CHARS
    size = len(payload)
    if size >= min_chars or context.strip():
        return ",".join(promoted), "rule"
    ans = _jev_decide(size, bool(context.strip()), len(entries))
    if ans and ans.get("choice") == "deepseek_first":
        return ",".join(promoted), "jev"
    return model, "default"


def _output_token_budget(user_content):
    """R3 (owner order 2026-10-08): the output ceiling DERIVED FROM PAYLOAD
    SIZE - floor + a fixed share of the payload's estimated tokens, hard-capped
    so a runaway composition bug still cannot bill unbounded output. Only the
    VARIABLE payload counts (the system prompt is constant; counting it would
    lift even an empty payload above the floor). A flat cap starves reasoning
    reviewers on big payloads: live 2026-10-08, every tier-2 rung hit
    finish_reason=length with 100% reasoning tokens and zero content at flat
    2000 (and 8000, and 16000) on a 132,486-token review."""
    payload_tokens = len(user_content) // 4
    budget = MAX_OUTPUT_TOKENS + payload_tokens * OUTPUT_TOKENS_PER_INPUT_PCT // 100
    return min(budget, MAX_OUTPUT_TOKENS_CAP)


def _call_one_model(entry, user_content, timeout=1200):
    fake = os.environ.get("ADVERSARY_FAKE")               # selftests only - no network
    if fake:
        root = os.path.basename(_repo_root())
        if root.startswith("advgate_") and os.environ.get("ADVERSARY_SELFTEST") == "1":
            # sequence mode (owner order 2026-10-08, tiering selftests): "BLOCK,CLEAR"
            # consumes one verdict per model call, repeating the last element; optional
            # ADVERSARY_FAKE_BODY prepends findings prose (WARN-tier tests).
            global _FAKE_CALLS
            seq = [p.strip() for p in fake.split(",") if p.strip()] or [fake]
            verdict = seq[min(_FAKE_CALLS, len(seq) - 1)]
            _FAKE_CALLS += 1
            body = os.environ.get("ADVERSARY_FAKE_BODY", "").strip()
            head = "(faked verdict for selftest)\n" + (body + "\n" if body else "")
            if verdict == "ERROR":                     # faked provider death (tiering
                raise SystemExit("ADVERSARY FAKE: faked provider death for selftest")
            return (head + "VERDICT: %s" % verdict), {}, "fake"
        sys.stderr.write("ADVERSARY_FAKE ignored outside a selftest repo (adversary "
                         "finding, birth review r2) - running the REAL reviewer.\n")
    model, order = _split_entry(entry)
    if model.startswith("xai:"):                          # xAI-native backup (grok): a
        if order:                                         # different API + key; no provider
            raise SystemExit("ADVERSARY GATE: provider pins apply to OpenRouter entries only "
                             "(%r routes to api.x.ai)" % entry)   # routing there - a pin would be a lie
        return _call_xai(model[len("xai:"):], user_content, timeout)
    if model.startswith("local:"):                        # local rung (owner order 2026-09-30):
        if order:                                         # an Ollama-compatible endpoint, same
            raise SystemExit("ADVERSARY GATE: provider pins apply to OpenRouter entries only "
                             "(%r routes to the local endpoint)" % entry)   # shape - a pin would be a lie
        return _call_local(model[len("local:"):], user_content, timeout)
    key = os.environ.get("OPENROUTER_API_KEY", "").strip()
    if not key:
        raise SystemExit("ADVERSARY GATE: OPENROUTER_API_KEY not set - the gate cannot run. "
                         "(Owner emergencies: see the OVERRIDE escape in the tool docstring.)")
    if model.endswith(":batch"):
        if order:
            raise SystemExit("ADVERSARY GATE: batch reviews use the batch model route without interactive pins")
        try:
            return _call_batch_model(model, user_content, key, timeout=timeout)
        except (OSError, http.client.HTTPException, ValueError, TypeError, KeyError) as exc:
            raise SystemExit("ADVERSARY GATE: batch transport failed closed; saved jobs retained: " + str(exc))
    body = {"model": model, "temperature": 0.2, "max_tokens": _output_token_budget(user_content),
            "messages": [{"role": "system", "content": PROMPT},
                         {"role": "user", "content": user_content}]}
    if order:
        body["provider"] = {"order": order, "allow_fallbacks": False}
    req = urllib.request.Request(
        API_URL, data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + key,
                 "HTTP-Referer": "https://nexusmill.com", "X-Title": "Nexusmill adversary-gate"},
        method="POST")
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read()
            try:
                d = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError) as je:
                # a 200 with a non-JSON / undecodable body (proxy interstitial, HTML error
                # page, truncated stream) must FAIL CLOSED as SystemExit so the fallback
                # chain advances - not crash cmd_run with a raw traceback (chain review r4).
                raise SystemExit("ADVERSARY GATE: unreadable model response (%s): %s"
                                 % (type(je).__name__, raw.decode("utf-8", "replace")[:200]))
            break
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < 3:
                sys.stderr.write("adversary model 429 - retry %d/3 in 30s\n" % (attempt + 1))
                time.sleep(30)
                continue
            raise SystemExit("ADVERSARY GATE: OpenRouter HTTP %s: %s"
                             % (e.code, e.read().decode("utf-8", "replace")[:300]))
        except (OSError, http.client.HTTPException) as e:
            # connection refused / DNS / TLS / a MID-STREAM read timeout or socket reset -
            # the canonical transport failures. Catch OSError (not just urllib URLError): a
            # bare TimeoutError from r.read() is an OSError, NOT a URLError, so the old
            # handler let it crash cmd_run with a traceback (surfaced on a large docs-build
            # review). http.client.HTTPException is the OTHER family r.read() raises - a
            # truncated chunked body is IncompleteRead, which is NOT an OSError and crashed
            # a live gate run with a raw traceback (fleet unit-2 round 1, 2026-09-15).
            # SystemExit fails CLOSED and advances the fallback chain. HTTPError is handled
            # above (it subclasses OSError) so its 429 retry is unaffected.
            raise SystemExit("ADVERSARY GATE: network/read error reaching OpenRouter: %r"
                             % (getattr(e, "reason", e),))
    return _parse_completion(d)


def _call_batch_model(model, user_content, key, transport=None, sleep=time.sleep,
                      timeout=1200, clock=time.monotonic):
    """Use the existing batch API; persist the paid job before waiting for its verdict."""
    suite = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if suite not in sys.path:
        sys.path.insert(0, suite)
    from autoland.scan_queue import LiveBatchTransport
    tx = transport or LiveBatchTransport()
    deadline = clock() + timeout
    body = {"endpoint": "/v1/chat/completions", "model": model,
            "requests": [{"custom_id": "scan", "body": {"temperature": 0.2,
                "max_tokens": _output_token_budget(user_content),
                "messages": [{"role": "system", "content": PROMPT},
                             {"role": "user", "content": user_content}]}}]}
    raw = json.dumps(body).encode("utf-8")
    request_sha = hashlib.sha256(raw).hexdigest()
    root = _repo_root()
    receipt_name = "batch-review-" + request_sha + ".json"
    receipt_path = os.path.join(_adv_dir(root), receipt_name)
    adv = _adv_dir(root)
    fd = _adv_lock(adv, receipt_name, deadline_s=min(30, timeout))
    if fd is None:
        raise BatchReviewPending("ADVERSARY GATE: exact batch submission is busy; retry without fallback")
    try:
        receipt = {}
        if os.path.isfile(receipt_path):
            with open(receipt_path, encoding="utf-8") as stream:
                receipt = json.load(stream)
            if receipt.get("request_sha256") != request_sha or receipt.get("model") != model:
                raise SystemExit("ADVERSARY GATE: batch receipt does not match exact review input")
        batch_id = receipt.get("batch_id")
        if receipt and not batch_id and receipt.get("submission") != "rejected":
            raise BatchReviewPending("ADVERSARY GATE: ambiguous paid submission; reconcile provider job before resubmitting exact input " + request_sha)
        if not batch_id:
            intent = {"request_sha256": request_sha, "model": model,
                      "batch_id": None, "submission": "in_flight"}
            _save_json(root, receipt_name, intent)  # Durable BEFORE the acceptance window.
            try:
                job = tx._req("POST", "https://openrouter.ai/api/v1/batches", key, raw)
            except urllib.error.HTTPError as exc:
                if exc.code in {400, 401, 403, 404, 422, 429}:
                    try:
                        _save_json(root, receipt_name, dict(intent, submission="rejected"))
                    except Exception:
                        raise BatchReviewPending("ADVERSARY GATE: submission receipt could not be updated; reconcile saved intent")
                    raise SystemExit("ADVERSARY GATE: batch submission rejected (HTTP %d)" % exc.code)
                raise BatchReviewPending("ADVERSARY GATE: ambiguous submission response; saved intent requires reconciliation")
            except Exception:
                raise BatchReviewPending("ADVERSARY GATE: submission response lost; saved intent prevents duplicate fallback")
            if not isinstance(job, dict):
                raise BatchReviewPending("ADVERSARY GATE: submission response is not an object; reconcile saved intent before resubmitting")
            batch_id = job.get("id")
            if not isinstance(batch_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", batch_id):
                raise BatchReviewPending("ADVERSARY GATE: accepted response has no valid job ID; reconcile saved intent")
            try:
                _save_json(root, receipt_name, {"request_sha256": request_sha,
                                               "model": model, "batch_id": batch_id})
            except Exception:
                raise BatchReviewPending("ADVERSARY GATE: accepted job %s could not be persisted; reconcile saved intent" % batch_id)
    finally:
        _adv_unlock(adv, receipt_name, fd)
    if not isinstance(batch_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", batch_id):
        raise SystemExit("ADVERSARY GATE: invalid saved batch job ID")
    def progress(message):
        try:
            # stdout belongs to JSON-RPC when this reviewer runs inside MCP.
            print(message, flush=True, file=sys.stderr)
        except OSError:
            raise BatchReviewPending("ADVERSARY GATE: output unavailable; resume saved batch %s without fallback" % batch_id)
    progress("adversary batch review: %s via %s (exact input %s)" %
             (batch_id, model, request_sha))
    previous = None
    not_found_retries = 0
    while True:
        remaining = deadline - clock()
        if remaining <= 0:
            raise BatchReviewPending("ADVERSARY GATE: batch %s still pending; resume the same exact input (no fallback submitted)" % batch_id)
        try:
            state = str(tx.status(batch_id, key)).lower()
        except urllib.error.HTTPError as exc:
            if exc.code == 404 and not_found_retries < 8:
                not_found_retries += 1
                sleep(min(15, remaining))  # A newly accepted batch may not yet reach the status replica.
                continue
            if exc.code != 429 and exc.code < 500:
                raise BatchReviewPending("ADVERSARY GATE: batch status refused (HTTP %d); resume saved job without fallback" % exc.code)
            sleep(min(15, remaining))
            continue
        except (OSError, http.client.HTTPException):
            sleep(min(15, remaining))
            continue  # Keep the paid job; never resubmit on a transient polling failure.
        except Exception:
            raise BatchReviewPending("ADVERSARY GATE: batch status response is unusable; resume saved job without fallback")
        if state != previous:
            progress("adversary batch status: " + state)
            previous = state
        if state == "completed":
            try:
                output = tx.fetch(batch_id, key)
            except (OSError, http.client.HTTPException):
                raise BatchReviewPending("ADVERSARY GATE: completed batch fetch failed; resume saved job without fallback")
            if not isinstance(output, str):
                raise SystemExit("ADVERSARY GATE: batch output must be JSONL text")
            try:
                records = [json.loads(line) for line in output.splitlines() if line.strip()]
            except (TypeError, ValueError):
                raise SystemExit("ADVERSARY GATE: batch output contains invalid JSON")
            if len(records) != 1 or not isinstance(records[0], dict) or records[0].get("custom_id") != "scan":
                raise SystemExit("ADVERSARY GATE: batch output does not identify the single exact review request")
            response = records[0].get("response") or {}
            if not isinstance(response, dict):
                raise SystemExit("ADVERSARY GATE: batch output response must be an object")
            if response.get("status_code", 200) != 200:
                raise SystemExit("ADVERSARY GATE: batch review returned an error response")
            return _parse_completion(response.get("body"))
        if state in {"failed", "expired", "cancelled"}:
            raise SystemExit("ADVERSARY GATE: batch review failed closed with state " + state)
        if state not in {"validating", "validation", "queued", "in_progress", "finalizing", "cancelling"}:
            raise BatchReviewPending("ADVERSARY GATE: unknown batch status; resume saved job without fallback")
        sleep(min(15, remaining))


def _parse_completion(d):
    """Parse one OpenRouter completion, preserving usage/provider and completion state."""
    if not isinstance(d, dict) or d.get("error"):
        raise SystemExit("ADVERSARY GATE: invalid/provider-error model response")
    choices = d.get("choices") or []
    if not isinstance(choices, list):
        raise SystemExit("ADVERSARY GATE: invalid completion choices")
    texts = []
    unfinished = len(choices) > 1  # alternatives must not be concatenated into one verdict
    for choice in choices:
        if not isinstance(choice, dict) or not isinstance(choice.get("message"), dict):
            raise SystemExit("ADVERSARY GATE: invalid completion message")
        message = choice["message"]
        content = message.get("content") or ""
        if not isinstance(content, str):
            raise SystemExit("ADVERSARY GATE: invalid completion content")
        texts.append(content)
        unfinished |= (choice.get("finish_reason") not in (None, "stop")
                       or bool(message.get("tool_calls")) or bool(message.get("function_call")))
    text = "\n".join(texts)
    _completion_guard(text, unfinished, d.get("provider"))
    return text, d.get("usage", {}), d.get("provider")


def _caller():
    """The CALLING AGENT identity stamped into every review artifact and notary
    note (owner order 2026-09-23: per-agent error rates require knowing who
    triggered each scan). Explicit ADVERSARY_CALLER wins; then the canonical
    harness markers - CLAUDECODE=1 (Claude Code; NOT the CLAUDE_CODE_* vars,
    which ZCode's tooling also sets), ZCODE_APP_VERSION (ZCode), CODEX_HOME
    (Codex) - else unknown. Old artifacts simply lack the field."""
    explicit = os.environ.get("ADVERSARY_CALLER", "").strip()
    if explicit:
        return urllib.parse.quote(explicit, safe="._-", errors="surrogatepass")
    if os.environ.get("CLAUDECODE") == "1":
        return "claude-code"
    if os.environ.get("ZCODE_APP_VERSION"):
        return "zcode"
    if os.environ.get("CODEX_HOME"):
        return "codex"
    return "unknown"


def _review_header(model, usage, provider, scrubbed_count, files):
    """The first line of every review artifact; `provider:` sits after `model:` so tools that read the model keep
    working and the provider is one field to the right. `caller:` rides the END
    of the line: every existing parser (model/provider/files regexes) is
    prefix-anchored and ignores the trailing field."""
    return "model: %s | provider: %s | usage: %s | scrubbed: %d | files: %s | caller: %s\n\n" % (
        model, provider, usage, scrubbed_count, files, _caller())


def _read_xai_key():
    """xAI key: env XAI_API_KEY, else `xaikey=` in the .env at NEXUSMILL_XAI_ENV (default the
    3DPrinting/.env, per grok_review.py). Never printed."""
    k = os.environ.get("XAI_API_KEY", "").strip()
    if k:
        return k
    envp = os.environ.get("NEXUSMILL_XAI_ENV", r"C:\Users\User\source\repos\3DPrinting\.env")
    try:
        for line in open(envp, encoding="utf-8-sig", errors="ignore").read().splitlines():
            s = line.strip()
            if s.startswith("xaikey") and "=" in s:
                return s.split("=", 1)[1].strip().strip('"').strip("'")
    except OSError:
        pass
    raise SystemExit("ADVERSARY GATE: xAI key not set (XAI_API_KEY, or xaikey in the .env) - "
                     "the grok backup cannot run.")


def _call_xai(model, user_content, timeout):
    """The xAI-native /v1/responses backup (grok). Different shape than OpenRouter chat: PROMPT
    goes in `instructions`, the payload in `input`, and the verdict text is walked out of the
    response tree as `output_text` (mirrors grok_review.py). Any HTTP/transport/parse failure
    -> SystemExit so _call_model's fallback advances; an empty walk -> "" which can never CLEAR
    (EV-004)."""
    key = _read_xai_key()
    body = {"model": model, "instructions": PROMPT, "temperature": 0.2,
            "reasoning": {"effort": "high"}, "stream": False,
            "max_output_tokens": _output_token_budget(user_content),
            "input": [{"role": "user", "content": user_content}]}
    req = urllib.request.Request(
        XAI_API_URL, data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + key},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
    except urllib.error.HTTPError as e:
        raise SystemExit("ADVERSARY GATE: xAI HTTP %s: %s"
                         % (e.code, e.read().decode("utf-8", "replace")[:300]))
    except (OSError, http.client.HTTPException) as e:   # IncompleteRead is not an OSError
        raise SystemExit("ADVERSARY GATE: network/read error reaching xAI: %r"
                         % (getattr(e, "reason", e),))
    try:
        d = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as je:
        raise SystemExit("ADVERSARY GATE: unreadable xAI response (%s): %s"
                         % (type(je).__name__, raw.decode("utf-8", "replace")[:200]))
    if isinstance(d, dict) and d.get("error"):
        raise SystemExit("ADVERSARY GATE: xAI model error: %s" % json.dumps(d["error"])[:300])
    texts = []
    unfinished = not isinstance(d, dict) or d.get("status") not in (None, "completed")

    def _walk(x):
        nonlocal unfinished
        if isinstance(x, dict):
            if str(x.get("type", "")).endswith("_call") or x.get("status") not in (None, "completed"):
                unfinished = True
            if x.get("type") == "output_text" and isinstance(x.get("text"), str):
                texts.append(x["text"])
            for v in x.values():
                _walk(v)
        elif isinstance(x, list):
            for v in x:
                _walk(v)
    _walk(d.get("output", d) if isinstance(d, dict) else d)
    text = "\n".join(texts)
    _completion_guard(text, unfinished, "xai")
    return text, (d.get("usage", {}) if isinstance(d, dict) else {}), "xai"


def _call_local(model, user_content, timeout):
    """The local rung (owner order 2026-09-30): an Ollama-compatible OpenAI endpoint on this
    machine. Same chat-completions request/response shape, so _parse_completion serves as-is;
    NO Authorization header - the OpenRouter key never rides a local socket, and the local
    server has no key to check. Connection refused / DNS / read errors fail CLOSED exactly
    like the OpenRouter transport (SystemExit advances the fallback chain), so a stopped
    Ollama can never wedge the gate. The URL is read per call so selftests and the replay
    harness can override ADVERSARY_LOCAL_URL after import."""
    _local_vram_guard(model)
    url = os.environ.get("ADVERSARY_LOCAL_URL") or LOCAL_API_URL_DEFAULT
    body = {"model": model, "temperature": 0.2,
            "max_tokens": _output_token_budget(user_content),
            "messages": [{"role": "system", "content": PROMPT},
                         {"role": "user", "content": user_content + LOCAL_FORMAT_SUFFIX}]}
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST")
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read()
            try:
                d = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError) as je:
                # a 200 with a non-JSON body fails CLOSED as SystemExit so the chain
                # advances - same rule as the OpenRouter path (chain review r4).
                raise SystemExit("ADVERSARY GATE: unreadable local model response (%s): %s"
                                 % (type(je).__name__, raw.decode("utf-8", "replace")[:200]))
            break
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < 3:
                sys.stderr.write("adversary local model 429 - retry %d/3 in 30s\n" % (attempt + 1))
                time.sleep(30)
                continue
            raise SystemExit("ADVERSARY GATE: local endpoint HTTP %s: %s"
                             % (e.code, e.read().decode("utf-8", "replace")[:300]))
        except (OSError, http.client.HTTPException) as e:
            raise SystemExit("ADVERSARY GATE: network/read error reaching the local endpoint: %r"
                             % (getattr(e, "reason", e),))
    return _parse_completion(d)


def _review_head():
    env = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1")
    result = subprocess.run([GIT, "rev-parse", "--verify", "--quiet", "HEAD"],
                            capture_output=True, env=env)
    if result.returncode == 0:
        return result.stdout.decode("ascii").strip()
    if result.returncode == 1:
        # An unborn symbolic branch has an empty base. Other failures stay fail-closed.
        _run_git(["symbolic-ref", "-q", "HEAD"])
        return EMPTY_TREE
    raise SystemExit("ADVERSARY GATE: cannot resolve the review base.")


def cmd_run(model, context):
    """Review frozen index/base inputs, then refuse release if the caller moved on."""
    global _REVIEW_BASE
    root = _repo_root()
    base = _review_head()
    tree = _run_git(["write-tree"]).strip()
    original_index = os.environ.get("GIT_INDEX_FILE")
    previous_base = _REVIEW_BASE
    with tempfile.TemporaryDirectory(prefix="review-index-", dir=_adv_dir(root)) as scratch:
        try:
            os.environ["GIT_INDEX_FILE"] = os.path.join(scratch, "index")
            _run_git(["read-tree", tree])
            _REVIEW_BASE = base
            result = _cmd_run_snapshot(model, context)
        finally:
            _REVIEW_BASE = previous_base
            if original_index is None:
                os.environ.pop("GIT_INDEX_FILE", None)
            else:
                os.environ["GIT_INDEX_FILE"] = original_index
    if result == 0 and (base != _review_head() or tree != _run_git(["write-tree"]).strip()):
        print("ADVERSARY GATE: staging or HEAD changed during review; commit REFUSED. "
              "Any saved clearance covers only the reviewed snapshot.", file=sys.stderr)
        return 1
    return result


def _module_level_names(src):
    """Module-level def / async def / class names of a Python source, or None when it does not
    parse (the caller decides what None means for its side)."""
    try:
        tree = ast.parse(src)
    except (SyntaxError, ValueError):
        return None
    return {n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}


# `match` pattern nodes exist from CPython 3.10; resolved defensively so an older interpreter's hook
# degrades to "no match captures" instead of an AttributeError on the first visited node (round 10)
_MATCH_CAPTURES = tuple(getattr(ast, n) for n in ("MatchAs", "MatchStar") if hasattr(ast, n))
_MATCH_MAPPING = tuple(getattr(ast, n) for n in ("MatchMapping",) if hasattr(ast, n))


def _sole_module_level_defs(src):
    """Module-level def/class names (direct children of the module body) whose ONLY binding anywhere in
    MODULE scope is that def/class. Module scope = every statement reachable from the module body without
    entering a def, lambda or class body - so `if`/`try`/`for`/`with`/`match` blocks count, a method or a
    function-local variable of the same name does not (they never re-bind the module attribute). A name
    is excluded when module scope also binds it by an import (`import m as N`, `from m import N`), an
    assignment of any shape (Name targets in Assign/AnnAssign/AugAssign/NamedExpr/for/with, nested tuples,
    lists, starred - a walrus inside a def's default arguments, annotations or return annotation, a
    lambda's defaults, or a class's bases or keywords included), a `del`, an
    `except ... as N`, a `match` capture (`case N:`, `case [*N]:`, `case {**N}:`), a `global`/`nonlocal` declared
    at module scope OR inside any nested body (a class body runs at import, a function body when called), or a second
    def/class of the same name (a def inside `if`/`try` included). A module-level `from m import *`
    re-binds every public name, so it disqualifies EVERYTHING (marketplace gate catches gate_20260915-182919
    and -184551: a def-then-rebind and a def-then-star-import both vouched for their importers). None when
    the source does not parse."""
    names = _module_level_names(src)
    if names is None:
        return None
    other = {}                                      # name -> count of module-scope bindings
    star = [False]

    def bind(name):
        other[name] = other.get(name, 0) + 1

    def visit(node):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bind(node.name)                         # the def itself counts once; a second one excludes
            for d in node.decorator_list:           # decorators run in module scope
                visit(d)
            if isinstance(node, ast.ClassDef):      # bases and keywords (metaclass=...) evaluate in
                for b in node.bases:                # module scope at class-definition time (round 10)
                    visit(b)
                for k in node.keywords:
                    visit(k.value)
            else:                                   # default arguments, annotations and the return
                visit(node.args)                    # annotation are EVALUATED in module scope at def
                if node.returns is not None:        # time - a walrus there re-binds (rounds 9-10)
                    visit(node.returns)
            for sub in ast.walk(node):              # ...except a `global N` declared in ANY nested body: a
                if isinstance(sub, (ast.Global, ast.Nonlocal)):  # class body runs at import, a function
                    for n in sub.names:             # body when called - either re-binds module.N
                        bind(n)                     # (round 11, marketplace gate_20260915-192907)
            return                                  # never enter the body otherwise: a method / local never rebinds
        if isinstance(node, ast.Lambda):
            visit(node.args)                        # same for a lambda's defaults; never its body
            return
        if isinstance(node, ast.Import):
            for al in node.names:
                bind(al.asname or al.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for al in node.names:
                if al.name == "*":
                    star[0] = True
                else:
                    bind(al.asname or al.name)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            for n in node.names:
                bind(n)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            bind(node.name)
        elif isinstance(node, _MATCH_CAPTURES) and node.name:
            bind(node.name)
        elif isinstance(node, _MATCH_MAPPING) and node.rest:
            bind(node.rest)                         # `case {**rest}:` - a str field, never a child node
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            bind(node.id)
        for child in ast.iter_child_nodes(node):
            visit(child)

    visit(ast.parse(src))
    if star[0]:
        return set()
    return {n for n in names if other.get(n, 0) <= 1}


def _staged_python_pairs():
    """[(old_path, new_path)] for every staged .py: M/T keep their path, R carries the OLD path
    (its HEAD blob is the one whose symbols may vanish), A has no old blob (old_path None), D has
    no new blob (new_path None: every symbol it defined is removed - a whole-content rename is
    reported by git as D+A, and a plain `git rm` is the same hole); a copy (C) removes nothing."""
    out = _run_git(["diff", "--cached", "--name-status", "-M", "-z", "--diff-filter=ACDMRT"])
    toks = out.split("\0")
    pairs, i = [], 0
    while i < len(toks):
        st = toks[i]
        if not st:
            i += 1
            continue
        if st[0] in ("R", "C"):
            old, new = toks[i + 1], toks[i + 2]
            i += 3
            if st[0] == "C":
                continue
        else:
            old = new = toks[i + 1]
            i += 2
            if st[0] == "A":
                old = None
            elif st[0] == "D":
                new = None
        if _is_py(old) or _is_py(new):
            pairs.append((old, new))
    return pairs


def _is_py(path):
    return bool(path) and path.lower().endswith(".py")


def _removed_symbol_callers():
    """DETERMINISTIC, LOCAL, FAIL-CLOSED: [(caller_path, line, name, defining_path)] for every
    module-level def/class that a staged .py REMOVES (present in its HEAD blob, absent from its
    index blob) while a tracked .py OUTSIDE the staged set still references the name (an ast
    Name or Attribute, or an import binding `from m import name` - a comment or docstring
    mention does not count). The hole this closes: Tools 8245433 (2026-09-07) removed
    adversary_gate._scan_text_secrets while reviewed_write.py still called it, and the review
    CLEARed - the reviewer only ever sees the staged files, so no prompt can see an unstaged
    caller; only arithmetic over the frozen index can. A new blob that does not parse, a deleted
    module, or a rename to a non-.py path counts as removing every old name. Names are matched
    unqualified EXCEPT where the bystander binds the name itself (2026-09-15, the fleet Atlas
    deletion: a package defining `main` could never be deleted because every other module's own
    `def main` and a `from deepagents import create_deep_agent` were reported as callers) - a
    module-level def/class of the name, or a MODULE-LEVEL `from m import name` whose source is
    PROVEN to define the name itself (see _SourceResolver: m maps to a tracked, unstaged file at
    the repo root that is the only path with that suffix anywhere in the non-ignored tree and
    whose index blob defines the name) - shadows it; everything else refuses: a bare unbound
    use, an attribute use, a plain `import m` (it binds the module object, never a shadow), a
    relative import, an import from the definer, its package, a staged module, an untracked or
    ignored module, a module static resolution cannot find at all (a src/ layout or a sys.path
    entry hides repo code behind such a name - gate catch gate_20260915-165305), a duplicated
    module name, or a tracked module that merely re-exports (`from M import *`, `S = M.S`, a
    `__getattr__`) - over-refuse rather than under-refuse. The tracked listing is
    root-anchored (`ls-files --full-name -- :/`) because a manual run from a subdirectory must
    see callers everywhere (gate catch gate_20260909-140534: a cwd-scoped listing was fail-open).
    Runs under the review's frozen index (GIT_INDEX_FILE) and review base, so the reviewed
    snapshot is what is compared. cmd_check inherits the guarantee: no clearance can exist
    without a passing run."""
    pairs = _staged_python_pairs()
    staged = {new for _, new in pairs if new} | {old for old, _ in pairs if old}
    removed = {}                                    # name -> defining (old) path
    for old, new in pairs:
        if old is None:
            continue
        old_names = _module_level_names(_run_git(["show", "HEAD:" + old]))
        if not old_names:
            continue
        new_names = _module_level_names(_run_git(["show", ":" + new])) if _is_py(new) else set()
        for name in old_names - (new_names or set()):
            removed.setdefault(name, old)
    if not removed:
        return []
    hits = []
    tracked = [f for f in _run_git(["ls-files", "-z", "--full-name", "--", ":/"]).split("\0")
               if _is_py(f) and f not in staged]
    staged_modules = {_module_name(p) for p in staged if _is_py(p)}
    untracked = [f for f in _run_git(["ls-files", "-z", "-o", "--exclude-standard", "--full-name",
                                      "--", ":/"]).split("\0") if _is_py(f)]
    resolver = _SourceResolver(_repo_root(), set(tracked), staged, untracked, staged_modules, removed)
    for path in tracked:
        try:
            tree = ast.parse(_run_git(["show", ":" + path]))
        except (SyntaxError, ValueError):
            continue                                # an unparsable bystander cannot be a caller
        shadow = _own_bindings(tree, resolver, path)
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                names = [node.id] if node.id not in shadow else []
            elif isinstance(node, ast.Attribute):
                names = [node.attr]
            elif isinstance(node, ast.Import):
                names = [a.name.split(".")[-1] for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                # `from m import gone` is a caller unless m provably cannot hand out the removed
                # symbol (see _SourceResolver.vouches) - fail-closed on everything unresolvable
                names = [a.name for a in node.names
                         if a.name in removed and not resolver.vouches(node, a.name, path)]
            else:
                continue
            for name in names:
                if name in removed:
                    hits.append((path, node.lineno, name, removed[name]))
    return sorted(set(hits))


def _module_name(py_path):
    """'pkg/mod.py' -> 'pkg.mod'; 'pkg/__init__.py' -> 'pkg'."""
    dotted = py_path.replace("\\", "/")[:-3].replace("/", ".")
    return dotted[:-9] if dotted.endswith(".__init__") else dotted


def _imports_definer(node, defining_path):
    """True when an ImportFrom may bind the removed symbol: relative or moduleless imports (unresolvable
    here -> assume yes), the defining module itself, or any parent package of it (a re-export)."""
    if node.level or not node.module:
        return True
    dm = _module_name(defining_path)
    return node.module == dm or dm.startswith(node.module + ".")


def _from_staged(node, staged_modules):
    """True when an ImportFrom draws from a module the change stages (deleted or rewritten) or from a
    package that contains one: such a source cannot vouch that the binding is the bystander's own."""
    m = node.module or ""
    return m in staged_modules or any(s.startswith(m + ".") for s in staged_modules)


class _SourceResolver(object):
    """Decides whether `from m import name` in a bystander PROVABLY binds something other than a
    removed symbol. Static resolution cannot prove that a module is external: a src/ layout, a
    sys.path entry, a namespace package or a not-yet-tracked file all put repo code behind an
    import name that resolves to nothing under the root (gate catches gate_20260915-162201,
    -163235 and -165305 each exploited a "not found -> external -> vouch" branch), so "not found"
    REFUSES. The only vouch is positive proof: m's dotted path names a TRACKED, UNSTAGED file at
    the repo root (`m/.../mod.py` or `.../__init__.py`); that file is the ONLY path with that
    suffix anywhere in the non-ignored tree (tracked, staged - deleted old paths included - or
    untracked); no unlisted (ignored) file sits at the root or beside the bystander under the same
    name; and the file's INDEX blob defines the name at module level (the `from fleet.cli import
    main` shape). Everything else is a caller: relative or moduleless imports, the definer or its
    parent packages, any staged module, a duplicated module name, an untracked or ignored
    candidate, and a tracked module that only re-exports the name (`from M import *`, `S = M.S`,
    a module `__getattr__`) - over-refuse, never under-refuse."""

    def __init__(self, root, tracked, staged_paths, untracked, staged_modules, removed):
        self._root = root
        self._tracked = set(tracked)                # unstaged tracked .py paths
        self._staged_paths = set(staged_paths)      # every staged path, DELETED old paths included
        self._untracked = set(untracked)            # worktree .py paths git does not track or ignore
        self._staged = staged_modules
        self._removed = removed
        self._defs = {}                             # tracked path -> set of module-level names

    @staticmethod
    def _tails(module):
        rel = module.replace(".", "/")
        return (rel + ".py", rel + "/__init__.py")

    def _suffix_matches(self, module):
        """Every listed path - tracked, staged or untracked - that the module's dotted path could
        name at ANY depth (`pkg/lib.py` matches `src/pkg/lib.py` and `tools/pkg/lib/__init__.py`)."""
        tails = self._tails(module)
        deep = tuple("/" + t for t in tails)
        return sorted(p for p in (self._tracked | self._staged_paths | self._untracked)
                      if p in tails or p.endswith(deep))

    def resolve(self, module, bystander):
        """The single root file that may vouch for `module`, or None when the proof fails: no match
        anywhere (unprovable, so external is NOT assumed), more than one match, a match that is not
        the root file, a staged or untracked match, or an unlisted (ignored) file under the same
        name at the root or beside the bystander that Python could import instead."""
        tails = self._tails(module)
        found = self._suffix_matches(module)
        if len(found) != 1 or found[0] not in tails or found[0] not in self._tracked:
            return None
        bases = [""]
        if "/" in bystander:
            bases.append(bystander.rsplit("/", 1)[0] + "/")
        for b in bases:
            for t in tails:
                cand = b + t
                if cand != found[0] and os.path.exists(os.path.join(self._root, cand)):
                    return None
        return found[0]

    def _module_defs(self, path):
        """Module-level def/class names of the candidate's INDEX blob that have NO other module-level
        binding there. A def the same module later re-binds - `def keep(): ...` then `from lib import
        keep`, `import lib as keep`, `keep = lib.keep` (the pure-Python-fallback-then-accelerator shape) -
        is not proof of anything: at runtime the name is whatever the last binding made it (marketplace
        gate catch gate_20260915-182919, selftest check 52). Over-refuse, never under-refuse."""
        if path not in self._defs:
            names = _sole_module_level_defs(_run_git(["show", ":" + path]))
            self._defs[path] = names if names is not None else set()
        return self._defs[path]

    def vouches(self, node, name, bystander):
        """True only on the positive proof described above; every unresolvable case is False."""
        module = node.module or ""
        if node.level or not module:
            return False
        defining = self._removed.get(name)
        if defining is not None and _imports_definer(node, defining):
            return False
        if _from_staged(node, self._staged):
            return False
        path = self.resolve(module, bystander)
        return path is not None and name in self._module_defs(path)


def _own_bindings(tree, resolver, bystander):
    """Names a bystander binds for itself at MODULE level: def/class names, plus `from m import name`
    bindings whose source provably defines the name itself (resolver.vouches). A use of such a name
    refers to the bystander's own object, not to the removed symbol. A plain `import m` binds the
    module object and never shadows a removed name (gate catch gate_20260915-165305: `import
    mpk.helpers` suppressed a bare use of a removed `mpk`); function-local imports do not shadow
    either (a module-level bare use is not covered by them)."""
    own = {n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            for a in node.names:
                if a.name not in resolver._removed or resolver.vouches(node, a.name, bystander):
                    own.add(a.asname or a.name)
    return own


def _print_removed_symbol_refusal(hits, stream):
    stream.write("\nADVERSARY GATE: REFUSED before review - the staged change REMOVES module-level "
                 "symbol(s) that tracked code outside the staged set still references (the reviewer "
                 "never sees unstaged callers; Tools 8245433 shipped exactly this hole):\n")
    for path, line, name, where in hits[:50]:
        stream.write("  %s:%d  references %s (removed from %s)\n" % (path, line, name, where))
    if len(hits) > 50:
        stream.write("  ... %d more\n" % (len(hits) - 50))
    stream.write("Fix: stage the callers with the reference removed (or re-pointed), or keep the "
                 "symbol. No clearance is written.\n")


# ---------------------------------------------------------------------------
# Tiered review, local pre-gate, scoped windows, sampled batch audits
# (owner order 2026-10-08; contract: docs/plans/2026-10-08-tiered-gate-grafts.md)
# ---------------------------------------------------------------------------

_PREGATE_TOOL_TIMEOUT_S = 20
_SCOPED_WINDOW_MAX = 40_000
_TS_LANG_BY_EXT = {".py": "python", ".js": "javascript", ".mjs": "javascript",
                   ".cjs": "javascript", ".ts": "typescript", ".tsx": "tsx",
                   ".jsx": "jsx", ".json": "json", ".sh": "bash", ".bash": "bash",
                   ".css": "css", ".html": "html", ".htm": "html"}
_TS_DEF_TYPES = ("function_definition", "class_definition", "function_declaration",
                 "class_declaration", "method_definition", "method_declaration",
                 "lexical_declaration", "export_statement")


def _tier_split(model):
    """(tier1_entries, tier2_entries). A manual override or ADVERSARY_TIER1_OFF gives
    a single tier running the WHOLE chain verbatim (the pre-2026-10-08 semantics)."""
    entries = [m.strip() for m in model.split(",") if m.strip()]
    # The tier split keys on the LITERAL default chain (gate round gate_20261008-122413,
    # HIGH F2): DEFAULT_MODEL is env-injectable, so keying on it force-split an
    # ADVERSARY_MODEL override into tier1/tier2 with the wrong timeout. Explicit
    # overrides ALWAYS run single-tier, whole chain verbatim.
    if os.environ.get("ADVERSARY_TIER1_OFF", "0") == "1" or model != DEFAULT_CHAIN:
        return [], entries
    n1 = len([m for m in TIER1_CHAIN.split(",") if m.strip()])
    return entries[:n1], entries[n1:]


def _tier1_eligible(payload, files, removals, context, blobs):
    """Quick-rung eligibility: small payloads with no rebuttal, no removals, no gated
    prefixes and no oversize blobs - everything substantive rides the strong rung."""
    if context.strip() or removals:
        return False
    if any(f.startswith(GATED_PREFIXES) for f in files):
        return False
    # gate round gate_20261008-141847 (MEDIUM): hook files are enforcement-critical
    # wherever they live (the hook_files_are_code_anywhere ruling) - they never
    # ride the quick rung
    if any(os.path.basename(f) in HOOK_NAMES for f in files):
        return False
    if any(len(blob) > MAX_FILE_BYTES for _f, blob in blobs):
        return False
    return len(payload) < TIER1_MAX_CHARS


def _audit_sampled(tree_sha):
    """Deterministic tree+day hash sampling of tier-1 CLEARs for the batch audit."""
    if AUDIT_PCT <= 0:
        return False
    if AUDIT_PCT >= 100:
        return True
    day = datetime.date.today().isoformat()
    h = int(hashlib.sha256(("%s|%s" % (tree_sha, day)).encode("utf-8")).hexdigest()[:12], 16)
    return h % 100 < AUDIT_PCT


def _enqueue_audit(root, tree_sha, payload, files, artifact):
    qdir = os.path.join(_adv_dir(root), "audit_queue")
    os.makedirs(qdir, exist_ok=True)
    name = datetime.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + tree_sha[:10]
    with open(os.path.join(qdir, name + ".payload"), "w", encoding="utf-8",
              errors="replace") as stream:
        stream.write(payload)
    tmp = os.path.join(qdir, name + ".json.tmp")
    with open(tmp, "w", encoding="utf-8") as stream:
        json.dump({"queued": name, "tree": tree_sha, "files": sorted(files),
                   "artifact": str(artifact), "model": TIER2_AUDIT_MODEL}, stream, indent=1)
    os.replace(tmp, os.path.join(qdir, name + ".json"))
    return name


def _spawn_audit_drain(root):
    """Best-effort detached drain; the queue is durable either way. Disabled by
    ADVERSARY_AUDIT_NOSPAWN=1 (selftests and operators who drain manually)."""
    if os.environ.get("ADVERSARY_AUDIT_NOSPAWN", "0") == "1":
        return
    try:
        log = open(os.path.join(_adv_dir(root), "audit_drain.log"), "a", encoding="utf-8")
        flags = (0x00000008 | 0x00000200) if os.name == "nt" else 0  # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
        subprocess.Popen([sys.executable, os.path.abspath(__file__), "audit-drain",
                          "--limit", "4"],
                         stdout=log, stderr=log, creationflags=flags, close_fds=True,
                         cwd=str(root))
    except Exception as exc:
        print("adversary gate: audit drain not spawned (%s) - run "
              "`python adversary_gate.py audit-drain` later; the queue keeps every "
              "entry." % str(exc)[:120])


def _warn_flagged_audits(root):
    """Loud, non-blocking warning when a sampled audit contradicted a landed CLEAR."""
    try:
        path = os.path.join(_adv_dir(root), "audit_findings.jsonl")
        if not os.path.isfile(path):
            return
        blocks = 0
        with open(path, encoding="utf-8") as stream:
            for line in stream:
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                if row.get("outcome") == "BLOCK":
                    blocks += 1
        if blocks:
            sys.stderr.write("ADVERSARY GATE: WARNING - %d sampled tier-1 audit(s) "
                             "returned BLOCK on landed commits (.adversary/"
                             "audit_findings.jsonl). Inspect the trees, remediate, and "
                             "add docket rows for any real catch.\n" % blocks)
    except Exception:
        pass


def cmd_audit_drain(limit=4):
    """Drain queued tier-1 batch audits. BATCH POLICY (owner order 2026-10-08): the
    interactive commit path NEVER uses the batch API - only these post-hoc sampled
    audits do (50% off, zero commit latency; hours-scale completion is acceptable
    precisely because nothing waits on the verdict)."""
    root = _repo_root()
    qdir = os.path.join(_adv_dir(root), "audit_queue")
    if not os.path.isdir(qdir):
        print("adversary audit: queue empty.")
        return 0
    # T2.5 / hole H3 (gate top-to-bottom): probe the audit model against the LIVE
    # catalog before submitting - a delisted default dead-letters every sampled
    # audit (the ds-pro:batch incident). Probe failures degrade loud and skip
    # this drain (entries stay queued); only a POSITIVE delist blocks the run.
    if os.environ.get("ADVERSARY_SELFTEST") == "1":   # hermetic selftests -
        sys.stderr.write("adversary audit: catalog probe skipped (selftest hermetic mode).\n")
    else:
        try:
            key = os.environ.get("OPENROUTER_API_KEY", "").strip()
            req = urllib.request.Request("https://openrouter.ai/api/v1/models",
                                         headers={"Authorization": "Bearer " + key})
            with urllib.request.urlopen(req, timeout=20) as resp:
                catalog = json.loads(resp.read().decode("utf-8"))
            ids = {m.get("id") for m in catalog.get("data", [])}
            base = TIER2_AUDIT_MODEL.split(":")[0]
            # gate round gate_20261009-014204: the :batch suffix is ROUTING, not a
            # catalog id - this probe catches delisting of the UNDERLYING model (the
            # ds-pro incident); a base-listed-but-:batch-rejected submission is owned
            # downstream by the terminal rejected-receipt dead-letter path.
            if base not in ids:
                print("ADVERSARY AUDIT: model %s is NOT in the live catalog (delisted?) "
                      "- drain SKIPPED, entries preserved; re-pin TIER2_AUDIT_MODEL." % base)
                return 1
        except Exception as exc:
            sys.stderr.write("adversary audit: catalog probe unavailable (%s) - degrading - drain SKIPPED, entries stay queued "
                             "Re-run when the catalog is reachable.\n" % str(exc)[:100])
            return 1
    done = pending = 0
    for name in sorted(os.listdir(qdir)):
        if done + pending >= max(1, limit):
            break
        if not name.endswith(".json"):
            continue
        meta_path = os.path.join(qdir, name)
        # gate round gate_20261008-122413, HIGH F3: item-level locking - two drains
        # (spawned background + manual) must never process one paid entry twice or
        # race the removals. A busy entry belongs to the drain holding its lock.
        # gate_20261008-144437 (MEDIUM): a drain lock is held across the batch call,
        # so a dead drain orphans it - and its holder's lifetime is BOUNDED by
        # construction (the audit timeout), unlike review locks: a lock older than
        # that bound + margin has no live holder by definition and is stolen.
        lock_name = name + ".drain"
        lock_fd = _adv_lock(qdir, lock_name, deadline_s=1)
        if lock_fd is None:
            lock_path = os.path.join(qdir, lock_name + ".lock")
            try:
                _age = time.time() - os.path.getmtime(lock_path)
            except OSError:
                _age = 0.0
            if _age > _env_int("ADVERSARY_AUDIT_TIMEOUT", 3600) + 300:
                # rename, never remove+recreate (gate round gate_20261008-152545,
                # MEDIUM): the rename is atomic - the losing drain's rename fails on
                # the vanished path and it then sees the winner's NEW lock, so two
                # steals can never both proceed on one entry
                stamp = os.path.join(qdir, "%s.steal-%d.lock" % (lock_name, os.getpid()))
                try:
                    os.rename(lock_path, stamp)
                except OSError:
                    pass          # another drain stole it first - its lock now stands
                else:
                    sys.stderr.write("adversary audit: stole orphaned drain lock %s "
                                     "(age %ds exceeds the audit-timeout bound)\n"
                                     % (lock_name, int(_age)))
                    try:
                        os.remove(stamp)
                    except OSError:
                        pass
                lock_fd = _adv_lock(qdir, lock_name, deadline_s=1)
        if lock_fd is None:
            pending += 1
            print("adversary audit: %s locked by another drain - left for its owner."
                  % name)
            continue
        try:
            try:
                with open(meta_path, encoding="utf-8") as stream:
                    meta = json.load(stream)
                with open(os.path.join(qdir, meta["queued"] + ".payload"), encoding="utf-8",
                          errors="replace") as stream:
                    payload = stream.read()
            except (OSError, ValueError, KeyError) as exc:
                print("adversary audit: unreadable queue entry %s (%s) - skipping."
                      % (name, str(exc)[:100]))
                continue
            try:
                text, usage, provider = _call_one_model(
                    TIER2_AUDIT_MODEL, payload,
                    _env_int("ADVERSARY_AUDIT_TIMEOUT", 3600))
            except BatchReviewPending as exc:
                pending += 1
                print("adversary audit: %s still pending - kept for resume (%s)"
                      % (meta["queued"], str(exc)[:120]))
                continue
            except SystemExit as exc:
                # gate round gate_20261008-144437 (MEDIUM): a terminal batch
                # failure must free the queue, never resubmit forever - the entry
                # is dead-lettered WITH an evidence row; move the files back into
                # audit_queue/ to retry by hand.
                dead = os.path.join(qdir, "dead")
                os.makedirs(dead, exist_ok=True)
                for _p in (meta_path,
                           os.path.join(qdir, meta["queued"] + ".payload")):
                    try:
                        os.rename(_p, os.path.join(dead, os.path.basename(_p)))
                    except OSError:
                        pass
                with open(os.path.join(_adv_dir(root), "audit_findings.jsonl"), "a",
                          encoding="utf-8") as stream:
                    stream.write(json.dumps({
                        "when": datetime.datetime.now().strftime("%Y%m%d-%H%M%S"),
                        "queued": meta["queued"], "tree": meta.get("tree"),
                        "model": TIER2_AUDIT_MODEL, "outcome": "REJECTED",
                        "text_head": str(exc)[:500]}) + "\n")
                print("adversary audit: %s terminally rejected - dead-lettered to "
                      "audit_queue/dead/ (an evidence row was written; move the "
                      "files back to retry)." % meta["queued"])
                continue
            outcome = _review_outcome(text)
            if outcome == "WARN":
                # single authority (F8/F17 divergence class)
                if not _warn_proven_low(text, meta.get("files") or []):
                    outcome = "BLOCK"
            row = {"when": datetime.datetime.now().strftime("%Y%m%d-%H%M%S"),
                   "queued": meta["queued"], "tree": meta.get("tree"),
                   "artifact": meta.get("artifact"),
                     "model": TIER2_AUDIT_MODEL, "provider": str(provider),
                   "outcome": outcome if outcome in ("CLEAR", "WARN", "BLOCK") else "BLOCK",
                   "text_head": text[:2000]}
            with open(os.path.join(_adv_dir(root), "audit_findings.jsonl"), "a",
                      encoding="utf-8") as stream:
                stream.write(json.dumps(row) + "\n")
            os.remove(meta_path)
            try:
                os.remove(os.path.join(qdir, meta["queued"] + ".payload"))
            except OSError:
                pass
            done += 1
            print("adversary audit: %s -> %s (%s)" % (meta["queued"], row["outcome"], row["model"]))
            if row["outcome"] == "BLOCK":
                print("ADVERSARY AUDIT: tier-1 CLEAR CONTRADICTED on tree %s - inspect and "
                      "remediate; a real catch owes a docket row." % str(meta.get("tree"))[:12])
        finally:
            _adv_unlock(qdir, name + ".drain", lock_fd)
    print("adversary audit: drained %d, pending %d." % (done, pending))
    return 0


def _pregate_run(cmd, src):
    """Run one linter reading stdin; (rc, stdout, stderr) or None when the tool is
    missing or times out (degrade-loud, never a block, never a crash)."""
    import shutil
    exe = shutil.which(cmd[0])
    if not exe:
        return None
    try:
        r = subprocess.run([exe] + cmd[1:], input=src, capture_output=True, text=True,
                           encoding="utf-8", errors="replace",
                           timeout=_PREGATE_TOOL_TIMEOUT_S)
        return r.returncode, r.stdout or "", r.stderr or ""
    except (subprocess.TimeoutExpired, OSError):
        return None


def _pbt_pregate(files):
    """T1.2 (owner order 2026-10-08): opt-in property-suite rung. Runs the
    hypothesis battery when staged code touches the gate engine or the suite
    itself; blocks ONLY on a real pytest failure (rc != 0 - a property failure
    is a violated invariant by construction); absent tools or a timeout degrade
    loud and never block. ADVERSARY_PREGATE_PBT=1 enables (default off)."""
    if os.environ.get("ADVERSARY_PREGATE_PBT", "0") != "1":
        return None
    if not any(f == "adversary-gate/adversary_gate.py" or f.startswith("tests/properties/")
               for f in files):
        return None
    root = _repo_root()
    if not os.path.isdir(os.path.join(root, "tests", "properties")):
        sys.stderr.write("adversary gate: property battery absent - degraded "
                         "(the model reviewer still runs).\n")
        return None
    # a MISSING pytest/hypothesis is an absent tool, not a failed invariant (gate
    # round gate_20261009-005859: `python -m pytest` exits rc 1 with 'No module
    # named' - that must degrade, never block)
    import importlib.util
    for _mod in ("pytest", "hypothesis"):
        if importlib.util.find_spec(_mod) is None:
            sys.stderr.write("adversary gate: property battery unavailable - %s not "
                             "installed; degraded (the model reviewer still runs).\n"
                             % _mod)
            return None
    try:
        r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                            "tests/properties"], cwd=root, capture_output=True, text=True,
                           encoding="utf-8", errors="replace",
                           timeout=_env_int("ADVERSARY_PREGATE_PBT_TIMEOUT", 120))
    except subprocess.TimeoutExpired:
        sys.stderr.write("adversary gate: property battery TIMEOUT - degraded "
                         "(the model reviewer still runs).\n")
        return None
    except OSError as exc:
        sys.stderr.write("adversary gate: property battery could not run (%s) - degraded.\n"
                         % str(exc)[:100])
        return None
    if r.returncode == 0:
        return None
    lines = [l for l in (r.stdout or "").splitlines() if l.strip()][-6:]
    # gate round gate_20261009-003823 (MEDIUM): a non-zero pytest with NO stdout
    # must still block - never a falsy "" on the failure path
    return " | ".join(lines) or ("pytest exited rc=%d with no stdout captured" % r.returncode)


_PREGATE_CACHE_MAX = 2000
# Bump when _pregate_check_one's CHECK LOGIC changes (new/stricter checks) - a
# cached pass was produced by an older logic and must not survive the change
# (gate round gate_20261009-085308 MEDIUM: tools+epoch keying alone goes stale
# when the gate's own logic evolves).
_PREGATE_LOGIC_VERSION = "1"
_TOOL_VERSIONS = None   # per-process memo


def _pregate_tool_versions():
    """T4.1 (owner order 2026-10-09): tool versions for the cache key - a ruff,
    biome or bash bump (or a python upgrade) invalidates every cached pass; the
    cache can only SKIP work the current tools would redo identically."""
    global _TOOL_VERSIONS
    if _TOOL_VERSIONS is not None:
        return _TOOL_VERSIONS
    import shutil as _sh
    v = {"python": sys.version.split()[0]}
    for tool in ("ruff", "biome", "bash"):
        exe = _sh.which(tool)
        out = ""
        if exe:
            try:
                r = subprocess.run([exe, "--version"], capture_output=True, text=True,
                                   encoding="utf-8", errors="replace", timeout=10)
                out = ((r.stdout or "") + (r.stderr or "")).strip().splitlines()
                out = out[0][:60] if out else ""
            except (subprocess.TimeoutExpired, OSError):
                out = ""
        v[tool] = out or "absent"
    _TOOL_VERSIONS = v
    return v


def _pregate_cache_load(root, epoch):
    p = os.path.join(_adv_dir(root), "pregate_cache.json")
    try:
        if not os.path.isfile(p):
            return {}
        d = json.loads(open(p, encoding="utf-8").read())
        if (d.get("tools") != _pregate_tool_versions()
                or d.get("logic") != _PREGATE_LOGIC_VERSION
                or str(d.get("epoch")) != str(epoch)):
            return {}          # version/epoch/logic mismatch: every entry drops
        entries = d.get("entries")
        return entries if isinstance(entries, dict) else {}
    except (OSError, ValueError):
        return {}


def _pregate_cache_save(root, epoch, entries):
    """Best-effort persist under the shared .adversary lock; the cache is an
    optimization - any failure degrades silently to re-running the checks."""
    try:
        adv = _adv_dir(root)
        os.makedirs(adv, exist_ok=True)
        fd = _adv_lock(adv, "pregate_cache", deadline_s=2)
        if fd is None:
            return
        try:
            items = dict(list(entries.items())[-_PREGATE_CACHE_MAX:])
            data = {"tools": _pregate_tool_versions(), "logic": _PREGATE_LOGIC_VERSION,
                    "epoch": str(epoch), "entries": items}
            tmp = os.path.join(adv, "pregate_cache.json.tmp")
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=1)
            os.replace(tmp, os.path.join(adv, "pregate_cache.json"))
        finally:
            _adv_unlock(adv, "pregate_cache", fd)
    except Exception:
        pass


def _pregate_check_one(f, src):
    """One file's deterministic checks (T4.2: runs inside a worker thread).
    Returns (fails[list], degraded[set]) - order-independent, no shared state."""
    fails, degraded = [], set()
    low = f.lower()
    if low.endswith(".py"):
        try:
            compile(src, f, "exec")
        except (SyntaxError, ValueError) as exc:
            fails.append("py-compile %s: line %s: %s"
                         % (f, getattr(exc, "lineno", "?"), str(exc)[:160]))
            return fails, degraded
        r = _pregate_run(["ruff", "check", "--no-cache", "--isolated",
                          "--output-format=concise",
                          "--select", "E9", "--stdin-filename", f, "-"], src)
        # E9 (syntax) ONLY: F821 was rejected 2026-10-08 - it false-blocks
        # dynamic-name code; dangling references are owned by the removed-symbol
        # scan and the model reviewer (EV-124: deterministic layers never
        # false-block).
        if r is None:
            degraded.add("ruff")
        elif r[0] == 1:
            hits = [ln for ln in r[1].splitlines()
                    if re.search(r"\bE9\d{2}\b", ln)][:3]
            fails.extend("ruff %s" % h[:180] for h in hits)
    elif low.endswith((".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs")):
        r = _pregate_run(["biome", "check", "--linter-enabled=false",
                          "--formatter-enabled=false", "--assist-enabled=false",
                          "--stdin-file-path=" + f], src)
        if r is None:
            degraded.add("biome")
        elif r[0] != 0 and re.search(r"pars", (r[1] + r[2]), re.I):
            first = [ln for ln in (r[1] + r[2]).splitlines() if ln.strip()][:2]
            fails.append("biome-parse %s: %s" % (f, " / ".join(first)[:200]))
    elif low.endswith(".json"):
        try:
            json.loads(src)
        except ValueError as exc:
            fails.append("json-parse %s: %s" % (f, str(exc)[:160]))
    elif low.endswith((".sh", ".bash")):
        r = _pregate_run(["bash", "-n", "-"], src)
        if r is None:
            degraded.add("bash")
        elif r[0] != 0:
            first = [ln for ln in (r[2] or r[1]).splitlines() if ln.strip()][:1]
            fails.append("bash -n %s: %s"
                         % (f, (first[0] if first else "syntax error")[:160]))
    return fails, degraded


def _local_pregate(files, blobs, root=None):
    """G-A (owner order 2026-10-08): the $0 deterministic pre-gate over the ALREADY
    FETCHED staged blobs (fetched once by the caller; this function performs no
    git I/O so namespace-exec selftests keep working). Compile/parse failures the
    paid reviewer would only rediscover are refused BEFORE any model call. Blocks
    ONLY on genuine deterministic errors; absent tools degrade loud.
    T4.1/T4.2 (owner order 2026-10-09): version+epoch-keyed PASS cache (same blob
    + same tools + same rules epoch = same verdict, so a cached pass can never
    skip a refusal) and parallel per-file checks; failures are never cached."""
    if os.environ.get("ADVERSARY_PREGATE_OFF", "0") == "1":
        return []
    by_path = dict(blobs)
    cacheable = (root is not None
                 and os.path.isdir(os.path.join(root, ".git"))
                 and os.environ.get("ADVERSARY_PREGATE_CACHE_OFF", "0") != "1")
    import hashlib as _hl
    epoch = _current_rules_epoch(root) if cacheable else ""
    cache = _pregate_cache_load(root, epoch) if cacheable else {}
    to_check, skipped = [], 0
    keyed = []                       # (f, key) parallel to to_check
    for f in files:
        data = by_path.get(f)
        if data is None:
            continue
        if not any(f.lower().endswith(ext) for ext in (
                ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
                ".json", ".sh", ".bash")):
            continue                 # unchecked extensions never touch the cache
        key = _hl.sha256(data).hexdigest() + ":" + f.lower().rsplit(".", 1)[-1]
        if key in cache:
            skipped += 1
            continue
        try:
            src = data.decode("utf-8")
        except UnicodeDecodeError:
            continue                 # not decodable: the model reviewer judges it
        to_check.append((f, src))
        keyed.append((f, key))
    if to_check:
        from concurrent.futures import ThreadPoolExecutor
        workers = min(4, len(to_check))
        if workers <= 1:
            results = [_pregate_check_one(f, src) for f, src in to_check]
        else:
            with ThreadPoolExecutor(max_workers=workers) as ex:
                results = list(ex.map(lambda pair: _pregate_check_one(*pair),
                                      to_check))
    else:
        results = []
    fails, degraded = [], set()
    for (f, key), (one_fails, one_deg) in zip(keyed, results):
        if one_fails:
            fails.extend(one_fails)   # failures are NEVER cached
        else:
            if cacheable:
                cache[key] = {"file": f, "when":
                              datetime.datetime.now().strftime("%Y%m%d-%H%M%S")}
        degraded |= one_deg
    if cacheable and cache:
        _pregate_cache_save(root, epoch, cache)
    if skipped:
        sys.stderr.write("adversary gate: pregate cache skipped %d unchanged "
                         "file(s) (tool+epoch keyed).\n" % skipped)
    for tool in sorted(degraded):
        sys.stderr.write("adversary gate: pre-gate tool '%s' %s unavailable/timed out - "
                         "degraded (the model reviewer still runs).\n"
                         % (tool, "(" + _pregate_tool_versions().get(tool, "?")[:40] + ")"))
    return fails


def _hunk_ranges(diff_text, path):
    """New-file line ranges of `path`'s hunks in a unified multi-file diff."""
    ranges = []
    in_file = False
    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            in_file = (" b/" + path) in line or line.endswith(" " + path)
            continue
        if not in_file:
            continue
        m = re.match(r"^@@ -\S+ \+(\d+)(?:,(\d+))? @@", line)
        if m:
            start = int(m.group(1))
            count = int(m.group(2) or "1")
            ranges.append((start, start + max(count, 1) - 1))
    return ranges


def _pad_range(a, b, n):
    pad = 40
    return (max(1, a - pad), min(n if n else b + pad, b + pad))


def _ast_enclosing(tree, a, b):
    """Innermost Python def/class whose span covers lines a..b, or None."""
    best = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            end = getattr(node, "end_lineno", None) or node.lineno
            if node.lineno <= a and end >= b:
                if best is None or node.lineno > best.lineno:
                    best = node
    return best


def _ts_enclosing(root_node, a, b):
    """Deepest tree-sitter node covering lines a..b, climbed to a definition-like
    ancestor; None when only the root covers the range."""
    node = deepest = root_node
    while True:
        nxt = None
        for child in node.children:
            if child.start_point[0] <= a - 1 and child.end_point[0] >= b - 1:
                nxt = child
                break
        if nxt is None:
            break
        node = deepest = nxt
    cur = deepest
    while cur is not None:
        if cur.type in _TS_DEF_TYPES:
            return cur
        cur = cur.parent
    return None if deepest is root_node else deepest


def _merge_spans(spans):
    out = []
    for a, b in sorted(spans):
        if out and a <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], b))
        else:
            out.append((a, b))
    return out


def _scoped_window(path, blob, diff):
    """G-B (owner order 2026-10-08): bounded enclosing-symbol window for an oversize
    staged file (tree-sitter; Python ast fallback; padded-line last resort). Empty
    string when nothing renderable fits."""
    try:
        text = blob.decode("utf-8")
    except UnicodeDecodeError:
        return ""
    lines = text.splitlines()
    n = len(lines)
    ranges = _hunk_ranges(diff, path) or [(1, min(200, n or 1))]
    spans = []
    parser = None
    lang = _TS_LANG_BY_EXT.get(os.path.splitext(path)[1].lower())
    if lang:
        try:
            from tree_sitter_language_pack import get_parser
            parser = get_parser(lang)
        except Exception:
            parser = None
    if parser is not None:
        tree = parser.parse(text.encode("utf-8"))
        for a, b in ranges:
            # a hunk can span several symbols: resolve BOTH endpoints and let the
            # merge cover every symbol between them (padding only when both fail)
            for probe in (a, b):
                node = _ts_enclosing(tree.root_node, probe, probe)
                if node is not None and node is not tree.root_node:
                    spans.append((node.start_point[0] + 1, node.end_point[0] + 1))
                else:
                    spans.append(_pad_range(probe, probe, n))
    elif os.path.splitext(path)[1].lower() == ".py":
        try:
            tree = ast.parse(text)
            for a, b in ranges:
                for probe in (a, b):
                    node = _ast_enclosing(tree, probe, probe)
                    spans.append((node.lineno, getattr(node, "end_lineno", node.lineno))
                                 if node else _pad_range(probe, probe, n))
        except (SyntaxError, ValueError):
            spans = [_pad_range(a, b, n) for a, b in ranges]
    else:
        spans = [_pad_range(a, b, n) for a, b in ranges]
    rendered = []
    size = 0
    for a, b in _merge_spans(spans):
        a2, b2 = max(1, a), min(n, b)
        if b2 < a2:
            continue
        # bounded DURING the render (gate round gate_20261008-131032, MEDIUM): a
        # class-spanning hunk on a huge file must never materialize every line
        # before the cap slices it
        for i in range(a2, b2 + 1):
            piece = "%d: %s\n" % (i, lines[i - 1])
            if size + len(piece) > _SCOPED_WINDOW_MAX:
                rendered.append("...window truncated at the %d-byte cap...\n"
                                % _SCOPED_WINDOW_MAX)
                size += 10 ** 12
                break
            rendered.append(piece)
            size += len(piece)
        if size >= _SCOPED_WINDOW_MAX:
            break
    body = "".join(rendered)
    if not body:
        return ""
    return ("\nSCOPED WINDOW for STAGED FILE %s (oversize: %d bytes - enclosing "
            "symbols of the diff hunks; full body omitted for size):\n%s\n"
            % (path, len(blob), body))


def _warn_proven_low(text, files):
    """The single proven-LOW authority for WARN verdicts (gate rounds
    gate_20261008-133828/150151: three inline copies diverged twice - F8, F17).
    True iff the parsed findings exist AND every one is PROVEN LOW; anything
    unproven (including no-severity rows) denies."""
    findings = _parse_findings(text, files)
    return bool(findings) and all(s == "LOW" for s, _cited in findings)


def _compose_review_payload(diff, blobs, context):
    """Assemble the reviewer's user message STABLE-FIRST/DIFF-LAST (cache-
    efficiency tranche R1, owner order 2026-09-23). `blobs` is [(path, bytes)]
    in the caller's stable sorted order. The full staged file bodies lead -
    they are near-identical across the rounds of one landing, so consecutive
    reviews share them as a provider-cacheable prefix (OpenRouter prompt
    caching is strict-prefix; the legacy diff-first layout shared only the
    system prompt and measured ~3% hits). The volatile diff and the rebuttal
    ride last. Omission decisions keep the legacy running-total semantics:
    the budget starts at the diff size and files are considered in order, so
    the same files drop under the same caps as before."""
    total = len(diff.encode("utf-8"))
    emitted = []
    for f, blob in blobs:
        nbytes = len(blob)
        if nbytes > MAX_FILE_BYTES or total + nbytes > MAX_TOTAL_BYTES:
            # G-B (owner order 2026-10-08): a bounded enclosing-symbol window beats a
            # bare omission - the reviewer sees the hunks' real context. The legacy
            # omission note survives only when even the window cannot fit the budget.
            window = _scoped_window(f, blob, diff)
            if window and total + len(window.encode("utf-8")) <= MAX_TOTAL_BYTES:
                emitted.append(window)
                total += len(window.encode("utf-8"))
                continue
            emitted.append("\nFULL STAGED FILE %s: OMITTED FOR SIZE (%d bytes) - judge "
                           "from the diff hunks and their context.\n" % (f, nbytes))
            continue
        emitted.append("\nFULL STAGED FILE %s:\n%s\n" % (f, blob.decode("utf-8", "replace")))
        total += nbytes
    parts = emitted + ["STAGED DIFF (the change under adversarial review):\n" + diff]
    # Experiment #10 transfer (owner order 2026-10-10): deterministic semantic
    # deltas ride AFTER the diff - the cacheable stable prefix is untouched, and
    # a diff with no operator/guard pair changes leaves the payload identical.
    try:
        import finding_adjudicator
        delta_block = finding_adjudicator.payload_section(
            finding_adjudicator.semantic_deltas(diff))
    except Exception:
        delta_block = ""
    if delta_block:
        parts.append(delta_block)
    if context:
        parts.append("\nREBUTTAL / AUTHOR NOTES (verify, do not blindly trust):\n" + context + "\n")
    return "".join(parts)


def _cmd_run_snapshot(model, context):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")   # before ANY print
    except Exception:
        pass
    root = _repo_root()
    # LOCAL secret pre-scan #1 - ADDED content across ALL staged files (docs included), so
    # a secret introduced by this change is caught and NOT sent to the external reviewer.
    secret_hits = _scan_staged_secrets()
    if secret_hits:
        _print_secret_warning(secret_hits, sys.stdout, "review-time pattern floor")
    files = _staged_code_files()
    removals = _staged_removals()
    runtime_catalog = ()
    try:
        from enforcement_runtime import ROOT as tools_origin, CERTIFIED_CATALOG as installed_catalog
        if str(tools_origin).lower().replace("\\", "/") == root.lower().replace("\\", "/"):
            if any(name in installed_catalog for name in files + [k[2:] for k in removals]):
                runtime_catalog = installed_catalog
                indexed = {os.fsdecode(name) for name in
                           _run_git(["ls-files", "--cached", "-z"], binary=True).split(b"\0") if name}
                missing = sorted(set(runtime_catalog) - indexed)
                if missing:
                    print("ADVERSARY GATE: required runtime catalog paths missing from the index: " +
                          ", ".join(missing) + "; update the catalog for coordinated retirement or restore them; no clearance written")
                    return 1
                files = sorted(set(files) | set(runtime_catalog))
    except ImportError:
        pass  # Legacy distributed gate copies have no runtime installer.
    if not files and not removals:
        print("adversary gate: no staged code files - nothing to review.")
        return 0
    # DETERMINISTIC refusal before any payload exists: a removed module-level symbol with a
    # live caller outside the staged set (2026-09-09; see _removed_symbol_callers).
    dangling = _removed_symbol_callers()
    if dangling:
        _print_removed_symbol_refusal(dangling, sys.stdout)
        return 1
    # Opaque binary code cannot receive a meaningful source review. Refuse before
    # forcing textual diffs, including deleted binary code from the frozen base.
    if (any(_blob_is_binary("", f) for f in files)
            or any(_blob_is_binary(_REVIEW_BASE or "HEAD", f)
                   for f in files + [k[2:] for k in removals])):
        print("adversary gate: binary code cannot be reviewed; no clearance written.")
        return 1
    # G-A (owner order 2026-10-08): $0 deterministic pre-gate - compile/parse failures
    # the paid reviewer would only rediscover are refused BEFORE any model call.
    # Staged blobs are fetched ONCE here and reused by the pre-gate, tier eligibility
    # and the payload composer (the composer keeps its running-total budget
    # semantics over the same list).
    blobs = [(f, _run_git(["show", ":" + f], binary=True)) for f in files]
    pregate_fails = _local_pregate(files, blobs, root)
    if pregate_fails:
        print("ADVERSARY GATE: local pre-gate REFUSED - deterministic error(s) the paid "
              "reviewer would only rediscover; fix and re-stage:")
        for line in pregate_fails:
            print("  " + line)
        return 1
    pbt_fail = _pbt_pregate(files)
    if pbt_fail:
        print("ADVERSARY GATE: property battery REFUSED - a stated invariant is "
              "violated (a property failure is a real violation by construction):")
        print("  " + pbt_fail)
        return 1
    code_paths = files + [k[2:] for k in removals]   # code files + removed code (D:oldpath)
    diff = _diff_paths(["-c", "core.quotepath=false", "diff", "--text", "--cached", "--unified=8"],
                       code_paths)   # docs excluded (doctrine); root-anchored + argv-batched
    if runtime_catalog:
        sizes = {f: len(_run_git(["show", ":" + f], binary=True)) for f in files}
        if any(sizes[f] > MAX_FILE_BYTES for f in runtime_catalog) or sum(sizes.values()) + len(diff.encode("utf-8")) > MAX_TOTAL_BYTES:
            print("ADVERSARY GATE: full runtime catalog cannot fit the review budget; no clearance written")
            return 1
    payload = _compose_review_payload(diff, blobs, context)
    # LOCAL SCRUB of the EXACT payload about to be transmitted (owner ruling 2026-09-07): a
    # secret in a REMOVED line, a diff hunk, an oversized-omitted file's hunk or the author's
    # own context (none in scan #1's new-blob view - e.g. `git rm secret.py`, the very EV-023
    # remediation flow) is REDACTED in place, never blocked and never sent. A false positive
    # (EV-025, EV-046) therefore costs one placeholder in the reviewer's view, not a denial.
    payload, scrubbed = _scrub_text(payload)
    if scrubbed:
        print("adversary gate: scrubbed %d secret-shaped value(s) from the review payload "
              "before transmission (staged-file hits were warned above; removed-line and "
              "context hits appear only here)." % len(scrubbed))
        unterminated = [ln for ln, lab in scrubbed if lab == "private-key-block:unterminated"]
        if unterminated:
            print("adversary gate: WARNING - a private-key BEGIN marker with no END within %d "
                  "lines at payload line(s) %s: the block was redacted up to the cap and "
                  "scrubbing resumed; the reviewer sees a partially redacted region there."
                  % (_PEM_MAX_LINES, ", ".join(str(x) for x in unterminated[:5])))
        # the reviewer must be able to tell a redacted FIXTURE from missing source: say so in
        # the payload itself (gate catch gate_20260907-163011 judged a scrubbed selftest
        # header as a broken fixture because nothing told it a tag stands for a literal)
        payload = ("REDACTION NOTE: %d secret-shaped value(s) in this payload were replaced by "
                   "<REDACTED:label> tags before transmission. Each tag marks a value in the "
                   "staged bytes that MATCHED a secret pattern - a real key, a password-shaped "
                   "value, a test fixture built to that shape, or a false positive. Judge the "
                   "surrounding code as if a value of that shape were there; never treat a "
                   "tag as a missing or malformed value.\n\n" % len(scrubbed)) + payload
    # --- tiered review (owner order 2026-10-08): quick rung first when eligible ---
    def _staged_keys():
        return dict({f: _staged_sha(f) for f in files}, **removals)

    def artifact_round(mdl, usg, prv, body_text):
        """One durable review round (atomic name + sidecar, owner order 2026-09-21);
        returns (artifact, ts). A total persistence failure raises to the caller."""
        ts_r = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        try:
            return _write_review_round(root, ts_r,
                                       _review_header(mdl, usg, prv,
                                                      len(scrubbed), files) + body_text,
                                       _staged_keys(), bool(context.strip()),
                                       tier=tier, tier_reason=tier_reason), ts_r
        except _ReviewRoundPartial as exc:
            print("adversary gate: review-round sidecar NOT stamped (%s) - this "
                  "round's findings will classify as indeterminate at notarization."
                  % str(exc)[:120])
            return exc.art, ts_r

    tier1_chain, tier2_chain = _tier_split(model)
    art = clear_ts = None
    tier = 2
    text = usage = used_model = provider = None
    tier_reason = "tier-2 (manual or ineligible)"
    if tier1_chain and _tier1_eligible(payload, files, removals, context, blobs):
        tier = 1
        tier_reason = "tier-1 eligible (payload < %d, no rebuttal/removals/gated/oversize)" % TIER1_MAX_CHARS
        print("adversary gate: tier-1 quick review (payload %d chars < %d)."
              % (len(payload), TIER1_MAX_CHARS))
        try:
            text, usage, used_model, provider = _call_model_ex(
                ",".join(tier1_chain), payload, TIER1_TIMEOUT_S)
        except SystemExit as exc:
            print("adversary gate: tier-1 reviewer unavailable (%s) - escalating to "
                  "the strong rung; a dead rung never clears." % str(exc)[:180])
            text = None
            tier = 2
            tier_reason = "tier-1 dead rung -> tier-2"
        if text is not None:
            if not text.rstrip().splitlines():
                text = "(model returned no content - failing closed)\nVERDICT: BLOCK"
            try:
                art, clear_ts = artifact_round(used_model, usage, provider, text)
            except Exception as exc:
                # No durable artifact means no clearance. Never allocate an unlocked
                # fallback name: concurrent reviewers could overwrite each other's proof.
                print("adversary gate: cannot persist review evidence (%s); no clearance written."
                      % str(exc)[:120])
                return 1
            if _review_outcome(text) != "CLEAR":
                # One-directional escalation (owner order 2026-10-08): the tier-1
                # round stays in the ledger; the strong rung confirms BLIND and its
                # verdict is final. Tier-1 never authors a standalone refusal.
                print("adversary gate: tier-1 flagged the change - confirming blind on "
                      "the strong rung (the strong verdict is final).")
                art = clear_ts = None
                text = usage = used_model = provider = None
                tier = 2
                tier_reason = "tier-1 flag -> tier-2 blind confirm"
    if tier == 2:
        route, routing_why = _route_chain(",".join(tier2_chain) if tier2_chain else model,
                                          payload, context)
        if routing_why in ("rule", "jev"):
            print("adversary gate: workload routing -> %s first (why=%s, payload=%d chars) "
                  "[the deepseek pins read provider prompt-cache at real size; the large or "
                  "repeating prefix rides them cheaply]"
                  % (_split_entry(route.split(",")[0])[0], routing_why, len(payload)))
        text, usage, used_model, provider = _call_model_ex(
            route, payload, TIER2_TIMEOUT_S)
        if not text.rstrip().splitlines():        # adversary finding (birth review): an
            text = "(model returned no content - failing closed)\nVERDICT: BLOCK"
            # substituted BEFORE the artifact write so the on-disk round carries the
            # fail-closed verdict - else it is invisible to true-rate adjudication
        try:
            art, clear_ts = artifact_round(used_model, usage, provider, text)
        except Exception as exc:
            print("adversary gate: cannot persist review evidence (%s); no clearance written."
                  % str(exc)[:120])
            return 1
    # G-E (owner order 2026-10-08): WARN authorizes ONLY a LOW-only finding set;
    # anything else wearing WARN collapses to BLOCK (fail-closed, never looser).
    outcome = _review_outcome(text)
    if outcome == "WARN":
        # G-E (owner order 2026-10-08): WARN authorizes ONLY a LOW-only finding set;
        # anything else wearing WARN collapses to BLOCK (fail-closed, never looser).
        if (os.environ.get("ADVERSARY_WARN_OFF", "0") == "1"
                or not _warn_proven_low(text, files + [k[2:] for k in removals])):
            outcome = "BLOCK"
    staged_keys_now = _staged_keys()
    _cache_drift_alarm(root, staged_keys_now, usage)
    verdict = outcome if outcome in ("CLEAR", "WARN") else "BLOCK"
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    print(text)
    print("\n=== adversary gate: %s | tier %d | artifact: %s" % (verdict, tier, art))
    if verdict == "BLOCK":
        _print_finding_adjudication(root, art, text, files, blobs, diff)
        print("Address the findings (or re-run with --context carrying a factual rebuttal).")
        return 1
    clear = _load_clear(root)
    for f in files:
        clear[f] = {"sha": _staged_sha(f), "verdict": verdict, "when": clear_ts,
                    "epoch": _current_rules_epoch(root),
                    "model": used_model, "artifact": os.path.relpath(art, root),
                    "tier": tier}
    for key, sha in removals.items():
        clear[key] = {"sha": sha, "verdict": verdict, "when": clear_ts,
                      "epoch": _current_rules_epoch(root),
                      "model": used_model, "artifact": os.path.relpath(art, root),
                      "tier": tier}
    _save_clear(root, clear)
    files_out = files + sorted(removals)
    print("Clearance written for %d file(s) - commit will pass while the staged bytes "
          "stay identical." % len(files_out))
    if tier == 1 and AUDIT_PCT > 0:
        tree_sha = _run_git(["write-tree"]).strip()
        if _audit_sampled(tree_sha):
            qname = _enqueue_audit(root, tree_sha, payload, files, art)
            print("adversary gate: tier-1 %s selected for the sampled batch audit "
                  "(%d%% of tree/day hashes) - queued as %s; post-hoc, never "
                  "commit-blocking." % (verdict, AUDIT_PCT, qname))
            _spawn_audit_drain(root)
    return 0


def _blob_sha(rev, path):
    return hashlib.sha256(_run_git(["show", rev + ":" + path], binary=True)).hexdigest()


def _changed_code_in_commit(rev):
    """Changed CODE in commit `rev` vs its FIRST parent (root commits vs the empty tree),
    with the SAME path rules as staging: returns (files {new_path: sha256 of the blob in
    rev}, removals {'D:'+old_path: sha256 of the parent blob}). This is the durable-side
    twin of _staged_code_files/_staged_removals - what a note must vouch for."""
    base = rev + "^1" if _git_ok(["rev-parse", "--verify", "--quiet", rev + "^1"]) else EMPTY_TREE
    hn = _hook_names_apply(rev)
    text_files = _text_files_apply(rev)
    out = _run_git(["diff", "--name-status", "-M", "-z", base, rev])
    toks = out.split("\0")
    files, removals = {}, {}
    i = 0
    while i < len(toks):
        st = toks[i]
        if not st:
            i += 1
            continue
        code = st[0]
        if code in ("A", "M", "T"):
            path = toks[i + 1]
            i += 2
            if _is_code(path, hn, text_files):
                files[path] = _blob_sha(rev, path)
        elif code in ("R", "C"):
            # gate round gate_20261009-145647: C (copy) records carry TWO paths
            # exactly like R (C<score>\0SRC\0DST) - walking C in the single-path
            # branch consumed only SRC and desynchronized the record stream. A
            # copy never removes its source, so only R contributes a removal.
            old, new = toks[i + 1], toks[i + 2]
            i += 3
            if _is_code(new, hn, text_files):
                files[new] = _blob_sha(rev, new)
            if code == "R" and _is_code(old, hn, text_files) and not _is_code(new, hn, text_files):
                removals["D:" + old] = _blob_sha(base, old)
        elif code == "D":
            old = toks[i + 1]
            i += 2
            if _is_code(old, hn, text_files):
                removals["D:" + old] = _blob_sha(base, old)
        else:
            i += 2
    return files, removals


def _hard_label(label):
    """Anchored literal patterns (private-key blocks, known key prefixes, sshpass / URL
    credentials) are HARD - near-zero false positives; the generic secret-named-assignment
    heuristic is SOFT (EV-025 and EV-046 were both its false positives). Owner ruling
    2026-09-07: commit time warns on both; the push guard refuses on hard, warns on soft."""
    return not label.startswith("secret-assignment(")


_C_ESCAPE = re.compile(r'\\(?:([\\"abtnvfr])|([0-7]{3}))')
_C_SIMPLE = {"\\": "\\", '"': '"', "a": "\a", "b": "\b", "t": "\t", "n": "\n", "v": "\v",
             "f": "\f", "r": "\r"}


def _unquote_c(s):
    """Undo git's C-style path quoting ("..." with \\", \\\\ and octal escapes) - used when a
    header path is quoted even under core.quotepath=false (a '\"' or control char in the name)."""
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        body = s[1:-1]
        return _C_ESCAPE.sub(lambda m: _C_SIMPLE[m.group(1)] if m.group(1)
                             else chr(int(m.group(2), 8)), body)
    return s


def _blob_is_binary(rev, path):
    """A NUL in the first 8 KB of the blob at rev:path - the staged docs scanner's rule
    (_staged_doc_files), applied to the push audit's DOCS FEED only. `--text` forces a diff of a
    binary, and its NUL-free lines (a PNG's deflate stream: 28,881 of them from one 2 MB brand
    image, whose push the docs model then refused as secret-shaped garbage, 2026-09-17) are not
    documentation; the pattern floor still scans every one of them (gate round on this fix:
    a literal planted inside a binary asset must refuse the push - the floor is the barrier).
    A path git cannot show (renamed away, absent) is not binary - it has no blob."""
    try:
        blob = _run_git(["show", "%s:%s" % (rev, path)], binary=True)
    except SystemExit:
        return False
    return bytes([0]) in blob[:8192]


def _diff_added_lines(base, rev):
    """[(path, new_line_no, text)] - the lines commit `rev` ADDS relative to `base` (its first
    parent, or the empty tree for a root commit), parsed from one `git diff --unified=0`.
    Pins (each one a known blindness): --text (a -diff attribute), --no-color, --no-ext-diff,
    --no-textconv, --no-relative, quotepath off, and --src-prefix/--dst-prefix so a pusher's
    `diff.noprefix=true` / `diff.mnemonicPrefix` cannot strip the `b/` this parser keys on
    (gate catch gate_20260907-171348: no prefix -> no path -> nothing scanned, silently).
    A '+++ ' line is a header ONLY outside a hunk - inside one it is content ('++ x' arrives
    as '+++ x' and is kept, as the staged scanner does); a C-quoted header path is unquoted.
    A deleted file has no '+++ b/' header and contributes nothing; lines carrying a NUL (a
    binary blob forced to text) are dropped rather than scanned as garbage - the NUL-free
    lines of a binary ARE kept here, for the pattern floor; the docs feed drops them by blob."""
    out = _run_git(["-c", "core.quotepath=false", "diff", "--unified=0", "--text", "--no-color",
                    "--no-ext-diff", "--no-textconv", "--no-relative",
                    "--src-prefix=a/", "--dst-prefix=b/", base, rev])
    added, path, in_hunk, cur = [], None, False, None
    for ln in out.split("\n"):
        if not in_hunk:
            if ln.startswith("diff --git "):
                path = None
                continue
            if ln.startswith("+++ "):
                hdr = _unquote_c(ln[4:])
                path = hdr[2:] if hdr.startswith("b/") else None
                continue
        m = _HUNK_HEADER.match(ln)
        if m:
            in_hunk, cur = True, int(m.group(1))
            continue
        if in_hunk and ln.startswith("diff --git "):
            in_hunk, path = False, None
            continue
        if in_hunk and path is not None and cur is not None and ln.startswith("+"):
            if "\x00" not in ln:
                added.append((path, cur, ln[1:]))
            cur += 1
    return added


def _note_type(rev):
    """'CLEAR' / 'OVERRIDE' from the commit's adversary note, else None."""
    p = subprocess.run([GIT, "notes", "--ref", NOTES_REF, "show", rev], capture_output=True,
                       text=True, encoding="utf-8", errors="replace",
                       env=dict(os.environ, GIT_NO_REPLACE_OBJECTS="1"))
    if p.returncode != 0:
        return None
    try:
        return json.loads(p.stdout).get("type")
    except ValueError:
        return None


def _shallow_boundaries():
    """The shas listed in the repo's `shallow` file (a shallow clone's grafted boundary
    commits) - their parents are absent by construction, so a first-parent diff would be
    the WHOLE tree; they came from the remote, they are not new history."""
    try:
        path = _run_git(["rev-parse", "--git-path", "shallow"]).strip()
        with open(path, encoding="utf-8") as fh:
            return {ln.strip() for ln in fh if ln.strip()}
    except (SystemExit, OSError):
        return set()


def _push_secret_audit(revs, doc_revs=None):
    """(hard, soft, doc_text) over the outgoing commits: every ADDED line of every commit is
    scanned with the same floor as commit time; hits split into HARD (anchored literals) and
    SOFT (the assignment heuristic) as (rev12, path, line, label); the added lines of
    non-code, non-BINARY paths are concatenated for the docs model - from `doc_revs` only when
    given (the commits not already on the remote's tracking refs: the floor still covers every
    commit in `revs`, the docs MODEL is not re-fed history the remote already holds). A binary
    blob's forced-text lines go through the floor like any other (a literal planted inside an
    asset still refuses) but never to the docs model (2026-09-17: a PNG's deflate lines read as
    secret-shaped garbage there), and the skip is said aloud once per blob. A commit that
    cannot be diffed is reported as a hard 'unscannable-commit' hit - the guard fails closed,
    never silently. A commit carrying the owner's OVERRIDE note has already been ruled on: its
    hard hits are demoted to warnings. A shallow-clone boundary commit is skipped with a loud
    line."""
    hard, soft, doc_lines = [], [], []
    doc_set = None if doc_revs is None else set(doc_revs)
    boundaries = _shallow_boundaries()
    binary_paths = {}                                    # (rev, path) -> bool, one `git show` per blob
    for rev in revs:
        if rev in boundaries:
            sys.stderr.write("adversary push guard: %s is a shallow-clone boundary commit - its "
                             "parent is absent here, so it is NOT scanned (it came from the "
                             "remote you cloned).\n" % rev[:12])
            continue
        base = rev + "^1" if _git_ok(["rev-parse", "--verify", "--quiet", rev + "^1"]) else EMPTY_TREE
        hn = _hook_names_apply(rev)
        text_files = _text_files_apply(rev)
        try:
            added = _diff_added_lines(base, rev)
        except SystemExit:
            hard.append((rev[:12], "(whole commit)", 0, "unscannable-commit"))
            continue
        overridden = _note_type(rev) == "OVERRIDE"
        for path, ln, text in added:
            for _, label in _scan_one_text(text, 1):
                if _hard_label(label) and overridden:
                    soft.append((rev[:12], path, ln, label + " (owner OVERRIDE note - allowed)"))
                else:
                    (hard if _hard_label(label) else soft).append((rev[:12], path, ln, label))
                break
            if (not _is_code(path, hn, text_files) or os.path.splitext(path)[1].lower() in DOCSCAN_EXTS) \
                    and (doc_set is None or rev in doc_set):
                key = (rev, path)
                if key not in binary_paths:
                    binary_paths[key] = _blob_is_binary(rev, path)
                    if binary_paths[key]:
                        sys.stderr.write("adversary push guard: %s %s is binary - its lines are not fed to the "
                                         "docs model (the pattern floor still scanned them).\n" % (rev[:12], path))
                if not binary_paths[key]:
                    doc_lines.append(text)
    return hard, soft, "\n".join(doc_lines)


def _push_secret_barrier(lref, revs, anchors, remote_known, doc_revs=None):
    """EV-046 (owner ruling 2026-09-07, 'instead of blocking on commit, force a git scan
    before each push'): the barrier commit time no longer provides. A HARD literal in any
    outgoing commit REFUSES the push - a hook cannot scrub history, so the recipe rewrites
    the unpushed commits; the soft heuristic WARNS; the outgoing DOC lines go through the
    local docs model - a block refuses, an absent model degrades loudly. Returns 1 to refuse."""
    hard, soft, doc_text = _push_secret_audit(revs, doc_revs)
    rows = lambda hs: "".join("  %s  %s:%s  %s\n" % h for h in hs)
    if soft:
        sys.stderr.write("\nADVERSARY PUSH GUARD: WARNING - secret-shaped values in outgoing "
                         "commits of %s (heuristic matches and owner-overridden commits warn, "
                         "never refuse; values not printed):\n%s\n" % (lref, rows(soft)))
    anchor = anchors[0][:12] if anchors else "<the remote's tip>"
    recipe = ("A hook cannot scrub history: rewrite the unpushed commits -\n  git rebase -i %s\n"
              "mark each listed commit 'edit', remove the value, re-run the gate, `git rebase "
              "--continue` (post-commit re-notarizes each rewritten commit), then push again. A "
              "DELIBERATE fixture (a tutorial key, a test value) is built at runtime from parts "
              "so no literal exists in the bytes - the gate's own selftests do this. Or the "
              "owner rules: a commit the owner OVERRIDE-notarizes passes with a warning.\n"
              % anchor)
    if not remote_known:
        recipe += ("The remote's tip is unknown here (a new remote, or not fetched), so some of "
                   "these commits may already be published elsewhere - if so, do NOT rewrite "
                   "them: rotate the value and the owner rules.\n")
    recipe += "\n"
    if hard:
        sys.stderr.write("\nADVERSARY PUSH GUARD: push of %s REFUSED - outgoing commit(s) carry a "
                         "secret LITERAL (values not printed):\n%s\n%s" % (lref, rows(hard), recipe))
        return 1
    if doc_text.strip():
        try:
            res = (docscan.scan_segmented(
                doc_text, max_chunks=_env_int("ADVERSARY_DOCSCAN_PUSH_CHUNKS", 96)) if docscan
                   else {"status": "degraded", "detail": "docscan module unavailable"})
        except (Exception, SystemExit) as e:
            res = {"status": "degraded", "detail": "docs scan crashed: %s" % (str(e)[:150])}
        if res["status"] == "block":
            sys.stderr.write("\nADVERSARY PUSH GUARD: push of %s REFUSED - the local docs reviewer "
                             "flagged secret material in outgoing documentation (%s). Values are "
                             "not printed; find it in the outgoing doc lines. %s"
                             % (lref, res.get("detail", ""), recipe))
            return 1
        if res["status"] == "degraded":
            sys.stderr.write("adversary push guard: docs SEMANTIC scan SKIPPED (%s) - outgoing "
                             "docs got the pattern floor only.\n" % res.get("detail", ""))
        elif res.get("capped"):
            sys.stderr.write("adversary push guard: docs scan CAPPED (%s) - the tail of the "
                             "outgoing docs was NOT semantically scanned.\n" % res.get("detail", ""))
    return 0


_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def _adv_lock(adv, name, deadline_s=10):
    """O_EXCL spin lock for a .adversary JSON read-modify-write (gate round 3,
    2026-09-21: the hook auto-review can race a manual run for minutes - a concurrent
    last-write silently DROPS a row). Returns the lock fd, or None when busy past the
    deadline. Never steal a lock based on age: a live holder may be delayed.
    An abandoned lock requires operator cleanup after verifying no holder is active.
    The holder's pid is written INTO the lock for ownership checks."""
    lock = os.path.join(adv, name + ".lock")
    deadline = time.time() + deadline_s
    mine = str(os.getpid())
    while True:
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, mine.encode("ascii"))
            try:
                # ownership re-check: on POSIX a racing stale-breaker can unlink and
                # re-create the lock between our create and this read - if the file
                # at the path is not ours, we do NOT hold the lock (r6 F3)
                with open(lock, encoding="utf-8", errors="replace") as stream:
                    owner = stream.read().strip()
                if owner != mine:
                    os.close(fd)
                    continue
            except OSError:
                os.close(fd)
                continue
            return fd
        except FileExistsError:
            if time.time() > deadline:
                return None
            time.sleep(0.05)


def _adv_unlock(adv, name, fd):
    try:
        os.close(fd)
    except OSError:
        pass
    lock = os.path.join(adv, name + ".lock")
    try:
        with open(lock, encoding="utf-8", errors="replace") as stream:
            owner = stream.read().strip()
        if owner == str(os.getpid()):
            os.remove(lock)                   # only OUR lock - never a successor's
    except OSError:
        pass


def _stamp_review_meta(root, art_name, staged, context_used, **extra):
    """Owner order 2026-09-21 (true-rate recording): every review round records the
    staged blob shas it judged (same key space as clearance/changed: paths + 'D:' keys)
    plus whether the author carried a --context REBUTTAL. Append-merge under the
    shared .adversary lock, atomic. (Kept for direct callers; the review flow itself
    goes through _write_review_round, which pairs artifact + sidecar atomically.)"""
    adv = _adv_dir(root)
    p = os.path.join(adv, "reviews", "staged_shas.json")
    fd = _adv_lock(adv, "reviews_staged_shas")
    if fd is None:
        raise RuntimeError("staged_shas.json lock busy - sidecar row not written")
    try:
        data = {}
        if os.path.isfile(p):
            try:
                data = json.loads(open(p, encoding="utf-8").read())
            except ValueError:
                raise RuntimeError("Corrupt evidence JSON; original preserved") from None
        data[art_name] = dict({"staged": staged, "rebuttal": bool(context_used)},
                               **extra)   # T2.3 tier/tier_reason telemetry
        tmp = p + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=1)
            f.flush(); os.fsync(f.fileno())
        os.replace(tmp, p)
    finally:
        _adv_unlock(adv, "reviews_staged_shas", fd)


class _ReviewRoundPartial(RuntimeError):
    """The review artifact landed but its sidecar row did not (lock busy / RMW
    failure) - carries the WRITTEN artifact path so the degraded caller pairs its
    clearance/note with the right round, never the base-name doppelganger (r6 F6)."""
    def __init__(self, detail, art):
        RuntimeError.__init__(self, detail)
        self.art = art


def _write_review_round(root, ts, body, staged, context_used,
                       tier=None, tier_reason=None):
    """Allocate the round's ARTIFACT NAME and its sidecar row atomically under the
    reviews lock (gate round 4, 2026-09-21): two runs ending in the same second must
    never share a gate_<ts>.md name - the second write would clobber the first's
    review text while the sidecar kept both baselines crossed. Collision appends
    '-<n>' before .md (consumers must tolerate the suffix). Returns the artifact path."""
    adv = _adv_dir(root)
    rvw = os.path.join(adv, "reviews")
    fd = _adv_lock(adv, "reviews_staged_shas")
    if fd is None:
        raise RuntimeError("review-round lock busy - artifact + sidecar not written")
    try:
        base = "gate_%s" % ts
        name = base + ".md"
        n = 2
        while os.path.exists(os.path.join(rvw, name)):
            name = "%s-%d.md" % (base, n)
            n += 1
        art = os.path.join(rvw, name)
        with open(art, "w", encoding="utf-8") as fh:
            fh.write(body)
        try:
            p = os.path.join(rvw, "staged_shas.json")   # inlined sidecar RMW - calling
            data = {}                                   # _stamp_review_meta here would
            if os.path.isfile(p):                       # re-acquire the SAME lock
                try:
                    data = json.loads(open(p, encoding="utf-8").read())
                except ValueError:
                    raise RuntimeError("Corrupt evidence JSON; original preserved") from None
            data[name] = dict({"staged": staged, "rebuttal": bool(context_used)}, tier=tier, tier_reason=tier_reason)
            tmp = p + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=1)
                f.flush(); os.fsync(f.fileno())
            os.replace(tmp, p)
        except Exception as exc:
            # the ARTifact exists and is OURS - surface it so the degraded caller
            # pairs clearance/note with the right round (r6 F6)
            raise _ReviewRoundPartial(str(exc), art)
        return art
    finally:
        _adv_unlock(adv, "reviews_staged_shas", fd)



def _parse_findings(text, files):
    """Best-effort findings of a BLOCK artifact: [(severity, [cited staged files])].
    The reviewer writes free-form prose (severity, file, line, trigger, impact); a
    paragraph counts as a finding when it carries a severity WORD (word-boundary, so
    'follow'/'below' never book as LOW) or names a staged file. A round that staged
    ONLY code removals has no files in its header; its findings cite nothing and
    classify at episode level."""
    body = text
    parts = body.split("\n\n", 1)
    if len(parts) == 2 and parts[0].startswith("model:"):
        body = parts[1]                      # drop the header line, keep the review
    i = body.find("VERDICT:")
    if i >= 0:
        body = body[:i]
    out = []
    for para in re.split(r"\n\s*\n", body):
        up = para.upper()
        sev = next((s for s in _SEVERITIES if re.search(r"\b%s\b" % s, up)), "")
        # token-exact citation: 'util.py' must not match inside 'x_util.py' - strip
        # the punctuation (incl. sentence periods) and trailing :line reviewers
        # attach (path.py:12. / (path.py) / 'path.py',) and compare whole tokens
        toks = {re.sub(r":\d+$", "", t.strip("`'\"\u2018\u2019(),:;.!?[]{}"))
                for t in para.split()}
        cited = [f for f in files if f in toks]
        if sev or cited:
            out.append((sev, cited))
    return out


_GNAME_RE = re.compile(r"gate_(\d{8}-\d{6})(?:-(\d+))?\.md$")


def _print_finding_adjudication(root, art, text, files, blobs, diff):
    """Experiment #10 transfer (owner order 2026-10-10): anchor-normalize the
    findings of a BLOCK review and persist the dispositions as evidence. The
    external reviewer's verdict stays the commit authority - this layer
    ANNOTATES, never rules (measured basis and the one-line upgrade path live
    in finding_adjudicator's module docstring; ADVERSARY_ADJUDICATE_OFF=1
    skips it entirely)."""
    if os.environ.get("ADVERSARY_ADJUDICATE_OFF", "0") == "1":
        return
    try:
        import finding_adjudicator
        res = finding_adjudicator.adjudicate_review(text, files, blobs, diff)
        res["artifact"] = os.path.relpath(art, root) if art else None
        res["verdict"] = "BLOCK"
        try:
            _save_json(root, "adjudication_%s"
                       % datetime.datetime.now().strftime("%Y%m%d-%H%M%S"), res)
        except Exception:
            pass                      # console annotation survives; persistence is best-effort
        print("\n=== " + finding_adjudicator.summary_line(res))
    except Exception as exc:
        print("adversary gate: finding adjudication skipped (%s) - evidence-only "
              "layer, never verdict-affecting." % str(exc)[:120])


def _adjudicate_cycle(root, head, changed, clear, note_type, after=None):
    """Owner order 2026-09-21 (true-rate recording): classify every finding of this
    commit's INITIAL denial from evidence the gate itself holds (review artifacts,
    the staged-shas sidecar, clearance rows) and return the episode dict for
    .adversary/adjudications.json - None when this commit had no denial cycle (a
    first-pass CLEAR commit carries no episode, matching the ledger's numerator).
    `after` (the PREVIOUS commit's note 'when') bounds the cycle: a BLOCK older than
    the last landing belongs to an abandoned change, never to this commit.
    Outcomes: fixed (blobs changed after the denial - real, remediated),
    rebutted-upheld (the CLEARING round carried a --context rebuttal that held on
    unchanged bytes - false positive), cleared-unedited (a re-run cleared unchanged
    bytes - model variance), overridden (OVERRIDE note - the owner's call, not an
    adjudication), indeterminate (the round predates the sidecar). Any BLOCK round
    that still carried a rebuttal flags rebuttal_rejected (the reviewer rejected it
    - corroboration the finding is real)."""
    rvw = os.path.join(_adv_dir(root), "reviews")
    sidecar = {}
    sc_path = os.path.join(rvw, "staged_shas.json")
    if os.path.isfile(sc_path):
        try:
            sidecar = json.loads(open(sc_path, encoding="utf-8").read())
        except ValueError:
            sidecar = {}
    consumed = set()
    adj_path = os.path.join(_adv_dir(root), "adjudications.json")
    if os.path.isfile(adj_path):
        try:
            for ep in json.loads(open(adj_path, encoding="utf-8").read()).get("episodes", []):
                consumed.add(os.path.basename(ep.get("denial_artifact") or ""))
                consumed.update(os.path.basename(r) for r in ep.get("rounds", []))
        except ValueError:
            pass
    lo = after or ""                           # compare the EXTRACTED ts, never the
    rounds = []                                # whole name: '-2' sorts before '.md'
    for name in sorted(os.listdir(rvw)):
        g = _GNAME_RE.match(name)              # (name -> (ts, n) keeps suffixed
        if not g:                              # collisions chronologically ordered)
            continue
        rkey = (g.group(1), int(g.group(2) or 0))
        try:
            text = open(os.path.join(rvw, name), encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        m = re.search(r"files:\s*(\[[^\n]*)", text)   # _review_header writes a Python
        files = []                                      # list repr - parse it as one
        if m:
            # end-of-line capture, then CUT at the trailing '| caller:' field: a
            # ']' inside a file name must NOT truncate the list (gate r2 F1 - the
            # bracket-terminated regex did) and the caller field must not leak
            # into the names (gate r1 F1 - the bare end-of-line capture did)
            frag = re.split(r"\s*\|\s*caller:\s*\S+\s*$", m.group(1))[0].strip()
            try:
                val = ast.literal_eval(frag) if frag.endswith("]") else None
            except (ValueError, SyntaxError):
                val = None
            if isinstance(val, list):
                files = [str(x) for x in val]
            else:
                files = [t.strip().strip("'\"") for t in frag.strip("[]").split(",")
                         if t.strip()]
        # derive the round's verdict from the SAME authority the run path enforces
        # (_review_outcome) - a lowercase 'verdict: block' or spaced 'VERDICT : X'
        # was a real failed round to the gate and must be one here too (r7 F1)
        outcome = _review_outcome(text)
        # WARN rounds classify by their own severities (gate round
        # gate_20261008-131032, MEDIUM): LOW-only WARN stood as a clearance;
        # anything heavier was collapsed to BLOCK by the run path and denied.
        if outcome == "WARN":
            # single authority (F8/F17 divergence class): same helper as the run path
            verdict = "CLEAR" if _warn_proven_low(text, files) else "BLOCK"
        else:
            verdict = ("CLEAR" if outcome == "CLEAR" else
                       "BLOCK" if outcome in ("BLOCK", "malformed") else None)
        # header_listed separates a REAL empty list (a removals-only round) from a
        # parse miss (no files: header at all) - the latter must adopt nothing (r5 F5)
        rounds.append((rkey, name, verdict, files, text, m is not None))
    rounds.sort(key=lambda r: r[0])            # (ts, n): suffixed collisions stay in
                                               # write order behind their base name

    def _touches(r):
        # candidate keys = header names + the round's OWN sidecar staged keys: a
        # mixed round's D: half lives ONLY in the sidecar (the header lists files)
        staged = sidecar.get(r[1], {}).get("staged", {})
        keys = set(staged) | set(r[3]) | {"D:" + f for f in r[3]}
        if not keys:
            return bool(r[5]) and any(k.startswith("D:") for k in changed)
        return any(k in changed for k in keys)

    # >= at second granularity on the EXTRACTED ts: a same-second denial belongs to
    # THIS cycle (the consumed set keeps the parent's own rounds out); a name-level
    # compare broke on the '-2' collision suffix ('-' sorts before '.') (r6 F1)
    blocks = [r for r in rounds if r[2] == "BLOCK" and r[1] not in consumed
              and (not lo or r[0][0] >= lo) and _touches(r)]
    if not blocks:
        return None
    denial = blocks[0]                        # earliest in-cycle: the initial denial
    denial_shas = sidecar.get(denial[1], {}).get("staged", {})
    clearing = sorted({os.path.basename(clear[k].get("artifact") or "")
                       for k in changed if clear.get(k, {}).get("artifact")} - {""})
    round_names = [r[1] for r in blocks] + clearing
    # ONLY the clearing round's rebuttal can book `rebutted-upheld`: a rebuttal the
    # reviewer REJECTED (that round still BLOCKed) is the opposite evidence. The
    # clearing round is per-FILE - a commit whose files cleared in different rounds
    # must not let one file's rebuttal taint the others' findings (gate round 4).
    rebuttal_rounds = [n for n in round_names if sidecar.get(n, {}).get("rebuttal")]
    rejected = {r[1] for r in blocks if sidecar.get(r[1], {}).get("rebuttal")}

    def _pair(c):
        """A cited file's key in each evidence space: the denial staged it (maybe as
        a plain path) while the commit may have remediated by DELETING it (a 'D:' key
        in changed) - join across both spellings or the delete-fix books wrong."""
        ck = c if c in changed else ("D:" + c) if ("D:" + c) in changed else None
        dk = c if c in denial_shas else ("D:" + c) if ("D:" + c) in denial_shas else None
        return ck, dk

    def _outcome(cited):
        if note_type == "OVERRIDE":
            return "overridden", "override"
        pairs = [_pair(c) for c in cited if _pair(c)[0] is not None]
        if not pairs:                          # no cited file landed under its own
            pairs = [_pair(k[2:] if k.startswith("D:") else k)   # name - classify on
                     for k in changed]          # the keys that DID land
        # the keys that drove classification, CHANGED-side: the clearing-round
        # lookup must key on THESE - keying on the raw cited name could pull a
        # STALE clearance row for a file this commit never carried (r8 F1)
        used = [ck for ck, _dk in pairs if ck]
        known = [(ck, dk) for ck, dk in pairs if dk]
        if not any(ck for ck, _dk in known):
            used = [k for k in changed if k in denial_shas]
            known = [(k, k) for k in used]
        if not known:
            return "indeterminate", "evidence-absent"
        if any(denial_shas[dk] != changed[ck] for ck, dk in known if ck):
            return "fixed", "blobs-changed-after-denial"
        arts = ({os.path.basename(clear[k]["artifact"])
                 for k in used if clear.get(k, {}).get("artifact")} or clearing)
        if any(sidecar.get(n, {}).get("rebuttal") for n in arts):
            return "rebutted-upheld", "rebutted-then-cleared-unchanged"
        if not arts or not any(n in sidecar for n in arts):
            # no clearing round is known at all, or the clear predates the sidecar /
            # its stamp failed - whether a rebuttal carried it is UNANSWERABLE, not
            # 'no rebuttal' (gate rounds 3+5, 2026-09-21)
            return "indeterminate", "clearing-evidence-absent"
        return "cleared-unedited", "rerun-cleared-unchanged"

    findings = []
    for idx, (sev, cited) in enumerate(_parse_findings(denial[4], denial[3]), 1):
        outcome, method = _outcome(cited)
        findings.append({"id": "F%d" % idx, "severity": sev, "files": cited,
                         "outcome": outcome, "method": method,
                         "rebuttal_rejected": bool(rejected)})
    if not findings:                          # unparsable denial: one honest episode row
        outcome, method = _outcome([])
        findings = [{"id": "F1", "severity": "", "files": [],
                     "outcome": outcome, "method": method + "+unparsed",
                     "rebuttal_rejected": bool(rejected)}]
    counts = {}
    _head = denial[4].splitlines()[0] if denial[4] else ""
    _cm = re.search(r"\| caller: (\S+)", _head)   # header line ONLY: prose can
    for f in findings:                              # mention 'caller:' (gate r2 F2)
        counts[f["outcome"]] = counts.get(f["outcome"], 0) + 1
    return {"commit": head,
            "caller": _cm.group(1) if _cm else "",
            "recorded": datetime.datetime.now().strftime("%Y%m%d-%H%M%S"),
            "type": note_type, "denial_artifact": "reviews/" + denial[1],
            "rounds": sorted("reviews/" + n for n in round_names),
            "rebuttal_rounds": ["reviews/" + n for n in rebuttal_rounds],
            "denial_shas_known": bool(denial_shas),
            "findings": findings, "outcome_counts": counts}


def _append_adjudication(root, episode):
    """Append-only store (owner order 2026-09-21): one episode per commit; a second
    call for the same commit is a no-op - the hook and the commit driver BOTH invoke
    record, so the read-modify-write runs under the shared .adversary lock (a
    concurrent last-write would silently DROP an episode). Rows are never rewritten
    or deleted (evidence-docket discipline). Returns True when persisted (or
    already present), False when the lock stayed busy - callers must NOT report
    success on False (r7 F3)."""
    adv = _adv_dir(root)
    p = os.path.join(adv, "adjudications.json")
    fd = _adv_lock(adv, "adjudications")
    if fd is None:
        sys.stderr.write("adversary record: adjudication lock busy - episode for %s "
                         "NOT persisted.\n" % episode.get("commit", "")[:12])
        return False
    try:
        data = {"version": 1, "episodes": []}
        if os.path.isfile(p):
            try:
                data = json.loads(open(p, encoding="utf-8").read())
            except ValueError:
                raise RuntimeError("Corrupt evidence JSON; original preserved") from None
        # T6/W2 (gate round gate_20261009-121201): pre-write episodes carry NO
        # commit - the old equality dedup collapsed them all into one (both sides
        # None). Dedup key: commit when present, else the caller's identity tuple.
        def _ep_key(ep):
            return (ep.get("commit") or
                    ("pre-write", ep.get("path"), ep.get("artifact")))
        if not any(_ep_key(ep) == _ep_key(episode)
                   for ep in data.get("episodes", [])):
            data.setdefault("episodes", []).append(episode)
            tmp = p + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=1)
                f.flush(); os.fsync(f.fileno())
            os.replace(tmp, p)
        return True
    finally:
        _adv_unlock(adv, "adjudications", fd)


def _cycle_floor(head, ref):
    """The earliest artifact timestamp that can belong to THIS commit's review cycle.
    Anchor preference (gate round 5 F1): the parent note's CLEARING-ROUND timestamps
    (files[k]['when'] - the gate's own clock, strictly earlier than the record, and
    no child denial can predate the parent's clear), then the note's top-level
    'when', then - when the parent carries no note (a bypassed commit, a failed
    record, the first notarized commit) - the parent's own COMMIT time. None only
    for a root commit. Callers compare with >= (second granularity must never drop a
    same-second denial; the consumed set keeps the parent's own rounds out)."""
    try:
        if not _git_ok(["rev-parse", "--verify", "--quiet", head + "~1"]):
            return None
        if _git_ok(["notes", "--ref", ref, "show", head + "~1"]):
            try:
                note = json.loads(_run_git(["notes", "--ref", ref, "show",
                                            head + "~1"]))
                rounds = [row.get("when") for row in note.get("files", {}).values()
                          if isinstance(row, dict) and row.get("when")]
                if rounds:
                    return max(rounds)
                if note.get("when"):
                    return note["when"]
            except (SystemExit, ValueError):
                pass
        out = _run_git(["log", "-1", "--date=iso-local", "--format=%cd",
                        head + "~1"]).strip()
        return (out[:10].replace("-", "") + "-" + out[11:19].replace(":", "")) or None
    except (SystemExit, Exception):
        # SystemExit is NOT an Exception - _run_git raises it, and it must never
        # escape to kill the notarization (r8 F2)
        return None


_REFS_CAPABLE = None


def _refs_capable():
    """True when this git has the `git refs` subcommand (2.54+; adopted by
    owner order 2026-10-10). Probed with a count-limited empty listing: older
    gits exit nonzero on the unknown subcommand, capable gits succeed quietly
    regardless of repository state."""
    global _REFS_CAPABLE
    if _REFS_CAPABLE is None:
        _REFS_CAPABLE = _git_ok(["refs", "list", "--count=0"])
    return _REFS_CAPABLE


def _refs_head(ref):
    """The ref's current object id via `git refs` (exact-refname match from
    `refs list`), or None when absent. Older gits fall back to a read-only
    rev-parse probe."""
    if _refs_capable():
        if not _git_ok(["refs", "exists", ref]):
            return None
        out = _run_git(["refs", "list", "--format=%(refname) %(objectname)", ref])
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[0] == ref:
                return parts[1]
        return None
    if not _git_ok(["rev-parse", "--verify", "--quiet", ref]):
        return None
    return _run_git(["rev-parse", ref]).strip()


def _chain_predecessor_digest(head, ref):
    """sha256 of the chain predecessor's note bytes - the SAME mac-carrying
    ancestor `_chain_predecessor_commit` selects (git-log order over all
    ancestors, HEAD excluded; a merge may bind through its second parent) -
    or None when the chain is at GENESIS. The notarization window guard
    compares this before and after the write."""
    c = _chain_predecessor_commit(head, ref)
    if c is None:
        return None
    return hashlib.sha256(_run_git(["notes", "--ref", ref, "show", c],
                                   binary=True)).hexdigest()


def cmd_record(ref):
    """Post-commit NOTARIZATION (fail-closed): write a durable git note for HEAD only when
    every changed code blob matches a fresh CLEAR row (or a provenance-matched OVERRIDE).
    A post-commit step cannot undo a commit - but it can refuse to bless one: on any
    mismatch it writes NOTHING and exits 1, and the ABSENCE of a note is exactly the
    signal the audit tripwire (adversary_audit.py) keys on."""
    if _fixture_repo():
        return 0                              # EV-045: fixture repos are never notarized
    root = _repo_root()
    head = _run_git(["rev-parse", "HEAD"]).strip()
    files, removals = _changed_code_in_commit(head)
    changed = dict(files)
    changed.update(removals)
    if not changed:
        return 0                              # docs/manifests-only commit: nothing to notarize
    if _git_ok(["notes", "--ref", ref, "show", head]):
        return 0                              # already notarized (hook and driver both call this)
    note = None
    clear = _load_clear(root)                 # read once for both note paths; the
    ovp = os.path.join(_adv_dir(root), "override_used.json")   # OVERRIDE branch also
    if os.path.isfile(ovp):                   # feeds it to adjudication below
        try:
            ov = json.loads(open(ovp, encoding="utf-8").read())
        except ValueError:
            ov = {}
        os.remove(ovp)                        # one-shot either way
        if ov.get("docs_only"):
            sys.stderr.write("adversary record: a docs-only OVERRIDE cannot bless a code "
                             "commit - discarded.\n")
        elif ov.get("staged") == changed:
            note = {"type": "OVERRIDE", "commit": head, "when": ov.get("when"),
                    "reason": ov.get("reason", ""),
                    "files": {k: {"sha": v} for k, v in changed.items()}}
        else:
            sys.stderr.write("adversary record: override_used.json does not match HEAD's "
                             "blobs - discarded (a stale override cannot bless this commit).\n")
    if note is None:
        _epoch_now = _current_rules_epoch(root)   # H4: epoch-bound notarization
        bad = [k for k, sha in changed.items()
               if not (clear.get(k) and clear[k].get("sha") == sha
                       and clear[k].get("verdict") in ("CLEAR", "WARN")
                       and str(clear[k].get("epoch", "0")) == _epoch_now)]
        if bad:
            sys.stderr.write("adversary record: HEAD %s NOT notarized - no matching "
                             "clearance for:\n%s"
                             "The audit tripwire WILL flag this commit.\n"
                             % (head[:12], "".join("  %s\n" % k for k in bad)))
            return 1
        arts = {}
        for k in changed:
            rel = clear[k].get("artifact")
            if rel and rel not in arts:
                p = os.path.join(root, rel)
                if os.path.isfile(p):
                    arts[rel] = open(p, encoding="utf-8", errors="replace").read()[:100_000]
        note = {"type": "CLEAR", "commit": head, "caller": _caller(),
                "when": datetime.datetime.now().strftime("%Y%m%d-%H%M%S"),
                "files": {k: {"sha": changed[k], "model": clear[k].get("model"),
                              "verdict": clear[k].get("verdict"),
                              "when": clear[k].get("when"),
                              "artifact": clear[k].get("artifact")} for k in changed},
                "artifacts": arts}
        try:
            from enforcement_runtime import ROOT as tools_origin, CERTIFIED_CATALOG as installed_catalog
            if str(tools_origin).lower().replace("\\", "/") == root.lower().replace("\\", "/"):
                certified = {}
                for name in installed_catalog:
                    sha = hashlib.sha256(_run_git(["show", head + ":" + name], binary=True)).hexdigest()
                    row = clear.get(name) or {}
                    # Certified runtime installs demand an UNQUALIFIED CLEAR (gate
                    # round gate_20261008-135545, MEDIUM): a WARN row never
                    # authorizes machine-wide enforcement byte deployment.
                    if row.get("sha") != sha or row.get("verdict") != "CLEAR":
                        break
                    certified[name] = {key: row.get(key) for key in ("sha", "model", "when", "artifact")}
                if len(certified) == len(installed_catalog):
                    note["files"].update(certified)
        except (ImportError, SystemExit):
            pass  # No full-catalog credit: installer will require prior exact evidence.
    # Owner order 2026-09-21 (true-rate recording): classify this commit's denial
    # cycle, embed the summary in the notary note, append the full episode after.
    # Adjudication failure must never block a notarization - it degrades loudly.
    # `after` anchors the cycle at the PREVIOUS commit's note: a BLOCK older than
    # the last landing is an abandoned change's, never this commit's initial denial.
    episode = None
    try:
        # `after` anchors the cycle at the PREVIOUS commit's cycle close (its note's
        # clearing-round 'when', else its record 'when', else its commit time): a
        # BLOCK older than that is an abandoned change's, never this commit's.
        # Inside the try and Exception-broad: adjudication plumbing must NEVER block
        # a notarization (r6 F2).
        after = _cycle_floor(head, ref)
        episode = _adjudicate_cycle(root, head, changed,
                                    clear if note["type"] == "CLEAR" else {},
                                    note["type"], after)
        if episode:
            note["adjudication"] = {"denial": episode["denial_artifact"],
                                    "outcomes": episode["outcome_counts"],
                                    "detail": ".adversary/adjudications.json"}
    except (SystemExit, Exception) as exc:   # SystemExit escapes bare-Exception
        sys.stderr.write("adversary record: adjudication skipped (%s) - the notarization "
                         "stands, the episode is NOT recorded.\n" % str(exc)[:120])
    # T3.3 / H1 (owner ruling D1): the embedded artifacts must hash to the bytes on
    # disk (a forged/tampered .adversary/reviews file cannot bless a commit),
    # and the note carries an HMAC over its canonical body chained to the
    # prior notarized note - the auditor verifies both.
    key, key_created = _note_hmac_key(root)
    if "artifacts" in note:
        arts_sha = {}
        for rel, embedded in list(note["artifacts"].items()):
            disk_p = os.path.join(root, rel.replace("/", os.sep))
            # text-mode reads on BOTH sides: the artifact was written through
            # Windows text mode (CRLF on disk, LF in the embedded str) - compare
            # like-for-like content, not newline identity
            disk_s = (open(disk_p, encoding="utf-8", errors="replace").read()[:100_000]
                      if os.path.isfile(disk_p) else "")
            emb_sha = hashlib.sha256(embedded.encode("utf-8", "replace")).hexdigest()
            disk_sha = hashlib.sha256(disk_s.encode("utf-8", "replace")).hexdigest()
            arts_sha[rel] = {"embedded": emb_sha, "disk": disk_sha}
            if emb_sha != disk_sha:
                sys.stderr.write("adversary record: artifact %s does not match the bytes on disk -"
                                 " tampered or forged evidence; NOT notarizing.%s" % (rel, "\n"))
                return 1
        note["artifacts_sha256"] = arts_sha
    note.pop("_prior_mac", None)
    note["mac_key_created"] = key_created   # INSIDE the mac body (gate catch:
    # any field added after the mac changes the hashed body - the auditor
    # recomputes over the full note minus mac)
    # T1 (owner order 2026-10-10, git 2.56 adoption): guard the notarization
    # window. The HMAC binds to the note of the most recent mac-carrying
    # ANCESTOR (git-log order - for merges that may be the second parent); a
    # concurrent writer REPLACING that note between our read and our write
    # would chain this note to stale bytes the auditor will flag. Sibling
    # notaries (notes for other commits) are legitimate and tolerated - the
    # invariant is the predecessor's bytes, not the ref tip. Capture the
    # predecessor digest and the ref value first; after the write verify the
    # ref moved, the predecessor is untouched, and our note is readable. On
    # any mismatch, remove our note and fail closed (re-run record to retry).
    notes_old = _refs_head(ref)
    prior_digest = _chain_predecessor_digest(head, ref)
    note["mac"] = _chain_mac(key, note, _prior_note_mac(root, head, ref))
    tmp = os.path.join(_adv_dir(root), "note.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(note, f, indent=1)
    _run_git(["notes", "--ref", ref, "add", "-F", tmp, head])
    os.remove(tmp)
    try:
        # SystemExit-safe: a predecessor note that becomes unreadable inside
        # the window surfaces as _run_git's SystemExit - that is a FAILED
        # verification, never an escape past the cleanup (round
        # gate_20261010-220719, LOW: the raw exit skipped note removal and a
        # later record re-run would falsely report success).
        ok = (_refs_head(ref) not in (None, notes_old)
              and _chain_predecessor_digest(head, ref) == prior_digest
              and _git_ok(["notes", "--ref", ref, "show", head]))
    except SystemExit:
        ok = False
    if not ok:
        if _git_ok(["notes", "--ref", ref, "show", head]):
            _run_git(["notes", "--ref", ref, "remove", head])
        sys.stderr.write("adversary record: the notarization window was raced "
                         "(chain predecessor replaced or the note did not land) - "
                         "our note removed, NOT notarized; re-run record once the "
                         "concurrent writer is done.\n")
        return 1
    print("adversary record: %s note written for %s (%d file(s))"
          % (note["type"], head[:12], len(changed)))
    if episode:
        try:
            # success is reported ONLY on real persistence - _append returns False
            # (lock busy) without raising, and the note's adjudication block would
            # then point at a row that does not exist (r7 F3)
            if _append_adjudication(root, episode):
                print("adversary record: adjudication %s -> %s"
                      % (episode["denial_artifact"], episode["outcome_counts"]))
            else:
                # honest recovery note: the note-exists guard makes a re-run of
                # `record` a no-op, so the episode is lost for this commit (r8 F4)
                sys.stderr.write("adversary record: the note's adjudication block "
                                 "references an episode NOT in adjudications.json - "
                                 "it is LOST for this commit (re-running record is a "
                                 "no-op once the note exists); the gap is recorded "
                                 "here and visible against the file's episode list.\n")
        except (SystemExit, Exception) as exc:
            sys.stderr.write("adversary record: adjudication NOT persisted (%s) - the "
                             "episode is lost for this commit.\n" % str(exc)[:120])
    # G39 docket reminder (owner order 2026-08-31; enforcement added 2026-09-21): when a
    # BLOCK artifact exists from the last 48h, this commit is plausibly a remediation - the
    # catch OWES a row in the evidence docket, written in the SAME working session.
    try:
        cutoff = datetime.datetime.now() - datetime.timedelta(hours=48)
        rvw = os.path.join(_adv_dir(root), "reviews")
        flagged = [f for f in os.listdir(rvw) if f.startswith("gate_")
                   and os.path.getmtime(os.path.join(rvw, f)) >= cutoff.timestamp()
                   and "VERDICT: BLOCK" in open(os.path.join(rvw, f),
                                                encoding="utf-8", errors="replace").read()]
        if flagged:
            print("G39 DOCKET: %d BLOCK review(s) in the last 48h - if this commit "
                  "remediates a gate catch, add a row to colibri-code-review/docs/"
                  "gate_evidence.json (GATE_EVIDENCE_DOCKET.md) NOW, same session; "
                  "rows are never deleted, false rebuttals are the strongest rows." % len(flagged))
    except Exception:
        pass
    return 0


def _has_remote_tracking_refs(remote):
    """True when refs/remotes/<remote>/ holds anything - what the local clone last saw
    published on that remote; False for a URL-only or unknown remote. The exclusion itself is
    the ref GLOB `--remotes=<remote>/*` (one argv token however many refs exist - a sha list
    crossed the Windows command-line ceiling at ~790 refs, gate round 2 gate_20260909-153226);
    git resolves the glob itself, skipping a dangling symref (origin/HEAD after a server-side
    rename, gate round 1 gate_20260909-151127) and peeling a fetched tag."""
    out = _run_git(["for-each-ref", "--count=1", "--format=%(objectname)", "refs/remotes/%s/" % remote])
    return bool(out.strip())


def cmd_check_push(remote):
    """The pre-push PUSH GUARD (owner order 2026-08-31: notes are MANDATORY - a push
    is refused without them). Reads the pre-push stdin protocol (one line per ref:
    '<local ref> <local sha> <remote ref> <remote sha>'), audits every OUTGOING commit
    that changes code for the EXISTENCE of its adversary note (full sha verification is
    the auditor's job - record only ever writes matching notes, and CI re-verifies),
    then pushes refs/notes/adversary to the same remote so the evidence always travels
    with the history. Skips: refs/notes/* updates (recursion guard), ref deletions
    (nothing outgoing), and commits at or below .githooks/adversary_baseline (their
    clearances were transient by design - not retroactively provable)."""
    if os.environ.get("ADVERSARY_NOTES_PUSH") == "1":
        return 0                                # our own notes push - never recurse
    root = _repo_root()
    zero = "0" * 40
    baseline = None
    bp = os.path.join(root, ".githooks", "adversary_baseline")
    if os.path.isfile(bp):
        b = open(bp, encoding="utf-8").read().strip().split()
        # ROOT (armed at birth) is a SENTINEL, never resolved as a revision: a ref literally
        # named ROOT must not exclude anything (gate round 2, gate_20260908-224532)
        if b and b[0] != "ROOT" and _git_ok(["rev-parse", "--verify", "--quiet", b[0] + "^{commit}"]):
            baseline = b[0]
    audited_a_ref = False
    for line in sys.stdin.read().splitlines():
        parts = line.split()
        if len(parts) != 4:
            continue
        lref, lsha, rref, rsha = parts
        if lref.startswith("refs/notes/") or rref.startswith("refs/notes/"):
            continue
        if lsha == zero:
            continue                            # deleting a remote ref: nothing outgoing
        # ONE --not for all exclusions: --not TOGGLES in rev-list, so a second
        # occurrence would flip the baseline back to INCLUDED and drag the entire
        # pre-baseline history into the audit (caught live on the first real push)
        excl = []
        remote_known = rsha != zero and _git_ok(["cat-file", "-e", rsha])
        if remote_known:
            excl.append(rsha)
        if baseline:
            excl.append(baseline)
        # `revs` is the FULL outgoing set (remote tip when known, else the baseline only): the
        # hard-literal floor and the note audit always cover all of it - tracking refs are a
        # local snapshot the remote may have moved away from (gate round 3, gate_20260909-155108)
        args = ["rev-list", lsha] + (["--not"] + excl if excl else [])
        revs = _run_git(args).split()
        doc_revs = revs
        anchors = [rsha] if remote_known else []    # what the hard-literal recipe rebases onto
        if not remote_known and revs and _has_remote_tracking_refs(remote):
            # a NEW ref on the remote: the docs MODEL is not re-fed commits reachable from that
            # remote's own tracking refs (their doc lines were scanned when first pushed;
            # push-guard catch 2026-09-09: excluding only the baseline re-fed 124 published
            # commits, whose shifted chunk boundaries then refused a four-commit docs branch).
            # ONE glob token, never a sha list (gate round 2). Loud, like every other skip.
            doc_revs = _run_git(["rev-list", lsha, "--not", "--remotes=%s/*" % remote]
                                + ([baseline] if baseline else [])).split()
            n_pub = len(revs) - len(doc_revs)
            if n_pub:
                sys.stderr.write("adversary push guard: %d of %d outgoing commit(s) are already on "
                                 "%s's tracking refs - they get the pattern floor and the note audit "
                                 "but are NOT re-fed to the docs model (`git fetch --prune %s` first "
                                 "if those refs may be stale).\n" % (n_pub, len(revs), remote, remote))
        if not remote_known:
            # the recipe anchors at the FORK POINT: the parent of the OLDEST unpublished commit
            # (rev-list is newest-first), never at whichever tracking tip happened to list
            # first (gate round 1, gate_20260909-151127); a root commit has no parent
            if doc_revs and _git_ok(["rev-parse", "--verify", "--quiet", doc_revs[-1] + "^"]):
                anchors.append(_run_git(["rev-parse", doc_revs[-1] + "^"]).strip())
            if baseline:
                anchors.append(baseline)
        # the secret barrier runs BEFORE the note audit so a secret is reported even on
        # notarized history (EV-046); `remote_known` stays honest - with the tip unknown the
        # recipe keeps warning that listed commits may already be published elsewhere
        if _push_secret_barrier(lref, revs, anchors, remote_known, doc_revs):
            return 1
        boundaries = _shallow_boundaries()
        bad = []
        for rev in revs:
            if rev in boundaries:
                continue                        # a shallow boundary came FROM the remote; the
                                                # notes ref is not part of a depth-limited clone

            files, removals = _changed_code_in_commit(rev)
            if (files or removals) and not _git_ok(["notes", "--ref", NOTES_REF, "show", rev]):
                subj = _run_git(["log", "-1", "--format=%s", rev]).strip()
                bad.append("%s  %s" % (rev[:12], subj[:70]))
        if bad:
            sys.stderr.write(
                "\nADVERSARY PUSH GUARD: push of %s REFUSED - outgoing code commits "
                "carry NO adversary note (un-notarized history must not reach the "
                "remote):\n%s\nIf these predate the tripwire, move nothing - the "
                "baseline (.githooks/adversary_baseline) should already exclude them; "
                "a wrong baseline is an installer problem, re-run install_gate.py. "
                "Otherwise: clear and re-commit, or the owner rules.\n\n"
                % (lref, "".join("  %s\n" % b for b in bad)))
            return 1
        audited_a_ref = True
    if audited_a_ref and _git_ok(["rev-parse", "--verify", "--quiet", NOTES_REF]):
        env = dict(os.environ)
        env["ADVERSARY_NOTES_PUSH"] = "1"
        p = subprocess.run([GIT, "push", remote, NOTES_REF], capture_output=True, env=env)
        if p.returncode != 0:
            sys.stderr.write(
                "\nADVERSARY PUSH GUARD: the branch audit PASSED but pushing the notes "
                "ref FAILED - refusing the push (notes are mandatory, the evidence "
                "travels or nothing does). Remote said:\n%s\nIf notes diverged (another "
                "clone pushed notes), recover with:\n"
                "  git fetch %s +refs/notes/adversary:refs/notes/adversary-theirs\n"
                "  git notes --ref refs/notes/adversary merge -s cat_sort_uniq "
                "refs/notes/adversary-theirs\nthen push again.\n"
                "If you just REWROTE history (filter-repo) and rebuilt the notes, do NOT merge - "
                "the remote notes name commits that no longer exist. Force-push the notes ref "
                "FIRST, then the branch:\n"
                "  git push --force %s refs/notes/adversary\n\n"
                % (p.stderr.decode("utf-8", "replace")[:300], remote, remote))
            return 1
    return 0


def cmd_write_review_status(review_id):
    """Read one sanitized review, without exposing arbitrary state or granting clearance."""
    from pathlib import Path
    import stat
    if not re.fullmatch(r"[0-9a-f]{32}", review_id):
        print("Invalid write-review identifier")
        return 2
    root = Path(_repo_root()).resolve(strict=True)
    artifact = root / ".adversary" / "write-reviews" / (review_id + ".json")
    try:
        for path in (root / ".adversary", artifact.parent, artifact):
            info = path.lstat()
            if path.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
                raise ValueError("linked review path")
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 1_000_000:
            raise ValueError("unsafe or oversized review")
        if artifact.resolve(strict=True) != artifact.absolute():
            raise ValueError("aliased review path")
        with artifact.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            raw = stream.read(1_000_001)
        after = artifact.stat()
        def stamp(value):
            return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_nlink)
        if stamp(info) != stamp(opened) or stamp(info) != stamp(after) or len(raw) > 1_000_000:
            raise ValueError("review changed during read")
        record = json.loads(raw.decode("utf-8"))
        result = {key: record.get(key) for key in
                  ("path", "before_sha256", "after_sha256", "model", "outcome", "attempts", "review")}
        def sanitize(value):
            if isinstance(value, str):
                # Scrub raw text before JSON escapes its line breaks/quotes. The
                # assignment heuristic deliberately skips >4096-char segments;
                # hide those segments rather than promising unsafe redaction.
                bounded = "\n".join(line if len(line) <= 4096 else
                                    "<REDACTED:oversized-line>" for line in value.split("\n"))
                return _scrub_text(bounded)[0]
            if isinstance(value, list):
                return [sanitize(item) for item in value]
            if isinstance(value, dict):
                return {sanitize(key): sanitize(item) for key, item in value.items()}
            return value
        print(json.dumps(sanitize(result)))
        return 0
    except (OSError, ValueError, AttributeError, RecursionError) as exc:
        category = ("filesystem error " + str(exc.errno)) if isinstance(exc, OSError) else type(exc).__name__
        print("Write-review evidence unavailable or unsafe: " + category)
        return 2


def _cache_drift_alarm(root, staged_keys, usage):
    """T2.2 (owner order 2026-10-08): round N+1 of the same landing should hit the
    provider prompt cache; ~0 cached tokens on a big prompt with an overlapping
    prior round means the stable prefix rotated mid-landing. One loud line."""
    try:
        prompt = usage.get("prompt_tokens", 0) or 0
        cached = (usage.get("prompt_tokens_details") or {}).get("cached_tokens", 0) or 0
        if prompt < 30_000 or cached > 0:
            return
        adv = _adv_dir(root)
        p = os.path.join(adv, "reviews", "staged_shas.json")
        if not os.path.isfile(p):
            return
        rows = json.loads(open(p, encoding="utf-8").read())
        for name in sorted(rows, reverse=True)[:8]:
            prior_staged = (rows.get(name) or {}).get("staged") or {}
            if prior_staged and set(prior_staged) & set(staged_keys):
                art = os.path.join(adv, "reviews", name)
                head = open(art, encoding="utf-8", errors="replace").readline()
                # absent cached_tokens == zero (legacy headers): skip both
                if "cached_tokens': 0" in head or "cached_tokens" not in head:
                    continue
                print("adversary gate: CACHE DRIFT - %d prompt tokens with 0 cached on "
                      "a payload overlapping prior round %s: the stable prefix rotated "
                      "(staged bytes changed mid-landing?)." % (prompt, name))
                return
    except Exception:
        pass

def _current_rules_epoch(root):
    """T3.1 / hole H4 (gate top-to-bottom): the rules epoch the working tree
    reviews under. Absent file = epoch '0' (pre-epoch repos stay armed)."""
    p = os.path.join(root, RULES_EPOCH_FILE)
    try:
        val = open(p, encoding="utf-8", errors="replace").read().strip()
        return val or "0"
    except OSError:
        return "0"

def _note_hmac_key(root):
    """T3.3 / hole H1: the gate-held HMAC key (owner ruling D1). Created on first
    use: line 1 = '# created=<iso>', line 2 = 64 hex chars. Detection posture -
    the key binds notes to this machine's gate; a human-at-shell forger without
    the key cannot produce a chain-valid note."""
    import secrets
    adv = _adv_dir(root)
    os.makedirs(adv, exist_ok=True)
    p = os.path.join(adv, "note_hmac.key")
    if os.path.isfile(p):
        lines = open(p, encoding="utf-8", errors="replace").read().splitlines()
        for ln in lines:
            t = ln.strip()
            if len(t) == 64 and re.fullmatch(r"[0-9a-f]{64}", t):
                return bytes.fromhex(t), _key_created(lines)
        raise SystemExit("ADVERSARY GATE: note_hmac.key is corrupt - refusing to "
                         "notarize (restore the key or delete it to re-key; see "
                         "docs/plans/2026-10-09-note-integrity-hmac.md)")
    key = secrets.token_bytes(32)
    created = datetime.datetime.now().isoformat(timespec="seconds")
    with open(p, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("# created=%s\n%s\n" % (created, key.hex()))
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
    return key, created


def _key_created(lines):
    for ln in lines:
        if ln.startswith("# created="):
            return ln.split("=", 1)[1].strip()
    return ""


def _chain_predecessor_commit(head, ref=NOTES_REF):
    """The most recent ANCESTOR commit whose note carries a mac - the chain
    link target _prior_note_mac binds the HMAC to. Selected by `git log`
    order over ALL ancestors (for a merge this can be the second parent or an
    earlier ancestor when the first parent carries no mac); HEAD itself is
    excluded - the chain points BACKWARD from each new note."""
    commits = _run_git(["log", "--format=%H", head]).split()
    for c in commits[1:]:
        if not _git_ok(["notes", "--ref", ref, "show", c]):
            continue
        try:
            prior = json.loads(_run_git(["notes", "--ref", ref, "show", c]))
        except ValueError:
            continue
        if prior.get("mac"):
            return c
    return None


def _prior_note_mac(root, head, ref=NOTES_REF):
    """The most recent ANCESTOR commit's note mac (chain link); GENESIS when none.
    HEAD itself is excluded - the chain points BACKWARD from each new note."""
    c = _chain_predecessor_commit(head, ref)
    if c is None:
        return "GENESIS"
    return json.loads(_run_git(["notes", "--ref", ref, "show", c]))["mac"]


def _chain_mac(key, note, prior):
    import hmac as _h
    body = dict(note)
    body.pop("mac", None)
    payload = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return _h.new(key, (payload + "|" + str(prior)).encode("utf-8"),
                  "sha256").hexdigest()

_DOCSCAN_CACHE_MAX = 500


def _docscan_cache_lookup(root, text):
    """T4.4: return a cached CLEAR result dict, or None. Key axis = model
    fingerprint + rules epoch + sha256(text); any mismatch drops the file."""
    try:
        import hashlib as _hl
        p = os.path.join(_adv_dir(root), "docscan_cache.json")
        if not os.path.isfile(p):
            return None
        d = json.loads(open(p, encoding="utf-8").read())
        fp = docscan.model_fingerprint() if docscan else "no-module"
        if (d.get("model") != fp
                or str(d.get("epoch")) != str(_current_rules_epoch(root))):
            return None
        row = (d.get("entries") or {}).get(_hl.sha256(
            text.encode("utf-8", "replace")).hexdigest())
        if row and row.get("status") == "clear":
            return {"status": "clear",
                    "detail": "cached: " + str(row.get("detail", ""))[:120],
                    "chunks": row.get("chunks", 0), "capped": row.get("capped", False)}
        return None
    except (OSError, ValueError):
        return None


def _docscan_cache_store(root, text, res):
    """T4.4: persist a CLEAR verdict (block/degraded are never cached)."""
    if not res or res.get("status") != "clear":
        return
    try:
        import hashlib as _hl
        adv = _adv_dir(root)
        os.makedirs(adv, exist_ok=True)
        fd = _adv_lock(adv, "docscan_cache", deadline_s=2)
        if fd is None:
            return
        try:
            p = os.path.join(adv, "docscan_cache.json")
            d = {}
            if os.path.isfile(p):
                try:
                    d = json.loads(open(p, encoding="utf-8").read())
                except ValueError:
                    d = {}
            fp = docscan.model_fingerprint() if docscan else "no-module"
            if (d.get("model") != fp
                    or str(d.get("epoch")) != str(_current_rules_epoch(root))):
                d = {"model": fp, "epoch": str(_current_rules_epoch(root)),
                     "entries": {}}
            d.setdefault("entries", {})[_hl.sha256(
                text.encode("utf-8", "replace")).hexdigest()] = {
                "status": "clear", "chunks": res.get("chunks", 0),
                "capped": bool(res.get("capped")),
                "detail": str(res.get("detail", ""))[:160],
                "when": datetime.datetime.now().strftime("%Y%m%d-%H%M%S")}
            d["entries"] = dict(list(d["entries"].items())[-_DOCSCAN_CACHE_MAX:])
            tmp = p + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(d, fh, indent=1)
            os.replace(tmp, p)
        finally:
            _adv_unlock(adv, "docscan_cache", fd)
    except Exception:
        pass


def cmd_explain(path):
    """T5a (owner order 2026-10-09): why is this file unreviewed/stale? One command
    prints the clearance row (sha match vs staged, verdict, tier, epoch vs current,
    model, artifact) and the artifact's findings head - no more hand-reading
    clearance.json and matching artifacts by eye."""
    root = _repo_root()
    clear = _load_clear(root)
    row = clear.get(path)
    print(path)
    if not row:
        print("  no clearance row - unreviewed (run: python adversary_gate.py run)")
        return 0
    staged = None
    try:
        staged = _staged_sha(path)
    except BaseException:            # _run_git raises SystemExit (a BaseException)
        staged = None                # for unstaged paths - that is an ANSWER, not a crash
    epoch_now = _current_rules_epoch(root)
    sha_state = ("(matches staged)" if staged is not None and row.get("sha") == staged
                 else "(STALE - staged bytes differ or file not staged)")
    print("  verdict: %s | tier: %s | epoch: %s%s"
          % (row.get("verdict"), row.get("tier", "n/a"), row.get("epoch", "0"),
             "" if str(row.get("epoch", "0")) == epoch_now
             else " (CURRENT %s - stale, re-review needed)" % epoch_now))
    print("  sha: %s %s" % (str(row.get("sha", ""))[:16], sha_state))
    print("  model: %s | reviewed: %s" % (row.get("model"), row.get("when")))
    art = row.get("artifact")
    if art:
        p = os.path.join(root, str(art))
        present = os.path.isfile(p)
        print("  artifact: %s (%s)" % (art, "present" if present else "MISSING"))
        if present:
            head = open(p, encoding="utf-8", errors="replace").read(800)
            for line in head.splitlines()[:6]:
                print("    | " + line[:140])
    return 0


def cmd_costs(days=30):
    """T2.1 (owner order 2026-10-08): aggregate the usage blocks already stamped
    in every review artifact header into the re-pinning table: model, rounds,
    tokens, cached share, cost. Read-only; unknown/legacy headers degrade to a
    counted 'unparsed' row, never a crash."""
    import datetime as _dt
    root = _repo_root()
    rvw = os.path.join(_adv_dir(root), "reviews")
    if not os.path.isdir(rvw):
        print("adversary costs: no review artifacts.")
        return 0
    cutoff = _dt.datetime.now() - _dt.timedelta(days=days)
    rows = {}
    unparsed = 0
    for name in sorted(os.listdir(rvw)):
        if not (name.startswith("gate_") and name.endswith(".md")):
            continue
        p = os.path.join(rvw, name)
        try:
            if _dt.datetime.fromtimestamp(os.path.getmtime(p)) < cutoff:
                continue
            head = open(p, encoding="utf-8", errors="replace").readline()
        except OSError:
            continue
        m = re.match(r"model: ([^ |]+) .*usage: (\{.*\}) ", head)
        if not m:
            unparsed += 1
            continue
        model = m.group(1)
        try:
            u = json.loads(m.group(2).replace("'", '"'))
        except ValueError:
            unparsed += 1
            continue
        r = rows.setdefault(model, {"rounds": 0, "in": 0, "cached": 0, "out": 0, "$": 0.0})
        r["rounds"] += 1
        r["in"] += u.get("prompt_tokens", 0)
        r["cached"] += (u.get("prompt_tokens_details") or {}).get("cached_tokens", 0)
        r["out"] += u.get("completion_tokens", 0)
        r["$"] += float(u.get("cost", 0) or 0)
    if not rows:
        print("adversary costs: no parseable review headers in the last %d day(s)." % days)
        return 0
    print("%-46s %6s %12s %12s %10s %9s" % ("model", "rounds", "tok in", "tok cached",
                                            "tok out", "$"))
    total = 0.0
    for model in sorted(rows, key=lambda k: -rows[k]["$"]):
        r = rows[model]
        total += r["$"]
        print("%-46s %6d %12d %12d %10d %9.4f"
              % (model, r["rounds"], r["in"], r["cached"], r["out"], r["$"]))
    print("%-46s %6s %12s %12s %10s %9.4f"
          % ("TOTAL", "", "", "", "", total))
    if unparsed:
        print("(%d artifact header(s) unparsed - legacy or malformed)" % unparsed)
    return 0

def cmd_status():
    root = _repo_root()
    clear = _load_clear(root)
    for f in _staged_code_files():
        sha = _staged_sha(f)
        row = clear.get(f)
        state = ("CLEAR" if row and row.get("sha") == sha
                 and row.get("verdict") in ("CLEAR", "WARN")
                 else ("stale" if row else "unreviewed"))
        print("%-60s %s" % (f, state))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Mandatory pre-commit adversarial review gate.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check")
    sub.add_parser("verify", help="check existing clearance without requesting review")
    r = sub.add_parser("run")
    r.add_argument("--model", default=DEFAULT_MODEL)
    r.add_argument("--context", default="")
    rec = sub.add_parser("record")
    rec.add_argument("--ref", default=NOTES_REF)
    cp = sub.add_parser("check-push")
    cp.add_argument("remote")
    ex = sub.add_parser("explain",
                        help="why is one file unreviewed/stale? prints its clearance row + artifact head")
    ex.add_argument("path")
    costs = sub.add_parser("costs",
                           help="aggregate review cost/usage from artifact headers")
    costs.add_argument("--days", type=int, default=30)
    status = sub.add_parser("status")
    status.add_argument("--write-review", help="read one sanitized write-review by its 32-character identifier")
    ad = sub.add_parser("audit-drain",
                        help="drain queued tier-1 batch audits (post-hoc; never blocks commits)")
    ad.add_argument("--limit", type=int, default=4)
    a = ap.parse_args(argv)
    if a.cmd == "check":
        return cmd_check(auto_review=True)
    if a.cmd == "verify":
        return cmd_check()
    if a.cmd == "run":
        return cmd_run(a.model, a.context)
    if a.cmd == "record":
        return cmd_record(a.ref)
    if a.cmd == "check-push":
        return cmd_check_push(a.remote)
    if a.cmd == "explain":
        return cmd_explain(a.path)
    if a.cmd == "costs":
        return cmd_costs(a.days)
    if a.cmd == "audit-drain":
        return cmd_audit_drain(a.limit)
    return cmd_write_review_status(a.write_review) if a.write_review else cmd_status()


if __name__ == "__main__":
    sys.exit(main())
