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
  a file .adversary/OVERRIDE containing a written reason lets ONE commit through with a loud
  warning, then is deleted. Using it without Damien's explicit say-so is a protocol violation.

Key: OPENROUTER_API_KEY env (never printed). Artifacts land in .adversary/reviews/ (the
directory is gitignored - transient gate state, not history; durable verdicts still go to
the repo's review archives by the normal protocol).
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
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
             # EV-029 (2026-09-04): Caliper's git-guard.mjs - a security guard - passed a gate run
             # UNREVIEWED because the ES-module / CommonJS / TS-module forms were missing here.
             ".mjs", ".cjs", ".mts", ".cts"}
# .githooks/: a hook edit could neuter the gate (birth review r2). .github/workflows/: the
# CI audit workflow is enforcement config too - editing it un-gated is the same hole
# (layered-enforcement review 2026-08-31).
GATED_PREFIXES = (".githooks/", ".github/workflows/")
NOTES_REF = "refs/notes/adversary"
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
API_URL = "https://openrouter.ai/api/v1/chat/completions"
XAI_API_URL = "https://api.x.ai/v1/responses"   # xAI-native backup (grok); different API shape
# --model accepts a comma-separated FALLBACK CHAIN: models are tried in order and the
# chain advances only on transport/provider failure (HTTP errors, exhausted 429s, an
# error payload) or an EMPTY-content response (no verdict was rendered - seen live as
# reasoning-token exhaustion) - never on a rendered verdict. The EV-004 invariant that
# survives: an empty response can never CLEAR; if the LAST model in the chain is also
# empty, cmd_run fails closed to BLOCK exactly as before. Owner ruling 2026-09-01:
# glm-5.3-flash primary (similarly priced and it FINISHES). Owner ruling 2026-09-03:
# grok-4.6 (xAI-native - an `xai:` prefix routes a chain entry to api.x.ai, NOT OpenRouter)
# takes the SECOND/backup spot, replacing deepseek-v4-flash (which emptied on heavy
# payloads); its strength backstops glm on the payloads that exhaust a flash model.
DEFAULT_MODEL = os.environ.get(
    "ADVERSARY_MODEL", "z-ai/glm-5.3-flash,xai:grok-4.6")
MAX_FILE_BYTES = 250_000          # per staged file included in full
MAX_TOTAL_BYTES = 900_000         # whole prompt budget (hy3 ctx 262k tokens)

# ---- LOCAL secret pre-scan (layered-enforcement fix 2026-09-02) --------------------------
# WHY: the gate reviews by sending the staged diff to a REMOTE model (OpenRouter), and it
# only triggered when a CODE file was staged - so (a) a docs-only commit got no review at
# all, and (b) any secret in a reviewed diff was transmitted off-machine. Both proven live:
# EV-023 (a gateway root / AP admin / printer password pasted into a memory .md) was caught
# only because .py files were co-staged, and the catch itself shipped the plaintext creds to
# the reviewer API. This pre-scan runs LOCALLY on EVERY staged file first: it blocks on
# secret material without transmitting anything, and it is not extension-gated.
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
_SECRET_PLACEHOLDER = re.compile(
    r"your|example|changeme|placeholder|redact|dummy|sample|<[^>]*>|\.\.\.|xxx|"
    r"^\*+$|^(.)\1{4,}$|^(?:true|false|yes|no|none|null|n/?a|present|set|unset|todo|"
    r"enabled?|disabled?|undefined)$", re.I)


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
    - nothing is transmitted. The transmit guard in cmd_run additionally scans the exact
    payload (removed lines included) - _scan_text_secrets."""
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
    oversized-and-omitted file's hunks, none of which appear in _scan_staged_secrets."""
    return [("<payload>", ln, label) for ln, label in _scan_one_text(text, max_hits)]


def _print_secret_block(hits, stream, extra):
    stream.write("\nADVERSARY GATE: secret material detected in the staged change - %s.\n"
                 "BLOCKED locally; values are not printed:\n" % extra)
    for path, ln, label in hits:
        stream.write("  %s:%s  %s\n" % (path, ln, label))
    stream.write("\nRemove the secret and re-stage. (Owner emergencies escape at COMMIT time "
                 "via a one-shot .adversary/OVERRIDE - never by sending secrets to the "
                 "reviewer.)\n")


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
    "point it factually settles. End with EXACTLY one line: 'VERDICT: CLEAR' if nothing "
    "real was found, or 'VERDICT: BLOCK' preceded by your findings (each: severity, file, "
    "line/symbol, trigger, impact). A confident wrong finding wastes the author's time; an "
    "unearned CLEAR ships a bug. Be exact."
)


def _run_git(args, binary=False):
    # GIT_NO_REPLACE_OBJECTS: a local `git replace <dirty> <innocent>` otherwise makes
    # diff/show read the substituted object graph, so the gate would hash the innocent
    # blob and clear a dirty commit (audit-probe finding). Ignore replace refs.
    env = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1")
    p = subprocess.run([GIT] + args, capture_output=True, env=env)
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


def _is_code(path):
    return path.startswith(GATED_PREFIXES) or os.path.splitext(path)[1].lower() in CODE_EXTS


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


def _staged_doc_files():
    """(scannable, oversized): staged non-code text files split by size. `scannable` (<=25MB,
    non-binary) go to the LOCAL docscan; `oversized` (>25MB) are too big to scan and are
    REPORTED to the user, not silently dropped - NO layer covers them (pattern floor and the
    docs model both skip >25MB, and docs are never sent to the external reviewer)."""
    scannable, oversized = [], []
    for f in _all_staged_files():
        if _is_code(f):
            continue
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
    """True iff the git command succeeds - for existence probes where failure is an answer."""
    return subprocess.run([GIT] + args, capture_output=True).returncode == 0


def cmd_check():
    root = _repo_root()
    files = _staged_code_files()   # merges are NOT exempt: a merge can carry un-gated
    # commits (adversary finding, gate birth review 2026-08-30) - the staged result is
    # reviewable like any other change
    removals = _staged_removals()
    ov = os.path.join(_adv_dir(root), "OVERRIDE")
    override = os.path.isfile(ov)
    # LOCAL secret pre-scan - the ADDED lines of ALL staged files (any extension), so a docs-only
    # commit is no longer waved through, and a secret is caught WITHOUT the diff ever
    # leaving the machine. The owner's one-shot OVERRIDE still escapes a false positive.
    secret_hits = _scan_staged_secrets()
    if secret_hits and not override:
        sys.stderr.write("\nADVERSARY GATE: commit REFUSED - staged content carries secret "
                         "material (detected locally; nothing was transmitted):\n")
        for path, ln, label in secret_hits:
            sys.stderr.write("  %s:%s  %s\n" % (path, ln, label))
        sys.stderr.write("\nRemove the secret from the staged bytes and re-stage. Values are "
                         "not printed. (Owner emergencies: a one-shot .adversary/OVERRIDE.)\n\n")
        return 1
    # DOCS half of the domain division (2026-09-03): staged doc files' ADDED content is
    # reviewed by the LOCAL model (docscan), ON-MACHINE, never sent to the external reviewer.
    # It catches prose / dictionary-word secrets the pattern floor misses. Runs EVEN under
    # OVERRIDE - so a real block is distinguished from a clean commit and the one-shot hatch
    # is consumed only when it truly bypassed a block. Graceful-degrade (loud); never crashes
    # the hook; never a silent pass.
    doc_files, oversized_docs = _staged_doc_files()
    for f in oversized_docs:
        sys.stderr.write("adversary gate: doc %s is >25MB - NOT scanned by any layer (pattern "
                         "floor and the docs model both skip it; docs are not sent to the "
                         "external reviewer). Review it manually.\n" % f)
    docs_blocked = False
    if doc_files:
        try:
            res = (docscan.scan(_staged_doc_added_text(doc_files)) if docscan
                   else {"status": "degraded", "detail": "docscan module unavailable"})
        except (Exception, SystemExit) as e:     # incl. _run_git's SystemExit on git failure -
            # the docs layer must NEVER crash the hook: a too-long pathspec / git error /
            # docscan bug degrades loudly (pattern floor + code gate still enforce).
            res = {"status": "degraded", "detail": "docs scan crashed: %s" % (str(e)[:150])}
        if res["status"] == "block":
            docs_blocked = True
            if not override:
                sys.stderr.write("\nADVERSARY GATE: commit REFUSED - the local docs reviewer "
                                 "flagged a real secret in staged documentation (%s). Values "
                                 "are not printed; open the doc to find it, or (owner) use a "
                                 "one-shot .adversary/OVERRIDE.\n\n" % res.get("detail", ""))
                return 1
        elif res["status"] == "degraded":
            sys.stderr.write("adversary gate: docs SEMANTIC review SKIPPED (%s) - the pattern "
                             "floor ran, but a prose/dictionary-word secret could pass. Install "
                             "a local model to enable it.\n" % res.get("detail", ""))
        elif res.get("capped"):
            sys.stderr.write("adversary gate: docs scan CAPPED (%s) - the tail was NOT "
                             "semantically scanned.\n" % res.get("detail", ""))
    # the OVERRIDE is genuinely USED only if it bypassed a real block (a secret hit or a docs
    # block); a routine CLEAN docs commit must NOT consume the owner's one-shot hatch.
    used_override = override and (bool(secret_hits) or docs_blocked)
    if not files and not removals:
        # docs/manifests-only: no code clearance to check. A docs-only commit is never
        # notarized (cmd_record returns early), so an OVERRIDE that ACTUALLY bypassed a secret
        # hit or a docs block records a docs_only override_used.json (staged {}) as a durable
        # audit trail; cmd_record refuses to match a docs_only entry to any code commit.
        if used_override:
            reason = open(ov, encoding="utf-8", errors="replace").read().strip()
            sys.stderr.write("\n!!! ADVERSARY GATE OVERRIDDEN (one-shot, docs-only) !!!\n"
                             "reason on file: %s\nThis is auditable.\n\n"
                             % (reason[:300] or "(none given)"))
            # durable record: staged is {} (a docs-only commit is never notarized) and the
            # docs_only flag makes `record` refuse to match it to any code commit's blobs.
            _save_json(root, "override_used.json",
                       {"reason": reason[:2000],
                        "when": datetime.datetime.now().strftime("%Y%m%d-%H%M%S"),
                        "staged": {}, "docs_only": True})
            os.remove(ov)
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
    bad = []
    for f in files:
        sha = _staged_sha(f)
        row = clear.get(f)
        if not row or row.get("sha") != sha or row.get("verdict") != "CLEAR":
            bad.append((f, "stale" if row else "unreviewed"))
    for key, sha in removals.items():
        row = clear.get(key)
        if not row or row.get("sha") != sha or row.get("verdict") != "CLEAR":
            bad.append((key, "stale" if row else "unreviewed (code removal)"))
    if not bad:
        return 0
    sys.stderr.write("\nADVERSARY GATE: commit REFUSED - staged code lacks a fresh "
                     "adversarial clearance:\n")
    for f, why in bad:
        sys.stderr.write("  %-60s %s\n" % (f, why))
    sys.stderr.write("\nRun the adversary, address its findings, then commit:\n"
                     "  python %s run\n"
                     "(re-editing a file after clearance invalidates it by design)\n\n"
                     % os.path.abspath(__file__))
    return 1


def _call_model(model, user_content, timeout=1200):
    """`model` may be a comma-separated fallback chain; returns (text, usage, model_used)."""
    chain = [m.strip() for m in model.split(",") if m.strip()]
    if not chain:
        # reachable via --model "" or ADVERSARY_MODEL="" (adversary finding, chain review
        # r1: the "unreachable" claim here was wrong) - fail closed with a clean error.
        raise SystemExit("ADVERSARY GATE: no model given (empty --model / ADVERSARY_MODEL) "
                         "- the gate cannot run.")
    for i, m in enumerate(chain):
        try:
            text, usage = _call_one_model(m, user_content, timeout)
        except SystemExit as e:
            if i + 1 < len(chain):
                sys.stderr.write("adversary model %s failed (%s) - falling back to %s\n"
                                 % (m, str(e)[:160], chain[i + 1]))
                continue
            raise
        if not text.strip() and i + 1 < len(chain):
            # Empty content = no verdict (seen live: deepseek burning its whole completion
            # budget on reasoning tokens and emitting nothing). Advancing the chain keeps
            # the EV-004 guarantee intact: an empty response can still never CLEAR - if the
            # LAST model is empty too, cmd_run's fail-closed BLOCK takes it as before.
            sys.stderr.write("adversary model %s returned no content - falling back to %s\n"
                             % (m, chain[i + 1]))
            continue
        return text, usage, m


def _call_one_model(model, user_content, timeout=1200):
    fake = os.environ.get("ADVERSARY_FAKE")               # selftests only - no network
    if fake:
        root = os.path.basename(_repo_root())
        if root.startswith("advgate_") and os.environ.get("ADVERSARY_SELFTEST") == "1":
            return ("(faked verdict for selftest)\nVERDICT: %s" % fake), {}
        sys.stderr.write("ADVERSARY_FAKE ignored outside a selftest repo (adversary "
                         "finding, birth review r2) - running the REAL reviewer.\n")
    if model.startswith("xai:"):                          # xAI-native backup (grok): a
        return _call_xai(model[len("xai:"):], user_content, timeout)   # different API + key
    key = os.environ.get("OPENROUTER_API_KEY", "").strip()
    if not key:
        raise SystemExit("ADVERSARY GATE: OPENROUTER_API_KEY not set - the gate cannot run. "
                         "(Owner emergencies: see the OVERRIDE escape in the tool docstring.)")
    body = {"model": model, "temperature": 0.2,
            "messages": [{"role": "system", "content": PROMPT},
                         {"role": "user", "content": user_content}]}
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
        except OSError as e:
            # connection refused / DNS / TLS / a MID-STREAM read timeout or socket reset -
            # the canonical transport failures. Catch OSError (not just urllib URLError): a
            # bare TimeoutError from r.read() is an OSError, NOT a URLError, so the old
            # handler let it crash cmd_run with a traceback (surfaced on a large docs-build
            # review). SystemExit fails CLOSED and advances the fallback chain. HTTPError is
            # handled above (it subclasses OSError) so its 429 retry is unaffected.
            raise SystemExit("ADVERSARY GATE: network/read error reaching OpenRouter: %r"
                             % (getattr(e, "reason", e),))
    if d.get("error"):
        raise SystemExit("ADVERSARY GATE: model error: %s" % json.dumps(d["error"])[:300])
    text = "".join(ch.get("message", {}).get("content") or "" for ch in (d.get("choices") or []))
    return text, d.get("usage", {})


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
    except OSError as e:
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

    def _walk(x):
        if isinstance(x, dict):
            if x.get("type") == "output_text" and isinstance(x.get("text"), str):
                texts.append(x["text"])
            for v in x.values():
                _walk(v)
        elif isinstance(x, list):
            for v in x:
                _walk(v)
    _walk(d.get("output", d) if isinstance(d, dict) else d)
    return "\n".join(texts), (d.get("usage", {}) if isinstance(d, dict) else {})


def cmd_run(model, context):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")   # before ANY print
    except Exception:
        pass
    root = _repo_root()
    # LOCAL secret pre-scan #1 - ADDED content across ALL staged files (docs included), so
    # a secret introduced by this change is caught and NOT sent to the external reviewer.
    secret_hits = _scan_staged_secrets()
    if secret_hits:
        _print_secret_block(secret_hits, sys.stdout,
                            "the staged content was NOT sent to the external reviewer")
        print("\n=== adversary gate: BLOCK (local secret pre-scan)")
        return 1
    files = _staged_code_files()
    removals = _staged_removals()
    if not files and not removals:
        print("adversary gate: no staged code files - nothing to review.")
        return 0
    code_paths = files + [k[2:] for k in removals]   # code files + removed code (D:oldpath)
    diff = _diff_paths(["-c", "core.quotepath=false", "diff", "--cached", "--unified=8"],
                       code_paths)   # docs excluded (doctrine); root-anchored + argv-batched
    parts = ["STAGED DIFF (the change under adversarial review):\n", diff]
    total = len(diff.encode("utf-8"))
    for f in files:
        blob = _run_git(["show", ":" + f], binary=True)
        body = blob.decode("utf-8", "replace")
        nbytes = len(blob)
        if nbytes > MAX_FILE_BYTES or total + nbytes > MAX_TOTAL_BYTES:
            parts.append("\nFULL STAGED FILE %s: OMITTED FOR SIZE (%d bytes) - judge from "
                         "the diff hunks and their context.\n" % (f, len(body)))
            continue
        parts.append("\nFULL STAGED FILE %s:\n%s\n" % (f, body))
        total += nbytes
    if context:
        parts.append("\nREBUTTAL / AUTHOR NOTES (verify, do not blindly trust):\n" + context + "\n")
    payload = "".join(parts)
    # LOCAL secret pre-scan #2 - the EXACT payload about to be transmitted, so a secret in a
    # REMOVED line, a diff hunk, or an oversized-omitted file's hunk (none in scan #1's
    # new-blob view - e.g. `git rm secret.py`, the very EV-023 remediation flow) can never
    # reach the external reviewer either.
    payload_hits = _scan_text_secrets(payload)
    if payload_hits:
        _print_secret_block(payload_hits, sys.stdout,
                            "the review payload was NOT sent to the external reviewer")
        print("\n=== adversary gate: BLOCK (local secret pre-scan, transmit payload)")
        return 1
    text, usage, model = _call_model(model, payload)
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    art = os.path.join(_adv_dir(root), "reviews", "gate_%s.md" % ts)
    with open(art, "w", encoding="utf-8") as fh:
        fh.write("model: %s | usage: %s | files: %s\n\n%s" % (model, usage, files, text))
    lines = text.rstrip().splitlines()
    if not lines:                        # adversary finding (birth review): empty model
        text = "(model returned no content - failing closed)\nVERDICT: BLOCK"   # response must
        lines = text.splitlines()        # BLOCK cleanly, never IndexError
    verdict = "CLEAR" if lines[-1].strip().upper() == "VERDICT: CLEAR" else "BLOCK"
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    print(text)
    print("\n=== adversary gate: %s | artifact: %s" % (verdict, art))
    if verdict != "CLEAR":
        print("Address the findings (or re-run with --context carrying a factual rebuttal).")
        return 1
    clear = _load_clear(root)
    for f in files:
        clear[f] = {"sha": _staged_sha(f), "verdict": "CLEAR", "when": ts,
                    "model": model, "artifact": os.path.relpath(art, root)}
    for key, sha in removals.items():
        clear[key] = {"sha": sha, "verdict": "CLEAR", "when": ts,
                      "model": model, "artifact": os.path.relpath(art, root)}
    _save_clear(root, clear)
    files = files + sorted(removals)
    print("Clearance written for %d file(s) - commit will pass while the staged bytes "
          "stay identical." % len(files))
    return 0


def _blob_sha(rev, path):
    return hashlib.sha256(_run_git(["show", rev + ":" + path], binary=True)).hexdigest()


def _changed_code_in_commit(rev):
    """Changed CODE in commit `rev` vs its FIRST parent (root commits vs the empty tree),
    with the SAME path rules as staging: returns (files {new_path: sha256 of the blob in
    rev}, removals {'D:'+old_path: sha256 of the parent blob}). This is the durable-side
    twin of _staged_code_files/_staged_removals - what a note must vouch for."""
    base = rev + "^1" if _git_ok(["rev-parse", "--verify", "--quiet", rev + "^1"]) else EMPTY_TREE
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
        if code in ("A", "C", "M", "T"):
            path = toks[i + 1]
            i += 2
            if _is_code(path):
                files[path] = _blob_sha(rev, path)
        elif code == "R":
            old, new = toks[i + 1], toks[i + 2]
            i += 3
            if _is_code(new):
                files[new] = _blob_sha(rev, new)
            if _is_code(old) and not _is_code(new):
                removals["D:" + old] = _blob_sha(base, old)
        elif code == "D":
            old = toks[i + 1]
            i += 2
            if _is_code(old):
                removals["D:" + old] = _blob_sha(base, old)
        else:
            i += 2
    return files, removals


def cmd_record(ref):
    """Post-commit NOTARIZATION (fail-closed): write a durable git note for HEAD only when
    every changed code blob matches a fresh CLEAR row (or a provenance-matched OVERRIDE).
    A post-commit step cannot undo a commit - but it can refuse to bless one: on any
    mismatch it writes NOTHING and exits 1, and the ABSENCE of a note is exactly the
    signal the audit tripwire (adversary_audit.py) keys on."""
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
    ovp = os.path.join(_adv_dir(root), "override_used.json")
    if os.path.isfile(ovp):
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
        clear = _load_clear(root)
        bad = [k for k, sha in changed.items()
               if not (clear.get(k) and clear[k].get("sha") == sha
                       and clear[k].get("verdict") == "CLEAR")]
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
        note = {"type": "CLEAR", "commit": head,
                "when": datetime.datetime.now().strftime("%Y%m%d-%H%M%S"),
                "files": {k: {"sha": changed[k], "model": clear[k].get("model"),
                              "when": clear[k].get("when"),
                              "artifact": clear[k].get("artifact")} for k in changed},
                "artifacts": arts}
    tmp = os.path.join(_adv_dir(root), "note.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(note, f, indent=1)
    _run_git(["notes", "--ref", ref, "add", "-F", tmp, head])
    os.remove(tmp)
    print("adversary record: %s note written for %s (%d file(s))"
          % (note["type"], head[:12], len(changed)))
    return 0


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
        if b and _git_ok(["rev-parse", "--verify", "--quiet", b[0] + "^{commit}"]):
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
        if rsha != zero and _git_ok(["cat-file", "-e", rsha]):
            excl.append(rsha)
        if baseline:
            excl.append(baseline)
        args = ["rev-list", lsha] + (["--not"] + excl if excl else [])
        bad = []
        for rev in _run_git(args).split():
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
                "refs/notes/adversary-theirs\nthen push again.\n\n"
                % (p.stderr.decode("utf-8", "replace")[:300], remote))
            return 1
    return 0


def cmd_status():
    root = _repo_root()
    clear = _load_clear(root)
    for f in _staged_code_files():
        sha = _staged_sha(f)
        row = clear.get(f)
        state = ("CLEAR" if row and row.get("sha") == sha and row.get("verdict") == "CLEAR"
                 else ("stale" if row else "unreviewed"))
        print("%-60s %s" % (f, state))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Mandatory pre-commit adversarial review gate.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check")
    r = sub.add_parser("run")
    r.add_argument("--model", default=DEFAULT_MODEL)
    r.add_argument("--context", default="")
    rec = sub.add_parser("record")
    rec.add_argument("--ref", default=NOTES_REF)
    cp = sub.add_parser("check-push")
    cp.add_argument("remote")
    sub.add_parser("status")
    a = ap.parse_args(argv)
    if a.cmd == "check":
        return cmd_check()
    if a.cmd == "run":
        return cmd_run(a.model, a.context)
    if a.cmd == "record":
        return cmd_record(a.ref)
    if a.cmd == "check-push":
        return cmd_check_push(a.remote)
    return cmd_status()


if __name__ == "__main__":
    sys.exit(main())
