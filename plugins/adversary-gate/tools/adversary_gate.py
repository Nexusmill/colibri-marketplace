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
# Owner ruling 2026-09-16 (31 live runs of this gate's own PROMPT against planted defects,
# fleet docs/design/2026-09-16-provider-pins.md): deepseek-v4-flash RETURNS as the middle
# entry, PINNED to the two OpenRouter endpoints that completed every run - the 2026-09-03
# emptying was one provider's behaviour (DeepInfra served it with no reasoning and missed a
# planted defect). A chain entry `model@tag1+tag2` pins provider.order to those endpoint
# tags, in that order, with fallbacks OFF; an entry whose pinned endpoints are all down
# gets an error payload, which advances the chain like any transport failure. glm stays
# primary and unpinned (a 30k-reasoning-token review needs its fast providers); grok is the
# last chance. ADVERSARY_MODEL / --model still override the whole chain.
DEFAULT_CHAIN = "z-ai/glm-5.3-flash,deepseek/deepseek-v4-flash@open-inference/fp8+gmicloud/fp8,xai:grok-4.6"
DEFAULT_MODEL = os.environ.get("ADVERSARY_MODEL", DEFAULT_CHAIN)
MAX_FILE_BYTES = 250_000          # per staged file included in full
MAX_TOTAL_BYTES = 900_000         # whole prompt budget (hy3 ctx 262k tokens)

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
    "point it factually settles. Repo doctrine you must not re-litigate: a "
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


def _is_code(path, hook_names=True):
    return (path.startswith(GATED_PREFIXES) or os.path.splitext(path)[1].lower() in CODE_EXTS
            or (hook_names and os.path.basename(path) in HOOK_NAMES))


_EPOCH_ANCHOR_CACHE = {}


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
    for f in oversized_docs:
        sys.stderr.write("adversary gate: doc %s is >25MB - NOT scanned by any layer (pattern "
                         "floor and the docs model both skip it; docs are not sent to the "
                         "external reviewer). Review it manually.\n" % f)
    if doc_files:
        try:
            res = (docscan.scan(_staged_doc_added_text(doc_files)) if docscan
                   else {"status": "degraded", "detail": "docscan module unavailable"})
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
    if len(markers) == 1 and final in {"VERDICT: CLEAR", "VERDICT: BLOCK"}:
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


def _call_one_model(entry, user_content, timeout=1200):
    fake = os.environ.get("ADVERSARY_FAKE")               # selftests only - no network
    if fake:
        root = os.path.basename(_repo_root())
        if root.startswith("advgate_") and os.environ.get("ADVERSARY_SELFTEST") == "1":
            return ("(faked verdict for selftest)\nVERDICT: %s" % fake), {}, "fake"
        sys.stderr.write("ADVERSARY_FAKE ignored outside a selftest repo (adversary "
                         "finding, birth review r2) - running the REAL reviewer.\n")
    model, order = _split_entry(entry)
    if model.startswith("xai:"):                          # xAI-native backup (grok): a
        if order:                                         # different API + key; no provider
            raise SystemExit("ADVERSARY GATE: provider pins apply to OpenRouter entries only "
                             "(%r routes to api.x.ai)" % entry)   # routing there - a pin would be a lie
        return _call_xai(model[len("xai:"):], user_content, timeout)
    key = os.environ.get("OPENROUTER_API_KEY", "").strip()
    if not key:
        raise SystemExit("ADVERSARY GATE: OPENROUTER_API_KEY not set - the gate cannot run. "
                         "(Owner emergencies: see the OVERRIDE escape in the tool docstring.)")
    body = {"model": model, "temperature": 0.2,
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


def _review_header(model, usage, provider, scrubbed_count, files):
    """The first line of every review artifact; `provider:` sits after `model:` so tools that read the model keep
    working and the provider is one field to the right."""
    return "model: %s | provider: %s | usage: %s | scrubbed: %d | files: %s\n\n" % (
        model, provider, usage, scrubbed_count, files)


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
    if not files and not removals:
        print("adversary gate: no staged code files - nothing to review.")
        return 0
    # DETERMINISTIC refusal before any payload exists: a removed module-level symbol with a
    # live caller outside the staged set (2026-09-09; see _removed_symbol_callers).
    dangling = _removed_symbol_callers()
    if dangling:
        _print_removed_symbol_refusal(dangling, sys.stdout)
        return 1
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
    text, usage, model, provider = _call_model_ex(model, payload)
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    art = os.path.join(_adv_dir(root), "reviews", "gate_%s.md" % ts)
    with open(art, "w", encoding="utf-8") as fh:
        fh.write(_review_header(model, usage, provider, len(scrubbed), files) + text)
    lines = text.rstrip().splitlines()
    if not lines:                        # adversary finding (birth review): empty model
        text = "(model returned no content - failing closed)\nVERDICT: BLOCK"   # response must
        lines = text.splitlines()        # BLOCK cleanly, never IndexError
    verdict = "CLEAR" if _review_outcome(text) == "CLEAR" else "BLOCK"
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
    hn = _hook_names_apply(rev)
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
            if _is_code(path, hn):
                files[path] = _blob_sha(rev, path)
        elif code == "R":
            old, new = toks[i + 1], toks[i + 2]
            i += 3
            if _is_code(new, hn):
                files[new] = _blob_sha(rev, new)
            if _is_code(old, hn) and not _is_code(new, hn):
                removals["D:" + old] = _blob_sha(base, old)
        elif code == "D":
            old = toks[i + 1]
            i += 2
            if _is_code(old, hn):
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
            if not _is_code(path, hn) and (doc_set is None or rev in doc_set):
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
            res = (docscan.scan(doc_text) if docscan
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
    sub.add_parser("verify", help="check existing clearance without requesting review")
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
        return cmd_check(auto_review=True)
    if a.cmd == "verify":
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
