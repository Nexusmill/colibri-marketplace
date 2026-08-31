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
import subprocess
import sys
import time
import urllib.error
import urllib.request

GIT = r"C:\Program Files\Git\cmd\git.exe"
if not os.path.isfile(GIT):
    GIT = "git"                       # relocated/foreign machine: rely on PATH
CODE_EXTS = {".py", ".js", ".json", ".ts", ".jsx", ".tsx", ".html", ".css", ".ps1", ".sh", ".bat",
             ".c", ".cpp", ".h", ".rs", ".go", ".java", ".glsl", ".osl"}
# .githooks/: a hook edit could neuter the gate (birth review r2). .github/workflows/: the
# CI audit workflow is enforcement config too - editing it un-gated is the same hole
# (layered-enforcement review 2026-08-31).
GATED_PREFIXES = (".githooks/", ".github/workflows/")
NOTES_REF = "refs/notes/adversary"
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
API_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_MODEL = os.environ.get("ADVERSARY_MODEL", "tencent/hy3")
MAX_FILE_BYTES = 250_000          # per staged file included in full
MAX_TOTAL_BYTES = 900_000         # whole prompt budget (hy3 ctx 262k tokens)

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
    p = subprocess.run([GIT] + args, capture_output=True)
    if p.returncode != 0:
        raise SystemExit("git %s failed: %s" % (" ".join(args[:2]),
                                                p.stderr.decode("utf-8", "replace")[:300]))
    return p.stdout if binary else p.stdout.decode("utf-8", "replace")


def _repo_root():
    return _run_git(["rev-parse", "--show-toplevel"]).strip()


def _staged_code_files():
    out = _run_git(["diff", "--cached", "--name-only", "--diff-filter=ACMR"])
    files = []
    for f in out.splitlines():
        f = f.strip()
        if not f:
            continue
        if _is_code(f):
            files.append(f)
    return files


def _staged_sha(path):
    return hashlib.sha256(_run_git(["show", ":" + path], binary=True)).hexdigest()


def _is_code(path):
    return path.startswith(GATED_PREFIXES) or os.path.splitext(path)[1].lower() in CODE_EXTS


def _staged_removals():
    """Deleted code files + code files renamed AWAY (old path was code) - removing or
    hiding code is a code change (adversary finding, birth review r3). Keyed as
    'D:<old path>' with the sha of the HEAD blob being removed."""
    out = _run_git(["diff", "--cached", "--name-status", "-M", "--diff-filter=DR"])
    keys = {}
    for line in out.splitlines():
        bits = line.split("\t")
        if not bits or not bits[0]:
            continue
        st = bits[0][0]
        if st == "D" and len(bits) >= 2 and _is_code(bits[1]):
            old = bits[1]
        elif st == "R" and len(bits) >= 3 and _is_code(bits[1]) and not _is_code(bits[2]):
            old = bits[1]                          # code renamed to a non-code extension
        else:
            continue
        try:
            blob = _run_git(["show", "HEAD:" + old], binary=True)
        except SystemExit:
            blob = b""
        keys["D:" + old] = hashlib.sha256(blob).hexdigest()
    return keys


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
    if not files and not removals:
        return 0                                          # docs/manifests pass free
    ov = os.path.join(_adv_dir(root), "OVERRIDE")
    if os.path.isfile(ov):
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
    fake = os.environ.get("ADVERSARY_FAKE")               # selftests only - no network
    if fake:
        root = os.path.basename(_repo_root())
        if root.startswith("advgate_") and os.environ.get("ADVERSARY_SELFTEST") == "1":
            return ("(faked verdict for selftest)\nVERDICT: %s" % fake), {}
        sys.stderr.write("ADVERSARY_FAKE ignored outside a selftest repo (adversary "
                         "finding, birth review r2) - running the REAL reviewer.\n")
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
                d = json.loads(r.read().decode("utf-8"))
            break
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < 3:
                sys.stderr.write("adversary model 429 - retry %d/3 in 30s\n" % (attempt + 1))
                time.sleep(30)
                continue
            raise SystemExit("ADVERSARY GATE: OpenRouter HTTP %s: %s"
                             % (e.code, e.read().decode("utf-8", "replace")[:300]))
    if d.get("error"):
        raise SystemExit("ADVERSARY GATE: model error: %s" % json.dumps(d["error"])[:300])
    text = "".join(ch.get("message", {}).get("content") or "" for ch in d.get("choices", []))
    return text, d.get("usage", {})


def cmd_run(model, context):
    root = _repo_root()
    files = _staged_code_files()
    removals = _staged_removals()
    if not files and not removals:
        print("adversary gate: no staged code files - nothing to review.")
        return 0
    diff = _run_git(["diff", "--cached", "--unified=8"])
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
    text, usage = _call_model(model, "".join(parts))
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
    out = _run_git(["diff", "--name-status", "-M", base, rev])
    files, removals = {}, {}
    for line in out.splitlines():
        bits = line.split("\t")
        if not bits or not bits[0]:
            continue
        st = bits[0][0]
        if st in "ACM" and len(bits) >= 2 and _is_code(bits[1]):
            files[bits[1]] = _blob_sha(rev, bits[1])
        elif st == "R" and len(bits) >= 3:
            if _is_code(bits[2]):
                files[bits[2]] = _blob_sha(rev, bits[2])
            if _is_code(bits[1]) and not _is_code(bits[2]):
                removals["D:" + bits[1]] = _blob_sha(base, bits[1])
        elif st == "D" and len(bits) >= 2 and _is_code(bits[1]):
            removals["D:" + bits[1]] = _blob_sha(base, bits[1])
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
        if ov.get("staged") == changed:
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
