"""adversary_audit.py - the post-hoc AUDIT TRIPWIRE for the G39 adversarial commit gate.

The pre-commit gate is advisory by construction (git cannot make client-side hooks
mandatory): --no-verify, plumbing (commit-tree/update-ref), GUI clients, and unarmed
clones all walk around it. This auditor is the layer no local trick escapes, because it
reads immutable OUTPUT, not process: for every commit after the baseline that changes
CODE, it recomputes the changed blobs' sha256s and demands a matching durable note on
refs/notes/adversary (written by `adversary_gate.py record` from the post-commit hook).
A commit with no note, a note missing a changed path, or a note whose sha does not match
the recomputed blob is a VIOLATION. OVERRIDE notes (the owner's one-shot escape) pass but
are listed loudly; --strict-override turns them into violations too.

SELF-CONTAINED BY DESIGN: stdlib only, no imports from adversary_gate.py - this file is
VENDORED into each repo's .githooks/ by install_gate.py so CI can run it without the
Tools repo. The code-path rules (CODE_EXTS/GATED_PREFIXES) are therefore duplicated from
adversary_gate.py; audit_selftest.py asserts the two stay identical (drift tripwire).

Usage:
  python adversary_audit.py [--repo P] [--baseline REV] [--ref refs/notes/adversary]
                            [--json] [--strict-override]
Baseline default: the commit sha in <repo>/.githooks/adversary_baseline (written by the
installer at arming time - commits before it predate durable notarization and would be
pure false alarms). Exit 0 clean / 1 violations (or overrides under --strict-override) /
2 usage or environment error.

Honest limits (documented, not hidden): a determined fraudster can forge a note with
correct shas and fabricated verdict text; the auditor proves PROCESS EVIDENCE EXISTS and
matches the bytes, and the recorded artifact text lets a human (or a re-run review)
check the evidence itself. Detection, not prevention - by design.
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys

CODE_EXTS = {".py", ".js", ".json", ".ts", ".jsx", ".tsx", ".html", ".css", ".ps1", ".sh", ".bat",
             ".c", ".cpp", ".h", ".rs", ".go", ".java", ".glsl", ".osl"}
GATED_PREFIXES = (".githooks/", ".github/workflows/")
NOTES_REF = "refs/notes/adversary"
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

GIT = shutil.which("git") or r"C:\Program Files\Git\cmd\git.exe"


def _git(repo, args, binary=False, check=True):
    p = subprocess.run([GIT, "-C", repo] + args, capture_output=True)
    if check and p.returncode != 0:
        raise SystemExit("git %s failed: %s" % (" ".join(args[:2]),
                                                p.stderr.decode("utf-8", "replace")[:300]))
    if binary:
        return p.returncode, p.stdout
    return p.returncode, p.stdout.decode("utf-8", "replace")


def _is_code(path):
    return path.startswith(GATED_PREFIXES) or os.path.splitext(path)[1].lower() in CODE_EXTS


def _changed_code(repo, rev):
    """Changed CODE in `rev` vs its FIRST parent (root: vs the empty tree). Mirrors
    adversary_gate._changed_code_in_commit exactly: (files {new_path: sha256 of blob in
    rev}, removals {'D:'+old: sha256 of parent blob})."""
    rc, _ = _git(repo, ["rev-parse", "--verify", "--quiet", rev + "^1"], check=False)
    base = rev + "^1" if rc == 0 else EMPTY_TREE

    def blob_sha(r, path):
        _, raw = _git(repo, ["show", r + ":" + path], binary=True)
        return hashlib.sha256(raw).hexdigest()

    _, out = _git(repo, ["diff", "--name-status", "-M", base, rev])
    files, removals = {}, {}
    for line in out.splitlines():
        bits = line.split("\t")
        if not bits or not bits[0]:
            continue
        st = bits[0][0]
        if st in "ACM" and len(bits) >= 2 and _is_code(bits[1]):
            files[bits[1]] = blob_sha(rev, bits[1])
        elif st == "R" and len(bits) >= 3:
            if _is_code(bits[2]):
                files[bits[2]] = blob_sha(rev, bits[2])
            if _is_code(bits[1]) and not _is_code(bits[2]):
                removals["D:" + bits[1]] = blob_sha(base, bits[1])
        elif st == "D" and len(bits) >= 2 and _is_code(bits[1]):
            removals["D:" + bits[1]] = blob_sha(base, bits[1])
    files.update(removals)
    return files


def _audit_commit(repo, rev, ref):
    """Returns (kind, detail): 'clean' | 'skip' (no code) | 'override' | 'violation'."""
    changed = _changed_code(repo, rev)
    if not changed:
        return "skip", ""
    rc, raw = _git(repo, ["notes", "--ref", ref, "show", rev], check=False)
    if rc != 0:
        return "violation", "UNNOTARIZED - no adversary note (gate bypassed?); %d code path(s): %s" % (
            len(changed), ", ".join(sorted(changed)[:5]))
    try:
        note = json.loads(raw)
    except ValueError:
        return "violation", "note is not valid JSON (tampered?)"
    rows = note.get("files") or {}
    problems = []
    for key, sha in sorted(changed.items()):
        row = rows.get(key)
        if not row:
            problems.append("%s: changed but absent from the note" % key)
        elif row.get("sha") != sha:
            problems.append("%s: note sha does not match the committed blob (forged/stale note)" % key)
    if problems:
        return "violation", "; ".join(problems)
    if note.get("type") == "OVERRIDE":
        return "override", "owner override, reason: %s" % (note.get("reason", "")[:200] or "(none)")
    if note.get("type") != "CLEAR":
        return "violation", "note type %r is neither CLEAR nor OVERRIDE" % note.get("type")
    return "clean", ""


def main(argv=None):
    ap = argparse.ArgumentParser(description="Audit commit history against adversary-gate notes.")
    ap.add_argument("--repo", default=".")
    ap.add_argument("--baseline", default=None,
                    help="audit commits AFTER this rev (default: .githooks/adversary_baseline)")
    ap.add_argument("--ref", default=NOTES_REF)
    ap.add_argument("--json", action="store_true", dest="as_json")
    ap.add_argument("--strict-override", action="store_true",
                    help="owner OVERRIDE commits count as violations too")
    a = ap.parse_args(argv)

    rc, root = _git(os.path.abspath(a.repo), ["rev-parse", "--show-toplevel"], check=False)
    if rc != 0:
        print("adversary_audit: %s is not a git working copy" % a.repo)
        return 2
    root = root.strip()
    baseline = a.baseline
    if not baseline:
        bp = os.path.join(root, ".githooks", "adversary_baseline")
        if not os.path.isfile(bp):
            print("adversary_audit: no --baseline and no .githooks/adversary_baseline - "
                  "run install_gate.py first (the baseline marks where notarization began).")
            return 2
        baseline = open(bp, encoding="utf-8").read().strip().split()[0]
    rc, _ = _git(root, ["rev-parse", "--verify", "--quiet", baseline + "^{commit}"], check=False)
    if rc != 0:
        print("adversary_audit: baseline %r is not a commit in this repo" % baseline)
        return 2

    _, out = _git(root, ["rev-list", "--reverse", baseline + "..HEAD"])
    revs = [r for r in out.split() if r]
    violations, overrides, audited = [], [], 0
    for rev in revs:
        kind, detail = _audit_commit(root, rev, a.ref)
        if kind == "skip":
            continue
        audited += 1
        _, subj = _git(root, ["log", "-1", "--format=%s", rev])
        row = {"commit": rev[:12], "subject": subj.strip()[:80], "detail": detail}
        if kind == "violation":
            violations.append(row)
        elif kind == "override":
            overrides.append(row)

    if a.as_json:
        print(json.dumps({"baseline": baseline, "commits_walked": len(revs),
                          "code_commits_audited": audited, "violations": violations,
                          "overrides": overrides}, indent=1))
    else:
        print("adversary_audit: %d commit(s) after baseline %s; %d touched code"
              % (len(revs), baseline[:12], audited))
        for v in violations:
            print("  VIOLATION %s  %s\n            %s" % (v["commit"], v["subject"], v["detail"]))
        for o in overrides:
            print("  OVERRIDE  %s  %s\n            %s" % (o["commit"], o["subject"], o["detail"]))
        if not violations and not overrides:
            print("  clean - every code commit carries a matching adversary note")
    if violations or (a.strict_override and overrides):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
