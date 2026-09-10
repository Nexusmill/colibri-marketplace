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
             ".c", ".cpp", ".h", ".rs", ".go", ".java", ".glsl", ".osl",
             # EV-029 (2026-09-04): ES-module / CommonJS / TS-module forms (parity with the gate)
             ".mjs", ".cjs", ".mts", ".cts"}
GATED_PREFIXES = (".githooks/", ".github/workflows/")
# 2026-09-06: extensionless git hook files are code wherever they live (parity with the gate);
# confined to commits after the per-repo rules epoch (see _hook_names_apply)
HOOK_NAMES = ("pre-commit", "post-commit", "pre-push")
RULES_EPOCH_FILE = os.path.join(".githooks", "adversary_rules_epoch")
NOTES_REF = "refs/notes/adversary"
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

GIT = shutil.which("git") or r"C:\Program Files\Git\cmd\git.exe"


def _git(repo, args, binary=False, check=True):
    # GIT_NO_REPLACE_OBJECTS: a local `git replace <dirty> <innocent>` otherwise makes
    # diff/show read the substituted object graph, so the auditor would hash the innocent
    # blob and pass a dirty commit (audit-probe finding). Ignore replace refs.
    env = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1")
    p = subprocess.run([GIT, "-C", repo] + args, capture_output=True, env=env)
    if check and p.returncode != 0:
        raise SystemExit("git %s failed: %s" % (" ".join(args[:2]),
                                                p.stderr.decode("utf-8", "replace")[:300]))
    if binary:
        return p.returncode, p.stdout
    return p.returncode, p.stdout.decode("utf-8", "replace")


def _is_code(path, hook_names=True):
    return (path.startswith(GATED_PREFIXES) or os.path.splitext(path)[1].lower() in CODE_EXTS
            or (hook_names and os.path.basename(path) in HOOK_NAMES))


_EPOCH_CACHE = {}


def _epoch(repo):
    """(sha, state) for the `hook-names <sha>` epoch line: state 'none' | 'ok' | 'moved' |
    'unreadable'. ANCHORED IN HISTORY (deepagents re-vendor gate round 1, gate_20260906-210758):
    the recorded sha must be an ancestor of EVERY commit that ever added the epoch file (order-
    independent: forged dates cannot invert it; --full-history: merges cannot hide a re-add) -
    otherwise a later commit could rewrite it to a descendant and grandfather earlier hook-file
    commits out of the rule, surviving CI. An epoch that was never committed has no introducing
    commit yet and is trusted like the baseline (same local trust class). Shallow or unreadable
    history is 'unreadable' (fail closed). Memoized per repo: the walker asks once per commit."""
    key = os.path.normcase(os.path.abspath(repo))
    if key in _EPOCH_CACHE:
        return _EPOCH_CACHE[key]
    res = _epoch_uncached(repo)
    _EPOCH_CACHE[key] = res
    return res


def _epoch_uncached(repo):
    # The epoch is read from HEAD's TREE only - never from the working tree (Tools E gate round 1,
    # gate_20260906-223831): a working-tree read is case-folded on Windows/macOS and follows
    # symlinks, while the history anchor is exact, so a tracked case-variant or a symlinked
    # .githooks could satisfy the read without being the anchored blob. An uncommitted epoch
    # (the moment between the installer's write and the vendor commit) is 'uncommitted': the
    # rule applies to every commit until it is committed (fail closed, not a violation).
    rel = RULES_EPOCH_FILE.replace("\\", "/")
    rc, blob = _git(repo, ["show", "HEAD:" + rel], check=False)
    if rc != 0:
        return None, "uncommitted"
    sha = None
    for ln in blob.splitlines():
        parts = ln.split()
        if len(parts) == 2 and parts[0] == "hook-names":
            sha = parts[1]
    if not sha:
        return None, "none"
    # ORDER-INDEPENDENT (Tools D gate round 2, gate_20260906-214441): git log's date order is
    # attacker-controlled (forged committer dates), so no single 'earliest add' is trusted -
    # the recorded sha must be an ancestor of EVERY commit that ever added the file, listed with
    # --full-history so no merge simplification hides a re-add. A failed history read is
    # 'unreadable' (fail closed), never mistaken for 'not committed yet'.
    # a SHALLOW clone has truncated history: its boundary commit lists every file as an add and
    # the recorded sha's ancestry cannot be judged - 'unreadable', fail closed (Tools D gate
    # round 3, gate_20260906-220055)
    rc_s, shallow = _git(repo, ["rev-parse", "--is-shallow-repository"], check=False)
    if rc_s != 0 or shallow.strip() == "true":
        return sha, "unreadable"
    if sha == "ROOT":
        return sha, "ok"              # ROOT skips ancestry checks, never the shallow-history check
    rc, out = _git(repo, ["log", "--full-history", "--diff-filter=A", "--format=%H", "--",
                          ":(top)" + RULES_EPOCH_FILE.replace("\\", "/")], check=False)
    if rc != 0:
        return sha, "unreadable"
    adds = out.split()
    if not adds:
        return sha, "unreadable"      # in HEAD's tree (read above) yet no add commit = truncation
    for add in adds:
        rc2, _ = _git(repo, ["merge-base", "--is-ancestor", sha, add], check=False)
        if rc2 != 0:
            return sha, "moved"
    return sha, "ok"


def _hook_names_apply(repo, rev):
    """The HOOK_NAMES rule (2026-09-06) is confined to commits strictly AFTER the sha the
    installer recorded in .githooks/adversary_rules_epoch (`hook-names <sha>`) when it vendored
    a HOOK_NAMES-aware auditor: earlier commits were made when hook files were docs-class and
    carry no note by design (gate round 2 MEDIUM, gate_20260906-165900). No epoch line, or a
    MOVED epoch (see _epoch), = the rule applies everywhere (fail closed)."""
    sha, state = _epoch(repo)
    if state != "ok" or sha == "ROOT":
        return True                   # ROOT epoch (armed at birth): the rule applies everywhere
    rc, _ = _git(repo, ["merge-base", "--is-ancestor", rev, sha], check=False)
    return rc != 0              # ancestor-or-equal of the epoch -> old rules


def _changed_code(repo, rev):
    """Changed CODE in `rev` vs its FIRST parent (root: vs the empty tree). Mirrors
    adversary_gate._changed_code_in_commit exactly: (files {new_path: sha256 of blob in
    rev}, removals {'D:'+old: sha256 of parent blob})."""
    rc, _ = _git(repo, ["rev-parse", "--verify", "--quiet", rev + "^1"], check=False)
    base = rev + "^1" if rc == 0 else EMPTY_TREE
    hn = _hook_names_apply(repo, rev)

    def blob_sha(r, path):
        _, raw = _git(repo, ["show", r + ":" + path], binary=True)
        return hashlib.sha256(raw).hexdigest()

    # -z NUL parsing (non-ASCII paths are C-quoted otherwise -> silently skipped) + T
    # typechange handling; mirrors adversary_gate._changed_code_in_commit exactly.
    _, out = _git(repo, ["diff", "--name-status", "-M", "-z", base, rev])
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
                files[path] = blob_sha(rev, path)
        elif code == "R":
            old, new = toks[i + 1], toks[i + 2]
            i += 3
            if _is_code(new, hn):
                files[new] = blob_sha(rev, new)
            if _is_code(old, hn) and not _is_code(new, hn):
                removals["D:" + old] = blob_sha(base, old)
        elif code == "D":
            old = toks[i + 1]
            i += 2
            if _is_code(old, hn):
                removals["D:" + old] = blob_sha(base, old)
        else:
            i += 2
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
    if baseline == "ROOT":
        # armed at birth (owner ruling 2026-09-08): walk EVERY commit, the root included; an
        # UNBORN HEAD (armed, nothing committed yet) has nothing to audit - exit 0, never a raw
        # git error with the violations code (gate round 1, gate_20260908-223749)
        rc, out = _git(root, ["rev-list", "--reverse", "HEAD"], check=False)
        if rc != 0:
            # A missing branch ref does not prove that nothing was committed: deleting
            # the ref leaves unreachable history. Only an empty-of-commits object store
            # may be called unborn here; unreadable history or object enumeration fails closed.
            rc_b, branch = _git(root, ["symbolic-ref", "-q", "HEAD"], check=False)
            rc_r, _ = _git(root, ["show-ref", "--verify", "--quiet", branch.strip()],
                           check=False) if rc_b == 0 and branch.strip() else (128, "")
            rc_o, objects = _git(root, ["cat-file", "--batch-all-objects",
                                        "--batch-check=%(objecttype)"], check=False) \
                            if rc_b == 0 and rc_r == 1 else (128, "")
            if rc_b == 0 and rc_r == 1 and rc_o == 0 and all(
                    kind in {"blob", "tree", "tag"} for kind in objects.splitlines()):
                if a.as_json:                     # --json consumers always get a document
                    print(json.dumps({"baseline": "ROOT", "commits_walked": 0,
                                      "code_commits_audited": 0, "violations": [],
                                      "overrides": []}, indent=1))
                else:
                    print("adversary_audit: baseline ROOT and no commits yet - nothing to audit")
                return 0
            print("adversary_audit: baseline ROOT but the history read FAILED (missing objects or "
                  "a broken HEAD) - fail closed")
            return 2
    else:
        rc, _ = _git(root, ["rev-parse", "--verify", "--quiet", baseline + "^{commit}"], check=False)
        if rc != 0:
            print("adversary_audit: baseline %r is not a commit in this repo" % baseline)
            return 2
        _, out = _git(root, ["rev-list", "--reverse", baseline + "..HEAD"])
    revs = [r for r in out.split() if r]
    violations, overrides, audited = [], [], 0
    ep_sha, ep_state = _epoch(root)
    if ep_state in ("moved", "unreadable"):
        # the epoch file was rewritten to a sha that is not an ancestor of every commit that
        # introduced it (a committed-state grandfathering attempt, or a squash/cherry-pick
        # vendoring flow), or its history could not be read; every commit is audited under the
        # current rules (the walkers already fail closed) AND the state itself is a violation
        violations.append({"commit": "rules-epoch", "subject": ".githooks/adversary_rules_epoch",
                           "detail": ("rules epoch MOVED: recorded sha %s is not an ancestor of every "
                                      "commit that added the epoch file; every commit is audited under "
                                      "the current rules" % (ep_sha or "?")[:12]) if ep_state == "moved"
                           else "rules epoch history UNREADABLE (shallow clone, or the history read "
                                "failed); every commit is audited under the current rules"})
    if ep_state == "uncommitted" and not a.as_json:
        print("adversary_audit: rules epoch not committed (no .githooks/adversary_rules_epoch in "
              "HEAD's tree) - the hook-name rule applies to every commit until it is")
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
