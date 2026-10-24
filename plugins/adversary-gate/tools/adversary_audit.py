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
import datetime
import json
import os
import re
import shutil
import subprocess
import sys

CODE_EXTS = {".py", ".js", ".json", ".ts", ".jsx", ".tsx", ".html", ".css", ".ps1", ".sh", ".bat",
             ".c", ".cpp", ".h", ".rs", ".go", ".java", ".glsl", ".osl",
             # EV-029 (2026-09-04): ES-module / CommonJS / TS-module forms (parity with the gate)
             ".mjs", ".cjs", ".mts", ".cts",
             # OWNER RULING 2026-10-02 (parity with the gate): agent-modified .txt is reviewed
             ".txt"}
GATED_PREFIXES = (".githooks/", ".github/workflows/")
# 2026-09-06: extensionless git hook files are code wherever they live (parity with the gate);
# confined to commits after the per-repo rules epoch (see _hook_names_apply)
HOOK_NAMES = ("pre-commit", "post-commit", "pre-push")
RULES_EPOCH_FILE = os.path.join(".githooks", "adversary_rules_epoch")
TEXT_RULES_EPOCH_FILE = os.path.join(".githooks", "adversary_text_rules_epoch")
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


def _is_code(path, hook_names=True, text_files=True):
    ext = os.path.splitext(path)[1].lower()
    return (path.startswith(GATED_PREFIXES) or (ext in CODE_EXTS and (ext != ".txt" or text_files))
            or (hook_names and os.path.basename(path) in HOOK_NAMES))


_EPOCH_CACHE = {}


def _epoch(repo, rule="hook-names", epoch_file=RULES_EPOCH_FILE):
    """(sha, state) for the `hook-names <sha>` epoch line: state 'none' | 'ok' | 'moved' |
    'unreadable'. ANCHORED IN HISTORY (deepagents re-vendor gate round 1, gate_20260906-210758):
    the recorded sha must be an ancestor of EVERY commit that ever added the epoch file (order-
    independent: forged dates cannot invert it; --full-history: merges cannot hide a re-add) -
    otherwise a later commit could rewrite it to a descendant and grandfather earlier hook-file
    commits out of the rule, surviving CI. An epoch that was never committed has no introducing
    commit yet and is trusted like the baseline (same local trust class). Shallow or unreadable
    history is 'unreadable' (fail closed). Memoized per repo: the walker asks once per commit."""
    key = os.path.normcase(os.path.abspath(repo))
    if rule != "hook-names" or epoch_file != RULES_EPOCH_FILE:
        key = (key, rule, epoch_file)
    if key in _EPOCH_CACHE:
        return _EPOCH_CACHE[key]
    res = _epoch_uncached(repo, rule, epoch_file)
    _EPOCH_CACHE[key] = res
    return res


def _epoch_uncached(repo, rule="hook-names", epoch_file=RULES_EPOCH_FILE):
    # The epoch is read from HEAD's TREE only - never from the working tree (Tools E gate round 1,
    # gate_20260906-223831): a working-tree read is case-folded on Windows/macOS and follows
    # symlinks, while the history anchor is exact, so a tracked case-variant or a symlinked
    # .githooks could satisfy the read without being the anchored blob. An uncommitted epoch
    # (the moment between the installer's write and the vendor commit) is 'uncommitted': the
    # rule applies to every commit until it is committed (fail closed, not a violation).
    rel = epoch_file.replace("\\", "/")
    rc, blob = _git(repo, ["show", "HEAD:" + rel], check=False)
    if rc != 0:
        return None, "uncommitted"
    if rule == "text-files":
        rc, entry = _git(repo, ["ls-tree", "HEAD", "--", ":(top)" + rel], check=False)
        if rc != 0 or not entry.startswith(("100644 blob ", "100755 blob ")):
            return None, "unreadable"
        lines = [ln.split() for ln in blob.splitlines() if ln.strip()]
        if len(lines) != 1 or len(lines[0]) != 2 or lines[0][0] != rule:
            return None, "unreadable"
        if not re.fullmatch(r"ROOT|[0-9a-f]{40}|[0-9a-f]{64}", lines[0][1]):
            return None, "unreadable"
    sha = None
    for ln in blob.splitlines():
        parts = ln.split()
        if len(parts) == 2 and parts[0] == rule:
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
                          ":(top)" + rel], check=False)
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


def _text_files_apply(repo, rev):
    """Only an immutable, historically anchored marker can exempt legacy text blobs.

    Missing/uncommitted, malformed, moved and shallow markers apply the rule everywhere.
    Staged-file classification never consults this historical exception.
    """
    sha, state = _epoch(repo, "text-files", TEXT_RULES_EPOCH_FILE)
    if state != "ok" or sha == "ROOT":
        return True
    rc, _ = _git(repo, ["merge-base", "--is-ancestor", rev, sha], check=False)
    return rc != 0


def _changed_code(repo, rev):
    """Changed CODE in `rev` vs its FIRST parent (root: vs the empty tree). Mirrors
    adversary_gate._changed_code_in_commit exactly: (files {new_path: sha256 of blob in
    rev}, removals {'D:'+old: sha256 of parent blob})."""
    rc, _ = _git(repo, ["rev-parse", "--verify", "--quiet", rev + "^1"], check=False)
    base = rev + "^1" if rc == 0 else EMPTY_TREE
    hn = _hook_names_apply(repo, rev)
    text_files = _text_files_apply(repo, rev)

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
        if code in ("A", "M", "T"):
            path = toks[i + 1]
            i += 2
            if _is_code(path, hn, text_files):
                files[path] = blob_sha(rev, path)
        elif code in ("R", "C"):
            # gate round gate_20261009-151907: C (copy) records carry TWO paths
            # exactly like R (C<score>\0SRC\0DST) - walking C in the single-path
            # branch consumed only SRC and desynchronized the record stream. A
            # copy never removes its source, so only R contributes a removal.
            old, new = toks[i + 1], toks[i + 2]
            i += 3
            if _is_code(new, hn, text_files):
                files[new] = blob_sha(rev, new)
            if code == "R" and _is_code(old, hn, text_files) and not _is_code(new, hn, text_files):
                removals["D:" + old] = blob_sha(base, old)
        elif code == "D":
            old = toks[i + 1]
            i += 2
            if _is_code(old, hn, text_files):
                removals["D:" + old] = blob_sha(base, old)
        else:
            i += 2
    files.update(removals)
    return files


def _verify_chain_mac(repo, rev, ref, note):
    """T3.3 / hole H1: verify the note's HMAC chain binding. Returns None when
    valid/legacy/unkeyed, or a problem string that escalates the finding.
    Legacy: notes without a mac whose notarization predates the key's creation
    stamp are 'legacy-unsigned' - expected history, NOT a violation. A note
    CARRYING a mac that does not verify, or one whose embedded artifact hashes
    no longer match, is a violation (the tripwire fires)."""
    import hashlib
    import hmac as _h
    # gate round 2026-10-23 (re-vendor reviews, colibri LOW + repo-memory
    # findings): the note is hostile input - type-guard every field the
    # walk touches, and verify the EMBEDDED artifact hashes for EVERY note
    # BEFORE any key-dependent branch: the embedded==disk check needs no
    # key, and both the legacy branch and the no-key degrade returned None
    # before it, so mac-less notes and fresh CI clones never verified the
    # one integrity datum they can (the comments claimed they did).
    if not isinstance(note, dict):
        return "note is not a JSON object (malformed)"
    key_p = os.path.join(repo, ".adversary", "note_hmac.key")
    key = None
    # gate round 2026-10-23 (colibri re-vendor review MEDIUM): the legacy
    # decision MUST come from the LOCAL key file's stamp. Seeding from the
    # note's own mac_key_created let an unauthenticated note claim a future
    # key-creation date and exempt itself - the forged? branch could never
    # fire. The note's field is ignored for this decision entirely.
    key_created = ""
    try:
      if os.path.isfile(key_p):
        for ln in open(key_p, encoding="utf-8", errors="replace").read().splitlines():
            t = ln.strip()
            if len(t) == 64:
                try:
                    key = bytes.fromhex(t)
                except ValueError:
                    key = None   # corrupt hex: degrade to unverifiable-mac
            elif ln.startswith("# created="):
                key_created = ln.split("=", 1)[1].strip()
    except OSError:
        key = None            # unreadable key: degrade, never crash
    import hashlib as _hl
    arts = note.get("artifacts_sha256")
    if arts is not None:
        if not isinstance(arts, dict):
            return "artifacts_sha256 is malformed (forged evidence)"
        for rel, shas in arts.items():
            if not isinstance(shas, dict):
                return "artifact entry %s is malformed (forged evidence)" % rel
            if shas.get("embedded") != shas.get("disk"):
                return "embedded artifact %s hash mismatch (forged evidence)" % rel
            # LIVE disk check: post-notarization tampering of the evidence file
            # (record cannot catch a pre-record tamper - it reads both sides from
            # the same bytes; the note is the anchor, the auditor is the witness)
            live_p = os.path.join(repo, str(rel).replace("/", os.sep))
            if not os.path.isfile(live_p):
                # .adversary is gitignored transient state - fresh clones/CI never
                # have the evidence files; the EMBEDDED hashes still verify the note
                # body self-consistency. Absence is unverifiable, not tampering
                # (gate round gate_20261009-063510 HIGH).
                continue
            try:
                live_s = open(live_p, encoding="utf-8", errors="replace").read()[:100_000]
            except OSError:
                live_s = ""
            live_sha = _hl.sha256(live_s.encode("utf-8", "replace")).hexdigest()
            if live_sha != shas.get("disk"):
                return "artifact %s changed on disk after notarization (tampered evidence)" % rel
    mac = note.get("mac")
    if not mac:
        # legacy exemption with FORMAT-NORMALIZED dates: note stamps are
        # %Y%m%d-%H%M%S and the key stamp is ISO - compare like with like
        # (gate round gate_20261009-053337 HIGH: the raw string compare was
        # always False, flagging every legacy note as forged)
        when = str(note.get("when", ""))
        try:
            when_iso = datetime.datetime.strptime(when[:15], "%Y%m%d-%H%M%S").date().isoformat()
        except ValueError:
            when_iso = ""
        # same-DAY pre-key notes are legacy too: the key stamp carries only day
        # granularity, so a note stamped earlier the SAME day is indistinguishable
        # from post-key - exempt on <= (gate round gate_20261009-065049 MEDIUM)
        if key is None or (key_created and when_iso and when_iso <= key_created[:10]):
            return None            # legacy note (pre-key) or unkeyed repo
        return "note has no chain mac but the key predates it (forged?)"
    # key-stamp identity: a note signed by a DIFFERENT key (multi-clone history,
    # re-keyed machine) is UNVERIFIABLE here, not forged - degrade loud, never
    # a violation (gate round gate_20261009-060518 HIGH)
    local_stamp = ""
    try:
        if os.path.isfile(key_p):
            for ln in open(key_p, encoding="utf-8", errors="replace").read().splitlines():
                if ln.startswith("# created="):
                    local_stamp = ln.split("=", 1)[1].strip()
    except OSError:
        key = None         # unreadable key: degrade to unverifiable (gate
                          # round gate_20261009-062031 LOW), never crash the tripwire
    note_stamp = note.get("mac_key_created") or ""
    # unverifiable (degrade, never a violation): no local key (clone/CI -
    # gate_20261009-053337 HIGH), or either stamp missing. When BOTH stamps are
    # present and DIFFER, the note is either foreign-key signed (multi-clone
    # history) or forged - this machine cannot distinguish, so it degrades too
    # (gate_20261009-063510 MEDIUM: a forged note may omit the stamp entirely;
    # stampless = unverifiable here, and the future --strict-mac ruling can
    # tighten all three).
    if key is None or not note_stamp or not local_stamp or note_stamp != local_stamp:
        # also covers the no-key clone (.adversary never cloned - CI is the
        # auditor primary deployment, gate_20261009-053337 HIGH)
        return None
        # a future owner ruling may add --strict-mac to make this fatal
    prior = "GENESIS"
    rc, log = _git(repo, ["log", "--format=%H", rev], check=False)
    for c in (log.split()[1:] if rc == 0 else []):
        rc2, raw = _git(repo, ["notes", "--ref", ref, "show", c], check=False)
        if rc2 != 0:
            continue
        try:
            pn = json.loads(raw)
        except ValueError:
            continue
        if isinstance(pn, dict) and isinstance(pn.get("mac"), str) and pn["mac"]:
            prior = pn["mac"]
            break
    body = dict(note)
    body.pop("mac", None)
    payload = json.dumps(body, sort_keys=True, separators=(",", ":"))
    want = _h.new(key, (payload + "|" + prior).encode("utf-8"), "sha256").hexdigest()
    if want != mac:
        return "chain mac mismatch (note body or prior note tampered)"
    return None

def root_abs(repo):
    return repo if os.path.isabs(repo) else os.path.abspath(repo)

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
    mac_problem = _verify_chain_mac(root_abs(repo), rev, ref, note)
    if mac_problem:
        return "violation", "NOTE INTEGRITY: " + mac_problem
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
    text_sha, text_state = _epoch(root, "text-files", TEXT_RULES_EPOCH_FILE)
    if text_state in ("moved", "unreadable"):
        violations.append({"commit": "text-rules-epoch", "subject": TEXT_RULES_EPOCH_FILE,
                           "detail": "text rules epoch %s (%s); every text commit is audited" %
                                     (text_state.upper(), text_sha or "invalid marker")})
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
