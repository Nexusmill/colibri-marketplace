# -*- coding: utf-8 -*-
"""Deterministic finding adjudication for the adversary gate (owner order
2026-10-10, transferred from local-gate experiment #10: extractor + code
adjudicator - the program measured adj-FP 0/15 clean rounds while confirming
every model-anchored mutation; the transfer keeps the mechanism, not the
local model).

Two independent instruments, both pure functions of bytes already inside the
gate - no model calls, no network, no index dependency, milliseconds:

  semantic_deltas(diff)  - every staged line pair (old -> new) that differs
                           ONLY by a comparison-operator change or an
                           inserted/removed leading 'not '. These are the
                           exact shapes experiment #10's seeded mutations
                           took, and they are deterministic to detect from
                           the unified diff alone.
  payload_section(...)   - the SEMANTIC DELTAS block appended to the review
                           payload (after the diff, before the rebuttal, so
                           the cache-friendly stable-first layout survives).
  adjudicate_review(...) - post-review anchor normalization for BLOCK
                           findings: per finding paragraph, resolve cited
                           files (exact -> basename -> difflib; grammar- and
                           prose-constrained reviewers hallucinate near-miss
                           filenames - measured ~30-50% of findings on the
                           local corpus), verify quoted code fragments
                           verbatim against the staged bytes, and flag
                           proximity to a semantic delta.

VERDICT SEMANTICS (upgraded by owner order 2026-10-12 - the corpus basis the
original delegation demanded now exists: EV-201/202/203 plus this week's
rounds): the adjudicator still does not rewrite verdicts itself, but the GATE
caller now treats an ALL-REFUTED finding set (every finding NO_ANCHOR or
UNRESOLVED_FILE - the fabrication signatures; a pure-removal review is exempt,
it has no bytes to anchor against) as verdict-void: no clearance is written
and no remediation is owed, but NEVER an auto-CLEAR - a deterministic layer
never authorizes a commit; the review re-runs. Any finding with a surviving
anchor (CONFIRMED/PARTIAL_ANCHOR, FILE_ONLY) keeps the verdict standing - the
strike is deliberately conservative. Measured basis for the underlying checks:
0 false positives over 15 clean replay rounds.
"""
import difflib
import re

__all__ = ["semantic_deltas", "payload_section", "adjudicate_review",
           "resolve_file_ref", "MAX_DELTAS"]

MAX_DELTAS = 40
_OPS = {">=": ">", ">": ">=", "<=": "<", "<": "<=", "==": "!=", "!=": "=="}
_DIFFGIT = re.compile(r"^diff --git a/(.+?) b/(.+)$")
_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def _norm(s):
    return re.sub(r"\s+", " ", s or "").strip()
# A QUOTED fragment counts as a code anchor when it carries code punctuation
# and enough length that being wrong about it is detectable.
_FRAGMENT_MIN = 12


def _split_by_file(diff):
    out, cur = {}, None
    for ln in diff.split("\n"):
        if ln.endswith("\r"):
            ln = ln[:-1]
        m = _DIFFGIT.match(ln)
        if m:
            cur = m.group(2)
            out[cur] = []
        elif cur is not None:
            out[cur].append(ln)
    return {f: "\n".join(ls) for f, ls in out.items()}


def _classify_pair(old, new):
    """'operator change X->Y' / 'guard inversion' / None for unrelated lines."""
    a, b = old.strip(), new.strip()
    if not a or not b or a == b:
        return None
    for op, other in _OPS.items():
        if op in a and other in b:
            if a.replace(op, "\x00") == b.replace(other, "\x00"):
                return "operator change %s->%s" % (op, other)
    if a.replace("not ", "", 1) == b or b.replace("not ", "", 1) == a:
        return "guard inversion (not inserted/removed)"
    if a.replace("not ", "") == b.replace("not ", ""):
        return "guard inversion (not moved)"
    return None


def semantic_deltas(diff):
    """[(file, new_line_no, old_text, new_text, kind)] for every -/+ pair in
    the unified diff whose members differ only by an operator change or a
    guard inversion. Deterministic, replay- and production-identical."""
    out = []
    for fname, fdiff in sorted(_split_by_file(diff).items()):
        new_no = None
        minus_run, plus_run, plus_start = [], [], None

        def flush():
            if minus_run and plus_run and plus_start is not None:
                for i, old in enumerate(minus_run):
                    if i >= len(plus_run):
                        break
                    kind = _classify_pair(old, plus_run[i])
                    if kind:
                        out.append((fname, plus_start + i, old[:120], plus_run[i][:120], kind))

        for ln in fdiff.split("\n"):
            m = _HUNK.match(ln)
            if m:
                flush()
                minus_run, plus_run, plus_start = [], [], None
                new_no = int(m.group(3))
                continue
            if new_no is None:
                continue
            if ln.startswith("+"):
                if not plus_run:
                    plus_start = new_no
                plus_run.append(ln[1:])
                new_no += 1
            elif ln.startswith("-"):
                if plus_run:              # a minus after a plus starts a new group
                    flush()
                    minus_run, plus_run, plus_start = [], [], None
                minus_run.append(ln[1:])
            elif ln.startswith(" "):
                flush()
                minus_run, plus_run, plus_start = [], [], None
                new_no += 1
        flush()
    return out[:MAX_DELTAS]


def payload_section(deltas, cap=2000):
    """The payload block for `deltas` ("" when there are none - the payload
    stays byte-identical for diffs without semantic deltas)."""
    if not deltas:
        return ""
    lines = ["\nSEMANTIC DELTAS (deterministic, computed by the gate from the staged "
             "diff - line pairs where the change alters a comparison operator or "
             "inverts a guard; verify the boundary/equal case is intended):\n"]
    for fname, line_no, old, new, kind in deltas:
        lines.append("  %s:%d %s\n    - %s\n    + %s\n" % (fname, line_no, kind, old.strip(), new.strip()))
    text = "".join(lines)
    return text if len(text) <= cap else text[:cap] + "\n  ... [delta list capped]\n"


def resolve_file_ref(ref, staged):
    """Resolve a reviewer-cited path against the staged file list:
    exact -> unique basename -> close basename. Returns the staged path or
    None. Near-miss citations are the reviewer's most common anchoring slip;
    refuting on exact match alone would discard anchorable findings."""
    if ref in staged:
        return ref
    base = ref.replace("\\", "/").split("/")[-1].strip("`'\"(),:")
    keys = list(staged)
    cands = [k for k in keys if k.replace("\\", "/").split("/")[-1] == base]
    if len(cands) == 1:
        return cands[0]
    best = difflib.get_close_matches(base, [k.replace("\\", "/").split("/")[-1] for k in keys],
                                     n=1, cutoff=0.75)
    if best:
        cands = [k for k in keys if k.replace("\\", "/").split("/")[-1] == best[0]]
        if len(cands) == 1:
            return cands[0]
    return None


_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
_PATH_EXT = re.compile(r"\.(?:py|js|ts|tsx|jsx|json|md|txt|rst|cfg|ini|sh|bat|ps1|"
                       r"toml|yaml|yml|html|css|xml|sql|go|rs|cpp|c|h|lock)$")


def _fragments(para):
    """Quoted code anchors of one finding paragraph: backticked spans first
    (reviewers quote code in backticks), then long punctuation-bearing
    double-quoted spans."""
    out = [m for m in re.findall(r"`([^`\n]{%d,})`" % _FRAGMENT_MIN, para)]
    for m in re.findall(r'"([^"\n]{%d,})"' % _FRAGMENT_MIN, para):
        if re.search(r"[()\[\]=.:/]", m) and m not in out:
            out.append(m)
    return out[:4]


def adjudicate_review(text, files, blobs, diff):
    """Anchor-normalize the findings of a BLOCK review. `blobs` is
    [(path, bytes)] of the staged bodies, `diff` the reviewed diff. Returns a
    dict of per-finding dispositions plus totals - evidence only, the verdict
    is untouched by design (see module docstring)."""
    deltas = semantic_deltas(diff)
    delta_files = {d[0] for d in deltas}
    blob_text = {p: _norm(b.decode("utf-8", "replace")) for p, b in blobs}
    plus_norm = _norm("\n".join(l[1:] for l in diff.split("\n") if l.startswith("+")))
    if text.startswith("model:"):
        parts = text.split("\n\n", 1)
        if len(parts) == 2 and "\n" not in parts[0]:
            body = parts[1]              # canonical artifact shape: header + blank line
        else:
            body = text.split("\n", 1)[1] if "\n" in text else text
    else:
        body = text
    cut = body.find("VERDICT:")
    if cut >= 0:
        body = body[:cut]
    findings = []
    for para in re.split(r"\n\s*\n", body):
        up = para.upper()
        sev = next((s for s in _SEVERITIES if re.search(r"\b%s\b" % s, up)), "")
        toks = {re.sub(r":\d+$", "", t.strip("`'\"(),:;.!?[]{}")) for t in para.split()}
        # path-shaped citation suspects: tokens that look like file references
        # (slash or extension tail). Exact staged matches AND near-miss names
        # both flow through resolution - a wrong citation must be VISIBLE, not
        # silently dropped from the finding set (experiment #10: ~30-50% of
        # model findings carry near-miss filenames).
        suspects = sorted(t for t in toks
                          if len(t) > 3 and _PATH_EXT.search(t)
                          and not t.startswith(("http://", "https://")))
        resolved_map = {s: resolve_file_ref(s, files) for s in suspects}
        cited = sorted({f for f in files if f in toks}
                       | {r for r in resolved_map.values() if r})
        unresolved = [s for s, r in resolved_map.items() if not r]
        if not (sev or cited or unresolved):
            continue
        frs = _fragments(para)
        anchored = []
        for frag in frs:
            f_norm = _norm(frag)
            if f_norm.startswith("+"):
                f_norm = f_norm[1:].strip()
            if len(f_norm) < _FRAGMENT_MIN:
                continue
            hit = any(f_norm in t for p, t in blob_text.items() if p in cited) \
                or f_norm in plus_norm
            if hit:
                anchored.append(frag)
        has_resolved = bool(cited)
        if anchored and unresolved:
            # content anchors to staged bytes, but a cited location is wrong -
            # report the partial state, never silently CONFIRMED
            disp = "PARTIAL_ANCHOR"
        elif anchored:
            disp = "CONFIRMED_ANCHOR"
        elif unresolved and not has_resolved:
            disp = "UNRESOLVED_FILE"
        elif unresolved:
            disp = "PARTIAL_ANCHOR"
        elif has_resolved:
            disp = "FILE_ONLY"
        else:
            disp = "NO_ANCHOR"
        delta_aligned = sorted({f for f in cited if f in delta_files})
        findings.append({
            "severity": sev, "cited": cited,
            "unresolved": unresolved, "fragments": frs,
            "anchored_fragments": anchored, "disposition": disp,
            "delta_aligned_files": delta_aligned,
            "head": _norm(para)[:160],
        })
    return {
        "deltas": len(deltas),
        "delta_lines": [{"file": d[0], "line": d[1], "kind": d[4]} for d in deltas],
        "findings": findings,
        "totals": {d: sum(1 for f in findings if f["disposition"] == d)
                   for d in ("CONFIRMED_ANCHOR", "PARTIAL_ANCHOR", "FILE_ONLY",
                             "NO_ANCHOR", "UNRESOLVED_FILE")},
    }


def summary_line(res):
    """One console line for the BLOCK path. Since the 2026-10-12 upgrade the
    caller treats an all-refuted finding set as verdict-void (fail-closed
    re-review); any surviving anchor keeps the verdict - the strike is
    conservative."""
    t = res["totals"]
    n = len(res["findings"])
    return ("finding adjudication: %d finding(s) - "
            "%d anchored, %d partial, %d file-only, %d no-anchor, %d unresolved-file; "
            "%d semantic delta(s) in this diff"
            % (n, t["CONFIRMED_ANCHOR"], t["PARTIAL_ANCHOR"], t["FILE_ONLY"],
               t["NO_ANCHOR"], t["UNRESOLVED_FILE"], res["deltas"]))
