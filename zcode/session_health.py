#!/usr/bin/env python
"""colibri-marketplace session health + forced HIGH ingestion (zcode twin, 2026-10-18).

Repo-by-repo twin of the Nexusmill grounding health pair (tools/repo_health/
health_ledger.py + summary_ingest.py), ported via the Tools twin (65eb0c7 +
ea14805 budget backport) and the colibri-code-review twin (f407328, which
carries the EV-229/EV-230 hardening; owner order 2026-10-18: cross-repo twin
work runs from the NEXUSMILL session). The canonical machinery keys "current
repo" on the single `current` flag in repos.json - which belongs to the
Nexusmill twin's session - so the marketplace twin owns its verdict instead:

  assess : assess THIS repo (existence, git, state file AGENTS.md, store) and
           persist the marketplace-keyed verdict to
           ~/.zcode/health/colibri_marketplace_ledger.json
           (MARKETPLACE_HEALTH_STATE / MARKETPLACE_HEALTH_REPO override, for
           tests). zcode_repo_guards.ps1 reads that file for the G42 fail-arm.
  ingest : G44 forced ingestion - every [HIGH] summary row in the
           colibri-marketplace store (E:/repo-memory/colibri_marketplace)
           printed for the SessionStart payload; mirrors summary_ingest.py's
           JSON-RPC server call with the store pinned here (no registry
           dependency; tool colibri_marketplace_memory_search).

Fail-open by design: any error prints a note and exits 0 (a broken health
check must never break grounding or block work). assess exits 1 only when
the colibri-marketplace repo itself is failing (the G42 blocking semantic).
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
STORE = Path("E:/repo-memory/colibri_marketplace")
RM_ROOT = Path("C:/Users/User/source/repos/repo-memory")
RM_PY = RM_ROOT / ".venv" / "Scripts" / "python.exe"
STATE_DOC = REPO / "AGENTS.md"
CAP_CHARS = 3000
ROW_CAP = 50


def _state_file() -> Path:
    return Path(os.environ.get("MARKETPLACE_HEALTH_STATE")
                or Path.home() / ".zcode" / "health" / "colibri_marketplace_ledger.json")


def _git(root: Path, *args: str) -> str:
    # 6s per call: assess runs INSIDE the grounding hook's 75s window (two calls back to
    # back) and the grounding bounds the whole child at 12s - a git call that cannot
    # finish in 6s is a hung checkout, not a slow one.
    r = subprocess.run(["git", "-C", str(root), *args], capture_output=True,
                       text=True, timeout=6)
    if r.returncode != 0:
        raise RuntimeError("git %s: %s" % (args[0], (r.stderr or "").strip()[:120]))
    return r.stdout


def assess() -> int:
    override = os.environ.get("MARKETPLACE_HEALTH_REPO")
    root = Path(override) if override else REPO
    failings, warnings = [], []
    dirty = last_days = None
    if not root.exists():
        failings.append("repo root missing: %s" % root)
    else:
        if not (root / ".git").exists():
            failings.append("not a git repository")
        if not override and not STATE_DOC.exists():
            failings.append("state file AGENTS.md missing")
        try:
            dirty = len(_git(root, "status", "--porcelain").splitlines())
            ts = _git(root, "log", "-1", "--format=%ct").strip()
            last_days = int((time.time() - float(ts)) / 86400) if ts else None
        except Exception as exc:
            warnings.append("git state unreadable (%s)" % exc)
    if not STORE.exists():
        failings.append("memory store missing: %s" % STORE)
    state = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "repo": str(root),
        "current_fail": bool(failings),
        "failings": failings,
        "warnings": warnings,
        "dirty": dirty,
        "last_commit_days": last_days,
    }
    try:
        sf = _state_file()
        sf.parent.mkdir(parents=True, exist_ok=True)
        tmp = sf.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, indent=1), encoding="utf-8")
        os.replace(tmp, sf)
    except Exception as exc:
        warnings.append("ledger state not persisted (%s)" % exc)
    print("MARKETPLACE REPO HEALTH: %s (repo %s)" % ("FAIL" if failings else "PASS", root))
    for f in failings:
        print("  FAILING: " + f)
    for w in warnings:
        print("  warn: " + w)
    if dirty is not None:
        print("  dirty=%d last_commit=%sd" % (dirty, "?" if last_days is None else last_days))
    return 1 if failings else 0


def ingest() -> int:
    try:
        rpc = "\n".join([
            '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"ingest","version":"0"}}}',
            '{"jsonrpc":"2.0","method":"notifications/initialized"}',
            '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"colibri_marketplace_memory_search","arguments":{"query":"[HIGH] summary","n":%d,"category":"summary"}}}' % ROW_CAP,
        ])
        env = dict(os.environ)
        env.update({"PYTHONPATH": str(RM_ROOT), "REPO_MEMORY_NAME": "colibri-marketplace",
                    "REPO_MEMORY_DB": str(STORE)})
        # 2026-10-18 budget (ea14805 backport of 3DPrinting 15ae7fb, proven live there):
        # 30s bound, grounding Invoke-Bounded ingest budget 35s, hook window 75s. The
        # server's eager torch import is MANDATED (lazy-load deadlocks FastMCP workers on
        # Windows) and OBSERVED time to first JSON response is 8.4-13.6s
        # (E:/repo-memory/_launch_diag.log) - a short bound fails every cold-session
        # ingestion before the search even runs. TimeoutExpired still falls to the
        # fail-open handler (a missing ingestion must never take the payload with it).
        # gate round 3 finding 1: decode the server's UTF-8 stdout EXPLICITLY - text=True
        # rides the locale codec (cp1252-strict on Windows machines without the UTF-8
        # system locale; THIS machine measures utf-8 via getpreferredencoding, so the
        # loss is latent here but live on any cp1252 host), and 0x8D-class UTF-8
        # continuation bytes (U+200D et al) then raise UnicodeDecodeError inside
        # communicate(), which the fail-open handler converts into a permanently
        # "unavailable" G44 ingestion. The write side was already forced UTF-8 (see
        # main()); this pins the read side to match.
        r = subprocess.run([str(RM_PY), "-B", "-m", "repo_memory.server"],
                           input=rpc, capture_output=True, encoding="utf-8",
                           errors="replace", env=env, timeout=30)
        # distinguish retrieval FAILURE from a genuinely-empty store: only a VALID id:2
        # result may claim the empty store (the vacuous-green class).
        fail = None
        text = None
        for line in r.stdout.splitlines():
            if line.startswith("{") and '"id":2' in line:
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                if "error" in obj:
                    fail = "rpc error: %s" % (obj.get("error"),)
                    break
                res = obj.get("result") or {}
                if res.get("isError"):
                    fail = "tool error result"
                    break
                content = res.get("content") or []
                if not content or not isinstance(content[0], dict) or "text" not in content[0]:
                    fail = "empty rpc content"
                    break
                text = content[0].get("text", "")
        if fail is None and text is None:
            fail = "no id:2 response line (stdout=%r stderr=%r)" % (r.stdout[:120], r.stderr[:120])
        if fail is not None:
            print("FORCED INGESTION (G44): unavailable (%s)." % fail)
            return 0
        keep = []
        for sec in text.split("### ")[1:]:
            lines = sec.splitlines()
            head = lines[0] if lines else ""
            # strip the store's 'N. ' index prefix first, so a [LOW] title that merely
            # MENTIONS '[HIGH]' cannot ride along
            topic = re.sub(r"^\s*\d+\.\s*", "", head)
            if not topic.startswith("[HIGH]"):
                continue
            keep.append(sec.strip()[:700])
        if not keep:
            base = "FORCED INGESTION (G44): no HIGH-rated summaries on record for this repo."
            if len(text.split("### ")[1:]) >= ROW_CAP:
                base += "\n...(row cap reached - query the store for later [HIGH] rows)"
            print(base)
        else:
            out = "FORCED INGESTION (G44) - HIGH summaries, required context at session start:"
            out += "\n\n" + "\n\n".join(keep)
            if len(text.split("### ")[1:]) >= ROW_CAP:
                out += "\n\n...(row cap reached - query the store for later [HIGH] rows)"
            if len(out) > CAP_CHARS:
                out = out[:CAP_CHARS] + "\n...(ingestion truncated - query the store for the rest)"
            print(out)
        return 0
    except Exception as exc:
        print("FORCED INGESTION (G44): unavailable (%s)." % exc)
        return 0


def main() -> int:
    # stdout under the grounding hook's redirect is NOT a console, so Windows Python
    # defaults the encoder to the locale codepage (cp1252) - any non-ANSI character in a
    # store summary then raises UnicodeEncodeError, the fail-open handler swallows it,
    # and G44 ingestion is silently lost every session start. Force UTF-8 with
    # replacement on both streams; the grounding reads the redirect as UTF-8 to match.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "assess":
        return assess()
    if cmd == "ingest":
        return ingest()
    print("usage: session_health.py assess|ingest", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
