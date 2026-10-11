"""Install exact CLEAR-notarized Git blobs, separate from mutable source."""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

from runtime_loader import (CATALOG, GATE_DIR, GENERATION_SEGMENT, RuntimeDenied,
                            unaliased, validate_generation)
import adversary_audit

_location = Path(__file__).resolve()
ROOT = (_location.parents[7] if len(_location.parents) > 7 and
        _location.parents[3].name == "generations" and
        _location.parents[4].name == "runtime" and _location.parents[5].name == ".adversary"
        else _location.parent.parent)
GIT = adversary_audit.GIT
DISPATCHERS = ("pre-commit", "post-commit", "pre-push")
# Layout-agnostic dispatcher sources (0.3.7 plugin port, owner order
# 2026-10-11): the Tools suite stages dispatchers under <gate>/dispatchers/
# with byte-identical installed copies under <gate>/hooks/; a distribution
# that ships only <gate>/hooks/ uses those as the reviewed source directly.
_DISPATCHER_STAGING = GATE_DIR + "/dispatchers"
_HAS_STAGED_DISPATCHERS = (_location.parent / "dispatchers").exists()
if _HAS_STAGED_DISPATCHERS:
    CERTIFIED_CATALOG = CATALOG + tuple(
        GATE_DIR + "/" + folder + "/" + name
        for folder in ("dispatchers", "hooks") for name in DISPATCHERS)
else:
    CERTIFIED_CATALOG = CATALOG + tuple(
        GATE_DIR + "/hooks/" + name for name in DISPATCHERS)
GIT_CONTEXT = {"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR",
               "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_NAMESPACE",
               "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT", "GIT_CEILING_DIRECTORIES"}


def git(root, *args):
    env = {k: v for k, v in os.environ.items() if k not in GIT_CONTEXT}
    env["GIT_NO_REPLACE_OBJECTS"] = "1"
    result = subprocess.run([GIT, "-C", str(root), *args], env=env,
                            capture_output=True, timeout=60)
    if result.returncode:
        raise RuntimeDenied("Git could not verify/install reviewed enforcement: " +
                            result.stderr.decode("utf-8", "replace")[:400])
    return result.stdout


def verify_notary(root, commit):
    # Git hooks export a context for the committing repo. Do not let a foreign
    # repo's variables steer the canonical installation audit.
    saved = {key: os.environ.pop(key) for key in GIT_CONTEXT if key in os.environ}
    try:
        return adversary_audit._audit_commit(str(root), commit, "refs/notes/adversary")
    finally:
        os.environ.update(saved)


def atomic_write(path, raw):
    path = unaliased(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".runtime-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        if Path(tmp).read_bytes() != raw:
            raise RuntimeDenied("Installed enforcement readback mismatch")
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _materialize_generation(generations, final, payload):
    """Write `payload`'s files into a temp dir and atomically rename it to
    `final` (which must not exist). Shared by the fresh-write and the
    stale-era rewrite paths."""
    temp = Path(tempfile.mkdtemp(prefix=".generation-", dir=generations))
    try:
        for name, raw in payload.items():
            if name.endswith(".py"):
                compile(raw, name, "exec")
            target = temp / GENERATION_SEGMENT / name
            target.parent.mkdir(parents=True, exist_ok=True)
            atomic_write(target, raw)
        os.replace(unaliased(temp), unaliased(final))
    finally:
        if temp.exists():
            cleanup = unaliased(temp)
            if cleanup.parent != generations:
                raise RuntimeDenied("Generation cleanup escaped its target directory")
            shutil.rmtree(cleanup)


def _retire_stale_generation(root, commit, final, payload, cause):
    """EV-196 (2026-10-10): a FAILED activation under catalog era A can leave
    generations/<commit> holding era A's file set; the next attempt under era
    B (the bootstrap after a catalog change) deadlocked on it. Generation
    bytes are a deterministic function of (commit, catalog) - every file is
    `git show <commit>:<name>` - so a directory whose every file digest-matches
    THIS commit's payload blobs is provably our own stale-era material and may
    be replaced; anything else, or the ACTIVE commit's directory, is a hard
    failure naming the path. Returns the moved-aside directory for restore on
    a failed rewrite."""
    try:
        active = json.loads(unaliased(root / "active.json").read_text())
    except (OSError, ValueError):
        active = {}
    if isinstance(active, dict) and active.get("commit") == commit:
        raise RuntimeDenied("Generation directory for the ACTIVE commit is not rewritable "
                            "(original failure: %s)" % cause)
    digests = {name: hashlib.sha256(raw).hexdigest() for name, raw in payload.items()}
    package = unaliased(final / GENERATION_SEGMENT)
    for path in sorted(package.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(package).as_posix()
        if rel not in digests or hashlib.sha256(path.read_bytes()).hexdigest() != digests[rel]:
            raise RuntimeDenied("Existing generation directory %s holds bytes foreign to commit "
                                "%s (original failure: %s); refusing to replace it - remove the "
                                "directory manually and retry." % (final, commit, cause))
    aside = final.parent / (".retired-generation-%d" % os.getpid())
    unaliased(aside)
    os.replace(final, aside)
    return aside


def write_generation(root, commit, payload):
    root = unaliased(root)
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or set(payload) != set(CATALOG):
        raise RuntimeDenied("Generation requires an exact fixed catalog")
    manifest = {"commit": commit, "files": {name: hashlib.sha256(raw).hexdigest()
                                           for name, raw in payload.items()}}
    generations = root / "generations"
    unaliased(generations).mkdir(parents=True, exist_ok=True)
    final = unaliased(generations / commit)
    if final.exists():
        try:
            validate_generation(root, manifest)
            return manifest
        except RuntimeDenied as cause:
            aside = _retire_stale_generation(root, commit, final, payload, cause)
            try:
                _materialize_generation(generations, final, payload)
                validate_generation(root, manifest)
            except BaseException:
                if final.exists():
                    shutil.rmtree(unaliased(final))
                os.replace(aside, final)
                raise
            shutil.rmtree(aside)
            return manifest
    _materialize_generation(generations, final, payload)
    validate_generation(root, manifest)
    return manifest


def launcher_source():
    return Path(__file__).with_name("runtime_loader.py").read_text(encoding="utf-8")


# R2 (2026-10-08, owner order "fix it"): the post-commit hook cannot atomically
# replace the dispatcher shim that is executing as that very hook (Windows
# sharing violation, WinError 5) - every in-hook activation used to fail there,
# and the active certified generation silently lagged HEAD. Dispatcher entries
# are therefore idempotent (identical bytes are never rewritten, so the common
# case touches nothing) and defer a genuinely-changed-but-locked swap to
# <runtime>/pending/, completed by the next install whose context does not hold
# that file. Every other entry keeps strict all-or-rollback semantics.
_DEPLOY_LOCK_WAIT_S = float(os.environ.get("ADVERSARY_DEPLOY_LOCK_WAIT_S", "4") or 4)


def _is_dispatcher_target(path):
    return (path.name in DISPATCHERS
            and path.parent.name == "hooks"
            and path.parent.parent.name == GATE_DIR)


def _pending_path(dispatcher):
    pending = dispatcher.parent.parent / ".adversary" / "runtime" / "pending" / dispatcher.name
    pending.parent.mkdir(parents=True, exist_ok=True)
    return pending


def _swap_entry(path, raw, mode):
    """('same' | 'wrote') - idempotent, lock-retrying deployment of one entry."""
    path = unaliased(path)
    if path.exists() and path.read_bytes() == raw:
        if mode is not None:
            path.chmod(mode)
        return "same"
    deadline = time.monotonic() + _DEPLOY_LOCK_WAIT_S
    delay = 0.2
    while True:
        try:
            atomic_write(path, raw)
        except PermissionError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 1.0)
            continue
        if mode is not None:
            path.chmod(mode)
        return "wrote"


def pending_dispatchers(root):
    """Names of dispatcher swaps a locked (executing) hook forced a deployment
    to defer - reported by `status` so drift stays visible, never silent."""
    pending = root / GATE_DIR / ".adversary" / "runtime" / "pending"
    if not pending.is_dir():
        return []
    return sorted(entry.name for entry in pending.iterdir() if entry.name in DISPATCHERS)


def complete_pending(root):
    """Finish deferred dispatcher swaps; entries still locked stay pending."""
    remaining = []
    for name in pending_dispatchers(root):
        entry = unaliased(root / GATE_DIR / ".adversary" / "runtime" / "pending" / name)
        target = root / GATE_DIR / "hooks" / name
        try:
            _swap_entry(target, entry.read_bytes(), 0o755)
        except PermissionError:
            remaining.append(name)
            continue
        entry.unlink()
    if remaining:
        sys.stderr.write("adversary runtime: deferred dispatcher swap still locked: "
                         "%s (retried on the next activation)\n" % ", ".join(remaining))
    return remaining


def deploy_material(entries):
    """Publish the active manifest last; restore prior material on a failed write.

    Dispatcher entries are idempotent and lock-tolerant (R2, 2026-10-08): the
    executing hook shim cannot be atomically replaced on Windows, so identical
    bytes are not rewritten at all and a changed-but-locked dispatcher defers
    to pending/ instead of failing the deployment. Every other entry keeps
    strict all-or-rollback semantics; active.json is still published last."""
    previous = {}
    for path, raw, mode in entries:
        path = unaliased(path)
        previous[path] = (path.read_bytes(), path.stat().st_mode) if path.exists() else (None, None)
    attempted = []
    pendings = []
    try:
        for path, raw, mode in entries:
            path = unaliased(path)
            if _is_dispatcher_target(path):
                try:
                    _swap_entry(path, raw, mode)
                except PermissionError:
                    # The executing hook holds this shim and the retry window
                    # (in _swap_entry) already elapsed: defer exactly this one
                    # swap; everything else - launcher, hook config, and
                    # active.json last - still deploys.
                    pending = _pending_path(path)
                    atomic_write(pending, raw)
                    pendings.append(pending)
                    sys.stderr.write("adversary runtime: dispatcher %s is locked "
                                     "(executing hook) - deferred to %s; every other "
                                     "material deployed\n" % (path.name, pending))
                    continue
                attempted.append(path)
                continue
            atomic_write(path, raw)
            if mode is not None:
                path.chmod(mode)
            attempted.append(path)
    except Exception as exc:
        failures = []
        for pending in pendings:
            # An aborted generation must not leave a live pending swap behind.
            try:
                unaliased(pending).unlink()
            except Exception as rollback:
                failures.append("pending %s: %s" % (pending.name, rollback))
        for path in reversed(attempted):
            old, mode = previous[path]
            try:
                if old is None:
                    if path.exists():
                        unaliased(path).unlink()
                else:
                    if path.read_bytes() != old:
                        atomic_write(path, old)
                    path.chmod(mode)
            except Exception as rollback:
                failures.append(str(rollback))
        if failures:
            raise RuntimeDenied("Deployment incomplete; recovery required: " + "; ".join(failures)) from exc
        raise RuntimeDenied("Deployment failed; previous installation restored: " + str(exc)) from exc


def reviewed_payloads(root):
    root = unaliased(root)
    commit = git(root, "rev-parse", "HEAD").decode().strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise RuntimeDenied("No reviewed enforcement commit")
    # The established notary/auditor binds every changed code blob, not caller assertions.
    kind, detail = verify_notary(root, commit)
    if kind != "clean":
        raise RuntimeDenied("Enforcement installation requires a CLEAR notary: " + detail)
    note = json.loads(git(root, "notes", "--ref=refs/notes/adversary", "show", commit))
    if note.get("commit") != commit:
        raise RuntimeDenied("Notary commit does not match installation commit")
    payload = {name: git(root, "show", commit + ":" + name) for name in CERTIFIED_CATALOG}
    remaining = {name: hashlib.sha256(raw).hexdigest() for name, raw in payload.items()}
    # Every executable byte needs its own CLEAR evidence, including inherited blobs.
    # A full-catalog review may certify unchanged files in an otherwise normal commit.
    noted = {line.split()[1] for line in git(root, "notes", "--ref=refs/notes/adversary", "list").decode().splitlines()
             if len(line.split()) == 2}
    for ancestor in git(root, "rev-list", commit).decode().splitlines():
        if ancestor not in noted:
            continue
        try:
            evidence = json.loads(git(root, "notes", "--ref=refs/notes/adversary", "show", ancestor))
        except (ValueError, RuntimeDenied):
            continue
        if evidence.get("type") != "CLEAR" or evidence.get("commit") != ancestor:
            continue
        if verify_notary(root, ancestor)[0] != "clean":
            continue
        for name, sha in list(remaining.items()):
            row = (evidence.get("files") or {}).get(name) or {}
            # gate round gate_20261008-135545 (MEDIUM): a WARN clearance row must
            # never authorize installing enforcement bytes. Legacy notes predate
            # the verdict field (None == written CLEAR-only era) and stay valid.
            if (row.get("sha") != sha or not row.get("model")
                    or row.get("verdict") not in (None, "CLEAR")):
                continue
            try:
                reviewed_blob = git(root, "show", ancestor + ":" + name)
            except RuntimeDenied:
                continue
            if hashlib.sha256(reviewed_blob).hexdigest() == sha:
                remaining.pop(name)
        if not remaining:
            break
    if remaining:
        raise RuntimeDenied("Catalog blobs lack exact CLEAR review evidence: " + ", ".join(sorted(remaining)))
    return commit, {name: payload[name] for name in CATALOG}


def render_hook_configuration(root, raw):
    """Render reviewed hook templates for this installation; the launcher is
    emitted single-quoted with embedded quotes doubled (PowerShell '&'
    semantics), so spaces AND single quotes in the suite path both survive."""
    data = json.loads(raw)
    marker = "__INSTALLED_RUNTIME_LAUNCHER__"
    launcher = str(root / GATE_DIR / ".adversary/runtime/launch.py").replace("\\", "/").replace("'", "''")
    replaced = 0
    for groups in data["hooks"].values():
        for group in groups:
            for hook in group["hooks"]:
                command = hook["command"]
                if command.count(marker) != 1:
                    raise RuntimeDenied("Hook template requires one installed launcher per command")
                hook["command"] = command.replace(marker, launcher)
                replaced += 1
    if replaced != 4:
        raise RuntimeDenied("Hook template requires all four enforcement commands")
    return (json.dumps(data, indent=2) + "\n").encode("utf-8")


@contextmanager
def installation_lock(root, timeout=30):
    control = unaliased(root / GATE_DIR / ".adversary" / "runtime")
    control.mkdir(parents=True, exist_ok=True)
    lock = control / "installation.lock"
    deadline = time.monotonic() + timeout
    while True:
        unaliased(lock)
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            break
        except FileExistsError:
            if time.monotonic() >= deadline:
                raise RuntimeDenied("Installation busy; retry after the active installer completes")
            time.sleep(min(0.1, max(0, deadline - time.monotonic())))
    try:
        yield
    finally:
        os.close(fd)
        lock.unlink()  # Never steal another installer's lock by age.


def install(root):
    root = unaliased(root)
    with installation_lock(root):
        return _install_locked(root)


def _install_locked(root):
    root = unaliased(root)
    complete_pending(root)
    commit, payload = reviewed_payloads(root)
    # Bootstrap may execute editable source only when it is itself these reviewed bytes.
    # Later activation is invoked through the already-installed validated generation.
    source = Path(__file__).absolute()
    if source == root / GATE_DIR / "enforcement_runtime.py":
        for name in (GATE_DIR + "/enforcement_runtime.py", GATE_DIR + "/runtime_loader.py",
                     GATE_DIR + "/adversary_audit.py"):
            if (root / name).read_bytes().replace(b"\r\n", b"\n") != payload[name]:
                raise RuntimeDenied("Bootstrap source differs from reviewed commit")
    control = unaliased(root / GATE_DIR / ".adversary" / "runtime")
    manifest = write_generation(control, commit, payload)
    prospective_loader = (control / "generations" / commit / GENERATION_SEGMENT /
                          GATE_DIR / "runtime_loader.py")
    validation = subprocess.run([sys.executable, "-I", "-B", str(prospective_loader),
                                 "verify", str(control), json.dumps(manifest)],
                                capture_output=True, timeout=60)
    if validation.returncode:
        raise RuntimeDenied("Prospective installed loader refused its generation; active runtime unchanged")
    # Validate all deployment material before changing any active binding.
    dispatch = {}
    for name in DISPATCHERS:
        if _HAS_STAGED_DISPATCHERS:
            raw = git(root, "show", commit + ":" + GATE_DIR + "/dispatchers/" + name)
            installed = git(root, "show", commit + ":" + GATE_DIR + "/hooks/" + name)
            if raw != installed:
                raise RuntimeDenied("Dispatcher source and reviewed installation differ")
        else:
            raw = git(root, "show", commit + ":" + GATE_DIR + "/hooks/" + name)
        dispatch[name] = raw
    hooks = None
    hook_targets = []
    if GATE_DIR + "/codex_hooks.json" in payload:
        # author-machine Codex harness integration; distributions without the
        # template simply skip this deployment block
        hooks = render_hook_configuration(root, payload[GATE_DIR + "/codex_hooks.json"])
        plugin = Path.home() / "plugins/codex-enforcement-hooks"
        cache = Path.home() / ".codex/plugins/cache/personal/codex-enforcement-hooks"
        if plugin.is_dir():
            hook_targets.append(unaliased(plugin / "hooks.json"))
        if cache.is_dir():
            unaliased(cache)
            for version in cache.iterdir():
                if version.is_dir():
                    hook_targets.append(unaliased(version / "hooks.json"))
    for name in DISPATCHERS:
        unaliased(root / GATE_DIR / "hooks" / name)
    if git(root, "rev-parse", "HEAD").decode().strip() != commit:
        raise RuntimeDenied("Repository changed during runtime preparation; active runtime unchanged")
    material = [(root / GATE_DIR / "hooks" / name, raw, 0o755)
                for name, raw in dispatch.items()]
    material.extend((target, hooks, None) for target in hook_targets)
    material.append((control / "launch.py", payload[GATE_DIR + "/runtime_loader.py"], None))
    # No fallible deployment writes follow the active generation switch.
    material.append((control / "active.json", (json.dumps(manifest, indent=2) + "\n").encode(), None))
    deploy_material(material)
    return manifest


def stage_dispatchers(root):
    """Stage installation bytes without altering the currently running dispatchers."""
    root = unaliased(root)
    for name in DISPATCHERS:
        editable = root / GATE_DIR / "dispatchers" / name
        if not editable.exists():
            raw = git(root, "show", "HEAD:" + GATE_DIR + "/hooks/" + name)
            raw, count = re.subn(rb'(?m)^GATE=.*$', b'GATE="$SUITE/.adversary/runtime/launch.py"', raw)
            if count != 1:
                raise RuntimeDenied("Expected one dispatcher gate binding")
            raw = raw.replace(b'"$PYBIN" "$GATE"', b'"$PYBIN" -I -B "$GATE" gate')
            if name == "post-commit":
                # Activation refuses foreign cwd and any missing/stale notary.
                marker = b"exit 0"
                position = raw.rfind(marker)
                if position < 0:
                    raise RuntimeDenied("Post-commit dispatcher has no final exit")
                raw = raw[:position] + (b'"$PYBIN" -I -B "$GATE" activate || '
                      b'echo "ENFORCEMENT: reviewed runtime activation refused" >&2\n') + raw[position:]
            atomic_write(editable, raw)
        raw = editable.read_bytes().replace(b"\r\n", b"\n")
        if not raw.startswith(b"#!/bin/sh") or b'.adversary/runtime/launch.py' not in raw:
            raise RuntimeDenied("Dispatcher template lacks the installed launcher")
        result = subprocess.run([GIT, "-C", str(root), "hash-object", "-w", "--stdin"],
                                input=raw, capture_output=True, timeout=60,
                                env={k: v for k, v in os.environ.items() if k not in GIT_CONTEXT})
        if result.returncode:
            raise RuntimeDenied("Could not stage dispatcher blob")
        object_id = result.stdout.decode().strip()
        git(root, "update-index", "--cacheinfo", "100755," + object_id +
            "," + GATE_DIR + "/hooks/" + name)
    return [GATE_DIR + "/hooks/" + name for name in DISPATCHERS]


def commit_and_install(root, message):
    """Keep the normal pre-commit gate, then notarize the first dispatcher migration."""
    root = unaliased(root)
    if not message:
        raise RuntimeDenied("Migration commit requires an explicit message")
    output = git(root, "commit", "-m", message)
    sys.stdout.write(output.decode("utf-8", "replace"))
    env = {k: v for k, v in os.environ.items() if k not in GIT_CONTEXT}
    result = subprocess.run([sys.executable, "-B", str(root / GATE_DIR / "adversary_gate.py"), "record"],
                            cwd=str(root), env=env, capture_output=True, timeout=60)
    if result.returncode:
        raise RuntimeDenied("Commit succeeded but notarization refused; installation unchanged: " +
                            result.stderr.decode("utf-8", "replace")[:400])
    # install re-verifies the real notary and every certified blob before deploying.
    return install(root)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("stage", "install", "activate", "status", "commit"))
    parser.add_argument("--message")
    args = parser.parse_args()
    try:
        if args.command == "stage":
            print(json.dumps(stage_dispatchers(ROOT)))
        elif args.command == "commit":
            manifest = commit_and_install(ROOT, args.message)
            print("Committed and installed reviewed enforcement " + manifest["commit"])
        elif args.command == "status":
            control = ROOT / GATE_DIR / ".adversary" / "runtime"
            manifest = json.loads(unaliased(control / "active.json").read_text())
            validate_generation(control, manifest)
            report = {"installed_commit": manifest["commit"], "verified": True}
            pending = pending_dispatchers(ROOT)
            if pending:
                report["pending_dispatchers"] = pending
            print(json.dumps(report))
        else:
            if args.command == "activate":
                cwd_root = git(Path.cwd(), "rev-parse", "--show-toplevel").decode().strip()
                if Path(cwd_root).resolve() != ROOT.resolve():
                    return 0
                head = git(ROOT, "rev-parse", "HEAD").decode().strip()
                if verify_notary(ROOT, head)[0] == "skip":
                    return 0  # A documentation-only commit does not update executable bytes.
            manifest = install(ROOT)
            print("Installed reviewed enforcement " + manifest["commit"])
        return 0
    except Exception as exc:
        sys.stderr.write("Enforcement runtime refused: " + str(exc) + "\n")
        return 2


if __name__ == "__main__":
    sys.exit(main())
