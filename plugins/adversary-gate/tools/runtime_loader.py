"""Installed entrypoint: validate a fixed reviewed generation before executing it.

Layout-agnostic since the 0.3.7 plugin port (owner order 2026-10-11): every
path is DERIVED from this file's location, so the same bytes run both in the
Tools suite (gate dir ``adversary-gate/`` under the repo root) and in a
distributed plugin tree (gate dir ``tools/`` under the plugin root). Catalog
membership is existence-derived from an explicit list - a distribution that
ships a subset gets a subset catalog, and the generation snapshot always
contains its own full catalog so validation of an ACTIVE generation is stable
against working-tree changes.
"""
import hashlib
import importlib.abc
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

# --- layout derivation (three execution modes) -----------------------------
# 1. source module:   <root>/<gate-dir>/runtime_loader.py
# 2. snapshot module: <control>/generations/<commit>/<segment>/<gate-dir>/runtime_loader.py
# 3. launch copy:     <root>/<gate-dir>/.adversary/runtime/launch.py
_loc = Path(__file__).resolve()
if _loc.parent.name == "runtime" and _loc.parent.parent.name == ".adversary":
    _GATE_DIR_PATH = _loc.parent.parent.parent          # launch copy
else:
    _GATE_DIR_PATH = _loc.parent                        # source / snapshot module
GATE_DIR = _GATE_DIR_PATH.name                          # "adversary-gate" | "tools" | ...
SUITE_ROOT = _GATE_DIR_PATH.parent
GENERATION_SEGMENT = SUITE_ROOT.name                    # the dir name inside generations/<commit>/

# --- catalog: explicit list, existence-derived ------------------------------
_GATE_FILES = (
    "adversary_gate.py", "adversary_audit.py", "finding_adjudicator.py",
    "docscan.py", "codex_guard.py", "codex_policy.py", "harness_guard.py",
    "project_preview.py", "preview_worker.py", "reviewed_write.py",
    "enforcement_runtime.py", "runtime_loader.py", "codex_hooks.json",
)
_SUITE_FILES = (
    "safe-edit/_safe_edit.py", "skill-gate/skill_gate.py",
    "autoland/__init__.py", "autoland/scan_queue.py",
    "autoland/fleet_config.py", "autoland/locking.py",
    "autoland/front.py",
)


def _derive_catalog():
    names = [GATE_DIR + "/" + f for f in _GATE_FILES if (_GATE_DIR_PATH / f).exists()]
    names += [f for f in _SUITE_FILES if (SUITE_ROOT / f).exists()]
    return tuple(names)


CATALOG = _derive_catalog()


class RuntimeDenied(RuntimeError):
    pass


def unaliased(path):
    path = Path(path).absolute()
    for part in (path, *path.parents):
        if part.exists() or part.is_symlink():
            stat = part.lstat()
            if (part.is_symlink() or getattr(stat, "st_file_attributes", 0) & 0x400 or
                (part.is_file() and getattr(stat, "st_nlink", 1) > 1)):
                raise RuntimeDenied("Installed enforcement contains a linked path")
    if path.resolve() != path:
        raise RuntimeDenied("Installed enforcement path is aliased")
    return path


def _generation_package(root, commit):
    """The generation's package dir: generations/<commit>/<segment>, where the
    segment is DISCOVERED as the unique child (the segment name is a host
    layout artifact - 'Tools' at the author suite, the plugin-root name in a
    distribution - and must never be guessed at validate time)."""
    gdir = unaliased(root / "generations" / commit)
    children = [p for p in gdir.iterdir() if p.is_dir()]
    if len(children) != 1:
        raise RuntimeDenied("Generation must hold exactly one suite directory")
    return unaliased(children[0])


def validate_generation(root, manifest, captured=None):
    root = unaliased(root)
    if (not isinstance(manifest, dict) or set(manifest) != {"commit", "files"} or
        not isinstance(manifest["commit"], str) or not re.fullmatch(r"[0-9a-f]{40}", manifest["commit"]) or
        not isinstance(manifest["files"], dict) or set(manifest["files"]) != set(CATALOG)):
        raise RuntimeDenied("Invalid installed enforcement manifest")
    package = _generation_package(root, manifest["commit"])
    for name, sha in manifest["files"].items():
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
            raise RuntimeDenied("Invalid installed enforcement digest")
        target = unaliased(package / name)
        try:
            raw = target.read_bytes()
        except OSError as exc:
            raise RuntimeDenied("Missing installed enforcement file: " + name) from exc
        if hashlib.sha256(raw).hexdigest() != sha:
            raise RuntimeDenied("Installed enforcement digest mismatch: " + name)
        if captured is not None:
            captured[name] = raw
    contents = [unaliased(p) for p in package.rglob("*")]
    actual = {p.relative_to(package).as_posix() for p in contents if p.is_file()}
    directories = {p.relative_to(package).as_posix() for p in contents if p.is_dir()}
    expected_directories = {Path(name).parent.as_posix() for name in CATALOG}
    if actual != set(CATALOG):
        raise RuntimeDenied("Unreviewed files in installed enforcement generation")
    if directories != expected_directories:
        raise RuntimeDenied("Unreviewed directories in installed enforcement generation")
    return package


class SnapshotImports(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    def __init__(self, package, captured):
        self.package = package
        self.modules = {}
        for name, raw in captured.items():
            if not name.endswith(".py"):
                continue
            relative = name.split("/", 1)[1]
            is_package = relative == "__init__.py"
            module = name.split("/", 1)[0] if is_package else relative[:-3].replace("/", ".")
            if name.split("/", 1)[0] == "autoland" and not is_package:
                module = "autoland." + module
            self.modules[module] = (name, raw, is_package)

    def find_spec(self, fullname, path=None, target=None):
        if fullname in self.modules:
            return importlib.util.spec_from_loader(fullname, self, is_package=self.modules[fullname][2])

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        name, raw, is_package = self.modules[module.__name__]
        filename = str(self.package / name)
        module.__file__ = filename
        if is_package:
            module.__path__ = [str((self.package / name).parent)]
        exec(compile(raw, filename, "exec"), module.__dict__)


def execute_snapshot(package, captured, entry, args):
    target = package / entry
    finder = SnapshotImports(package, captured)
    sys.meta_path.insert(0, finder)
    try:
        sys.argv = [str(target), *args]
        exec(compile(captured[entry], str(target), "exec"),
             {"__name__": "__main__", "__file__": str(target),
              "__package__": "autoland" if entry.startswith("autoland/") else None})
    finally:
        sys.meta_path.remove(finder)


def _entries():
    """Command -> catalog entry, restricted to what this distribution ships."""
    wanted = (("codex", "codex_guard.py"), ("front", "autoland/front.py"),
              ("preview", "preview_worker.py"), ("gate", "adversary_gate.py"),
              ("skill", "skill-gate/skill_gate.py"),
              ("activate", "enforcement_runtime.py"))
    out = {}
    for cmd, fname in wanted:
        entry = fname if "/" in fname else GATE_DIR + "/" + fname
        if entry in CATALOG:
            out[cmd] = entry
    return out


def main():
    try:
        if len(sys.argv) == 4 and sys.argv[1] == "verify":
            validate_generation(Path(sys.argv[2]), json.loads(sys.argv[3]))
            return 0
        root = unaliased(Path(__file__)).parent
        manifest = json.loads(unaliased(root / "active.json").read_text(encoding="utf-8"))
        captured = {}
        package = validate_generation(root, manifest, captured)
        entries = _entries()
        entry = sys.argv[1]
        target = package / entries[entry]
        args = (["activate"] if entry == "activate" else []) + sys.argv[2:]
        # Dispatchers invoke -I -B, so cwd and PYTHONPATH cannot inject source modules.
        paths = [str(package / GATE_DIR)]
        for d in sorted({n.split("/", 1)[0] for n in CATALOG if "/" in n} - {GATE_DIR}):
            paths.append(str(package / d))
        sys.path[:0] = paths
        execute_snapshot(package, captured, entries[entry], args)
        return 0
    except Exception as exc:
        sys.stderr.write("Installed enforcement refused: " + str(exc) + "\n")
        return 2


if __name__ == "__main__":
    sys.exit(main())
