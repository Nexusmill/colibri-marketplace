"""harness_guard selftest: table-driven block/pass matrix run through the REAL hook
entry point (stdin JSON -> exit code), plus fail-open checks. Exit 0 iff ALL PASS."""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
GUARD = os.path.join(HERE, "harness_guard.py")
PY = sys.executable
results = {}


def check(name, ok, detail=""):
    results[name] = (bool(ok), detail)
    print(("PASS " if ok else "FAIL ") + name + ((" " + detail) if detail and not ok else ""))


def run_guard(payload):
    p = subprocess.run([PY, GUARD], input=payload, capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    return p.returncode, p.stderr


def bash(cmd):
    return json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}})


def ftool(tool, path):
    return json.dumps({"tool_name": tool, "tool_input": {"file_path": path}})


BLOCK = [
    ("noverify_commit", bash('git commit --no-verify -m "x"')),
    ("noverify_merge", bash("git merge --no-verify feature")),
    ("noverify_msg_falsepos", bash('git commit -m "add --no-verify docs"')),  # accepted FP
    ("commit_dash_n", bash("git commit -n -m x")),
    ("commit_cluster_n", bash("git commit -anm x")),
    ("hookspath_unset", bash("git config --unset core.hooksPath")),
    ("hookspath_inline", bash('git -c core.hooksPath=/dev/null commit -m x')),
    ("hookspath_repoint", bash("git config core.hooksPath .husky")),
    ("commit_tree", bash("echo tree | git commit-tree HEAD^{tree} -m x")),
    ("update_ref", bash("git update-ref refs/notes/adversary abc123")),
    ("notes_add", bash("git notes --ref refs/notes/adversary add -m '{}' HEAD")),
    ("notes_remove", bash("git notes remove HEAD")),
    ("notes_prune", bash("git notes prune")),
    ("adversary_redirect", bash('echo "{}" > .adversary/clearance.json')),
    ("adversary_copy", bash("cp fake.json repo/.adversary/clearance.json")),
    ("adversary_fake_env", bash("ADVERSARY_FAKE=CLEAR git commit -m x")),
    ("write_clearance", ftool("Write", r"C:\repo\.adversary\clearance.json")),
    ("edit_override", ftool("Edit", "/c/repo/.adversary/OVERRIDE")),
    ("write_override_used", ftool("Write", ".adversary/override_used.json")),
]

PASS_ = [
    ("plain_commit", bash('git commit -m "feat: normal commit"')),
    ("commit_message_n_word", bash('git commit -m "clean and tidy"')),
    ("arming_config", bash("git config core.hooksPath .githooks")),
    ("notes_show", bash("git notes --ref refs/notes/adversary show HEAD")),
    ("gate_run", bash("python C:/Users/User/source/repos/Tools/adversary-gate/adversary_gate.py run")),
    ("gate_status_mentions_dir", bash("python adversary_gate.py status && ls .adversary/reviews")),
    ("audit_run", bash("python .githooks/adversary_audit.py --repo .")),
    ("selftest_with_fake", bash("ADVERSARY_FAKE=CLEAR python gate_selftest.py")),
    ("grep_dash_n", bash("grep -n TODO src/main.py")),
    ("npm_update_unrelated", bash("npm update-refresh")),  # not the git subcommand... see below
    ("write_normal_file", ftool("Write", r"C:\repo\src\main.py")),
    ("edit_normal_file", ftool("Edit", "/repo/tools/adversary_notes.md")),
]


def main():
    for name, payload in BLOCK:
        rc, err = run_guard(payload)
        check("block_" + name, rc == 2 and "G39" in err, "rc=%s %s" % (rc, err[:100]))
    for name, payload in PASS_:
        rc, err = run_guard(payload)
        check("pass_" + name, rc == 0, "rc=%s %s" % (rc, err[:100]))

    # fail-open: malformed stdin must NEVER block the harness
    rc, _ = run_guard("this is not json")
    check("failopen_malformed", rc == 0)
    rc, _ = run_guard("")
    check("failopen_empty", rc == 0)
    rc, _ = run_guard(json.dumps({"tool_name": "Bash"}))
    check("failopen_missing_input", rc == 0)

    bad = {k: v for k, v in results.items() if not v[0]}
    print("\n%d/%d PASS" % (len(results) - len(bad), len(results)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
