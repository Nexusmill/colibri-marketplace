"""docscan selftest. Fake-stub + chunk/parse tests run with no model; a real-model accuracy
smoke runs only when a model is present (skipped otherwise, like the Blender-dependent
batteries). Exit 0 iff all executed checks pass."""
import os
import sys
import importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("docscan", os.path.join(HERE, "docscan.py"))
ds = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ds)

results = {}


def check(name, ok, detail=""):
    results[name] = bool(ok)
    print(("PASS " if ok else "FAIL ") + name + (("  " + detail) if detail and not ok else ""))


def main():
    # 1. chunking keeps whole lines and respects the size bound
    text = "".join("line %d has some words\n" % i for i in range(500))
    chunks = ds._chunk(text, 200)
    check("chunk_bound", all(len(c) <= 200 + 40 for c in chunks) and len(chunks) > 1)
    check("chunk_lossless", "".join(chunks) == text)
    check("chunk_no_midline", all(c.endswith("\n") or c == chunks[-1] for c in chunks))

    # a single line LONGER than size is hard-split into <= size pieces (finding 2)
    cs = ds._chunk("A" * 50000, 6000)
    check("chunk_long_line_split", len(cs) > 1 and all(len(c) <= 6000 for c in cs), str([len(c) for c in cs]))

    # 2. empty text is trivially clear, no model call
    r = ds.scan("   \n  \n")
    check("empty_clear", r["status"] == "clear")

    # 3. FAKE stub (selftest env + advgate_ cwd only) drives block/clear without a model
    import tempfile
    os.chdir(tempfile.mkdtemp(prefix="advgate_docscan_"))     # satisfy the stub's cwd guard
    os.environ["ADVERSARY_SELFTEST"] = "1"
    os.environ["DOCSCAN_FAKE"] = "BLOCK"
    r = ds.scan("anything here")
    check("fake_block", r["status"] == "block", str(r))
    os.environ["DOCSCAN_FAKE"] = "CLEAR"
    r = ds.scan("anything here")
    check("fake_clear", r["status"] == "clear", str(r))

    # 4. FAKE ignored OUTSIDE a selftest repo (mirrors adversary_gate's ADVERSARY_FAKE guard):
    #    without ADVERSARY_SELFTEST=1 the stub must not fire (would fall through to a real call
    #    or degrade). We assert it does NOT return the fake verdict shape from the stub path.
    os.environ["DOCSCAN_FAKE"] = "BLOCK"
    del os.environ["ADVERSARY_SELFTEST"]
    r = ds.scan("plain prose with no secret at all, just words")
    # with no model present this degrades; with a model it really scans -> clear. Either way
    # it must NOT be a stubbed 'block' on innocuous text.
    check("fake_ignored_outside_selftest", r["status"] in ("clear", "degraded"), str(r))
    os.environ.pop("DOCSCAN_FAKE", None)

    # 4b. the model's EVIDENCE gate (2026-09-07, push of the evaluation reports to main): a
    #     BLOCK stands only if the REASON line names a value-shaped literal; a NAME or a
    #     DESCRIPTION withdraws it (the model quoted "REPLICATE_API token variable" and a
    #     prose description of a project id as the "value"); an empty/none reason keeps the
    #     block - fail closed. Fixture values are assembled at runtime (no floor literal).
    model_slug = "z-ai" + "/" + "glm-5.3-flash"             # built from parts: never a literal in bytes
    names = [
        "REPLICATE_API token variable",
        "GOOGLE_CLOUD_PROJECT value (the real project id, quoted in the workflow) and a "
        "hard-coded LANGCHAIN_HUB_HANDLE value (the owner's hub handle)",
        "FIRMS_MAP_KEY",
        "Postgres creds",
        "the ANTHROPIC api-key variable and the workspace id",
        "CONTEXT7_API_KEY and the S3_BUCKET setting",      # digits inside NAMES (underscored)
        "yourpassword",                                     # placeholder tokens name no value
        "postgres password your-key-here",                  # (push-guard catch 2026-09-08)
        "the value <redacted> or changeme",
        "<your-password-here>",
        "pw", "user:pw", "the password placeholder",         # bare ROLE words = DSN placeholder
        "lsv2_sk_...", "sk-ant-...", "AKIA\u2026", "the key lsv2_sk_... in the example",  # an
        # push-guard catch 2026-09-09 (Nexusmill state push, chunk 16): the model glued the elided
        # prefix to the next word and wrapped it in prose the vocabulary did not know
        "AIza\u2026-shaped string (Google API key pattern)", "one AIza\u2026-shaped string in a tracked HTML",
        "an `AKIA...`-style id", "sk-ant-...-prefixed token",
        # push-guard catch 2026-09-14 (colibri main landing, chunk 3 of a 14-commit feed): the model
        # wrote a prose VERB the vocabulary lacked in front of an env-var NAME, so the name-only
        # withdrawal never fired and a legitimate gate doc refused the owner's fast-forward
        "needs `OPENROUTER_API_KEY`", "requires OPENROUTER_API_KEY and XAI_API_KEY",
        "needs the XAI_API_KEY env var", "the workflow expects CONTEXT7_API_KEY to be set",
        # EV-083 (marketplace README push 2026-09-14): a provider-slash-model SLUG is a name - the
        # reviewer's own default model id was quoted 3/3 as 'the secret value'
        model_slug, "the OpenRouter model id " + model_slug, "the default reviewer " + model_slug
        + " and its XAI_API_KEY fallback", "model slug " + "x-ai/" + "grok-4.6",
        "meta-llama/" + "llama-3.1-70b-instruct", "deepseek/" + "deepseek-chat", "openai/" + "gpt-4o",
        # push-guard catch 2026-09-15 (the fleet probe push, chunk 11 of 35, 3/3): a plan document's
        # embedded test code `monkeypatch.setenv("XAI_API_KEY", "k")` - the model quoted `"k"` as the
        # secret value. A ONE-CHARACTER literal is never a credential and names no value.
        '"k"', "'k'", "k", 'XAI_API_KEY set to "k"', "the value " + "7",
    ]                                                       # ELIDED vendor prefix names no value                                                       # vocabulary (fleet probe 2026-09-08)
    aws_example = "AKIA" + "IOSFODNN7" + "EXAMPLE"          # gate round 1: an ALL-CAPS VALUE
    project_id = "crafty-" + "hook-" + "483415" + "-b3"
    values = [
        "makerbase",
        "password makerbase",
        "sunshine-dragon-42",
        "root / X9k2-mQ7p!zL",
        'GOOGLE_CLOUD_PROJECT: "%s"' % project_id,
        project_id,
        "S3cr3tDbP@ss2024",
        aws_example, "PASSWORD1", "ABC123", "MY_SECRET_123",   # all-caps values must HOLD
        "sample-key-9f2ac1b8", "mysamplekey9f2a", "yourapp-secret", "ExamplePass2024!",  # a
        "<sunshine-dragon-42>", "sk-ant-api03-<realkey9f2ac1>",   # placeholder MORPHEME inside a
        "pw@host", "pw1234", "Passw0rd", "PW", "user:s3cr3t",    # role word + value stays a value
        "lsv2_sk_9f2ac1b8e4d7...", "sk-ant-api03-Qx9" + "kLm2...", "9f2ac1b8e4d7...",  # a TRUNCATED
        "makerbase...", "hunter2...", "Passw0rd...", "PASSWORD1...", "password: makerbase... (rotated)",
        # slug rule bounds (2026-09-14): a slash alone names nothing - the LEFT side must be a known
        # provider and the RIGHT side must look like a model id (lowercase, no 3+ digit run, no
        # 8+ hex run); a provider-prefixed key, a hex tail, a dictionary pair or base64 all HOLD
        "hunter/two", "abc/def123==", "openai/" + "sk-9f2ac1b8e4d7", "z-ai/" + "9f2ac1b8e4d7c3a0",
        "openrouter/" + "Qx9kLm2pR4sT", "needs " + "makerbase", "requires " + "hunter2",
        # gate round 1 (gate_20260914-215739): provider/PASSWORD must hold - the right side needs a
        # MODEL shape (dotted version, <n>b size or a family word), and a bare vendor word stays unknown
        "openai/" + "makerbase", "postgres/" + "sunshine-dragon-42", "openai/" + "hunter2",
        "x-ai/" + "admin", "nvidia", "password " + "nvidia", "z-ai", "the value " + "qwen",
        # the one-character rule stops at ONE: two characters and up stay values (PW above holds too)
        '"k7"', "k7", "kQ", "k7Qz", 'XAI_API_KEY set to "k7"',
    ]                             # real key OR a complete short password + prose ellipsis holds (round 4)                                                          # value never withdraws (round 2)
    check("evidence_names_withdraw", all(ds._evidence_is_name(n) for n in names),
          str([n for n in names if not ds._evidence_is_name(n)]))
    check("evidence_values_hold", not any(ds._evidence_is_name(v) for v in values),
          str([v[:20] for v in values if ds._evidence_is_name(v)]))
    check("evidence_empty_holds", not ds._evidence_is_name("") and not ds._evidence_is_name("none")
          and not ds._evidence_is_name("the value"))

    # 5. REAL-MODEL accuracy smoke (skipped if absent) - 0 missed secrets is the contract
    if ds.model_available():
        BLOCK = [
            "printer ssh: user mks, password makerbase",
            "Router admin login: root / X9k2-mQ7p!zL",
            "connect: mysql -u root -pS3cr3tDbP@ss2024 mydb",
        ]
        CLEAR = [
            "export API_KEY=your-key-here   # replace this",
            'deploy runs: sshpass -p "$PRINTER_PW" ssh mks@host',
            "store REPLICATE_API_TOKEN in the vault; never commit it",
            # 2026-09-07: a security INVENTORY that describes where credentials live carries
            # no value - the push guard's docs re-run blocked an evaluation report on these
            # shapes (four chunks) until the prompt learned to demand the quoted value
            "Never-publish flags (paths only, values not read): the root .env holds LangSmith, "
            "Google, Tavily, Replicate and Postgres entries plus a router login; "
            "logs/credential_search_20260505.txt is a 95 MB search dump; "
            "q2/restore_image.py has 11 password-assignment patterns; "
            "STL/_render_gallery.html carries one key-shaped string - verify and purge if real.",
            "Config/env: GOOGLE api-key variable, GOOGLE_MAPS api-key variable, "
            "GOOGLE_URL_SIGNING_SECRET, GOOGLE_CLOUD_PROJECT; the LangSmith api-key variable "
            "and workspace id; Postgres creds for env-monitoring tooling.",
        ]
        fn = sum(1 for t in BLOCK if ds.scan(t)["status"] != "block")
        fp = sum(1 for t in CLEAR if ds.scan(t)["status"] == "block")
        check("realmodel_no_missed_secrets", fn == 0, "FN=%d" % fn)
        check("realmodel_no_false_alarms", fp == 0, "FP=%d (friction, not fatal)" % fp)
    else:
        print("SKIP realmodel_* (no local model present)")

    # 6. broken BINARY (cli exists but is not runnable) -> DEGRADE, never crash (finding 1).
    # Machine-independent: dummy cli + dummy model files, stub disabled.
    d = tempfile.mkdtemp(prefix="advgate_bb_")
    fake_cli = os.path.join(d, "notacli.txt"); open(fake_cli, "w").write("not an executable")
    fake_model = os.path.join(d, "m.gguf"); open(fake_model, "wb").write(b"\x00not a real gguf")
    for k, v in [("NEXUSMILL_LLAMA_CLI", fake_cli), ("NEXUSMILL_DOCSCAN_MODEL", fake_model),
                 ("DOCSCAN_FAKE", "")]:
        os.environ[k] = v
    try:
        r = ds.scan("printer login user mks password makerbase")
        check("broken_binary_degrades", r["status"] == "degraded", str(r))
    finally:
        for k in ("NEXUSMILL_LLAMA_CLI", "NEXUSMILL_DOCSCAN_MODEL", "DOCSCAN_FAKE"):
            os.environ.pop(k, None)

    bad = [k for k, v in results.items() if not v]
    print("\n%d/%d PASS" % (len(results) - len(bad), len(results)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
