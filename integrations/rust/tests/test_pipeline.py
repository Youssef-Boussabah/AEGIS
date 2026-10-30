"""Parser, failure and process regression tests. Synthetic data is not protection evidence."""
import json
import os
from pathlib import Path
import sys
import time

import pytest

import protect


def invocation(tmp_path, **updates):
    value = {"schema_version": 1, "rustc": "/usr/bin/rustc", "cwd": str(tmp_path),
             "argv": ["--crate-name", "fixture", "src/lib.rs", "--test", "-C", "opt-level=3",
                      "-C", "lto=thin", "--out-dir", "/tmp/cargo-deps", "--emit=dep-info,link"],
             "compile_env": {"CARGO_PKG_NAME": "fixture"}}
    value.update(updates)
    return value


def test_release_args_normalize_without_mutating_capture(tmp_path):
    original = invocation(tmp_path)["argv"]
    replay = protect.prepare_args(original, tmp_path)
    assert "lto=thin" not in replay
    assert "lto=off" in replay and "codegen-units=1" in replay and "save-temps" in replay
    assert "opt-level=3" in replay
    assert replay.count("--out-dir") == 1
    assert "--emit=llvm-ir,link" in replay and "--print=link-args" in replay
    assert "lto=thin" in original


@pytest.mark.parametrize("extra", [
    ["--target", "wasm32-unknown-unknown"], ["--target=x86_64-unknown-linux-gnu"],
    ["--crate-type", "cdylib"], ["-o", "/tmp/elsewhere"],
    ["-C", "linker-plugin-lto"], ["-Clinker=/tmp/custom"],
    ["-C", "target-cpu=native"], ["-C", "target-feature=+avx2"],
    ["-C", "profile-generate"], ["-C", "relocation-model=static"],
    ["-Zbuild-std"], ["--sysroot=/tmp/custom"], ["@response"], ["--print=link-args"],
    ["-C", "panic=abort"], ["-C", "opt-level=0"],
])
def test_unsupported_compiler_modes_rejected(tmp_path, extra):
    with pytest.raises(protect.WorkflowError, match=".*") as failure:
        protect.prepare_args(invocation(tmp_path)["argv"] + extra, tmp_path)
    assert failure.value.code == "UNSUPPORTED_RUST"


@pytest.mark.parametrize("args", [["--test", "--crate-name", "a", "-C"],
                                 ["--test", "--crate-name", "a", "--out-dir"]])
def test_missing_option_values_rejected(tmp_path, args):
    with pytest.raises(protect.WorkflowError) as failure:
        protect.prepare_args(args, tmp_path)
    assert failure.value.code == "INVALID_INVOCATION"


def test_non_test_invocation_rejected(tmp_path):
    with pytest.raises(protect.WorkflowError) as failure:
        protect.prepare_args(["--crate-name", "a", "-Copt-level=3"], tmp_path)
    assert failure.value.code == "UNSUPPORTED_RUST"


@pytest.mark.parametrize("update", [{"compile_env": {"API_TOKEN": "synthetic-test-placeholder"}},
                                     {"schema_version": True}, {"argv": ["a\0b"]},
                                     {"rustc": "rustc"}, {"extra": "field"}])
def test_invocation_metadata_is_strict(tmp_path, update):
    path = tmp_path / "capture.json"
    path.write_text(json.dumps(invocation(tmp_path, **update)))
    with pytest.raises(protect.WorkflowError) as failure:
        protect.load_invocation(path)
    assert failure.value.code == "INVALID_INVOCATION"


def test_invocation_hardlinks_and_symlinks_rejected(tmp_path):
    source = tmp_path / "capture.json"
    source.write_text(json.dumps(invocation(tmp_path)))
    link = tmp_path / "capture-link.json"
    link.symlink_to(source)
    with pytest.raises(protect.WorkflowError) as failure:
        protect.load_invocation(link)
    assert failure.value.code == "UNSAFE_PATH"
    hard = tmp_path / "hard.json"
    os.link(source, hard)
    with pytest.raises(protect.WorkflowError):
        protect.load_invocation(source)


@pytest.mark.parametrize("header,groups,expected", [
    ("define i32 @owned(i32 %a, i32 %b) #0 {", {}, True),
    ("define internal noundef range(i8 0, 64) i8 @f(i8 noundef range(i8 0, 64) %a) unnamed_addr #2 {", {}, True),
    ('define i64 @"quoted\\22symbol"() local_unnamed_addr #0 {', {}, True),
    ("define i32 @f(i32 %a) #12 {", {"12": "optnone noinline"}, False),
    ("define i32 @f(i32 %a) optnone {", {}, False),
    ("define void @f(i32 %a) {", {}, False),
    ("define ptr @f(i32 %a) {", {}, False),
    ("define { i32, i32 } @f(i32 %a) {", {}, False),
    ("define <4 x i32> @f(i32 %a) {", {}, False),
    ("define i32 @f(ptr byval({i32, i32}) %a) {", {}, False),
    ("define i32 @f(i32 %a, ...) {", {}, False),
    ("define i32 @f([2 x i32] %a) {", {}, False),
])
def test_signature_selection_by_types_only(header, groups, expected):
    selected, position = protect.integer_signature(header, groups)
    assert selected == expected
    assert 0 < position < len(header)


def test_marking_preserves_bodies_and_skips_group_optnone(tmp_path):
    src, dst = tmp_path / "input.ll", tmp_path / "marked.ll"
    src.write_text("define i32 @f(i32 %x) unnamed_addr #0 {\n ret i32 %x\n}\n"
                   "define i32 @g(i32 %x) #1 {\n ret i32 %x\n}\n"
                   "attributes #0 = { noinline }\nattributes #1 = { optnone noinline }\n")
    result = protect.mark_ir(src, dst)
    assert result["definitions"] == 2 and result["marked_integer_signatures"] == 1
    assert dst.read_text().count('"aegis.protect"') == 1
    assert dst.read_text().count("ret i32 %x") == 2
    assert '"aegis.protect"' not in src.read_text()


def test_noncanonical_ir_refused():
    with pytest.raises(protect.WorkflowError) as failure:
        protect.integer_signature("define i32 @multiline(\n", {})
    assert failure.value.code == "UNSUPPORTED_IR"


def test_link_command_parses_quoted_paths_without_shell(tmp_path):
    obj = tmp_path / "my crate-cgu.0.rcgu.o"
    obj.write_bytes(b"test object")
    data = f'LC_ALL="C" PATH="/usr/bin:/bin" "cc" "{obj}" "-o" "{tmp_path}/old" "-Wl,--gc-sections"'
    argv, env, primary = protect.parse_link_command(data, tmp_path)
    assert argv[0].endswith("/cc") and str(obj) in argv and primary == obj
    assert env == {"LC_ALL": "C", "PATH": "/usr/bin:/bin"}


@pytest.mark.parametrize("command", [
    'SECRET_PLACEHOLDER=value cc a-cgu.0.rcgu.o -o out',
    'cc a-cgu.0.rcgu.o b-cgu.1.rcgu.o -o out',
    'cc a.o -o out', 'cc @response -o out', 'rust-lld a.o -o out',
    'cc a.o -o out\ncc b.o -o out',
])
def test_ambiguous_or_unvalidated_link_commands_refused(tmp_path, command):
    with pytest.raises(protect.WorkflowError) as failure:
        protect.parse_link_command(command, tmp_path)
    assert failure.value.code == "UNSUPPORTED_LINK"


def test_cargo_binary_path_uses_exact_crate_and_suffix(tmp_path):
    args = invocation(tmp_path)["argv"] + ["-C", "extra-filename=-abc"]
    assert protect.captured_binary(args, tmp_path) == Path("/tmp/cargo-deps/fixture-abc")


def libtest(passed=True):
    result, status, failed, count = ("ok", "ok", 0, 1) if passed else ("FAILED", "FAILED", 1, 0)
    return (f"running 2 tests\ntest a ... {result}\ntest b ... ignored, deliberate\n"
            f"test result: {status}. {count} passed; {failed} failed; 1 ignored; 0 measured; "
            "0 filtered out; finished in 0.01s\n")


def test_test_parser_preserves_real_failures_and_ignored_tests():
    outcome = protect.test_outcome(libtest(False), 101)
    assert outcome["counts"] == {"passed": 0, "failed": 1, "ignored": 1, "measured": 0, "filtered_out": 0}
    assert outcome["tests"] == {"a": "FAILED", "b": "ignored"}


@pytest.mark.parametrize("text,code", [(libtest(False), 0), (libtest(), 1),
                                      (libtest().replace("test a", "not a test a"), 0),
                                      ("", 0), (libtest() + libtest(), 0)])
def test_invalid_test_outputs_cannot_succeed(text, code):
    with pytest.raises(protect.WorkflowError) as failure:
        protect.test_outcome(text, code)
    assert failure.value.code == "INVALID_TEST_OUTPUT"


def test_same_counts_with_different_failing_tests_are_a_mismatch(tmp_path):
    baseline = libtest(False)
    protected_output = baseline.replace("test a ... FAILED", "test a ... ignored")\
                               .replace("test b ... ignored, deliberate", "test b ... FAILED")

    class Observations:
        # Synthetic libtest observations only, never a fake protection backend.
        def run(self, argv, **kwargs):
            name = Path(argv[0]).name
            return {"returncode": 101, "wall_seconds": 0.1, "stderr": "synthetic.stderr",
                    "stdout": name, "text": protected_output if name == "protected" else baseline}

        @staticmethod
        def stdout(entry):
            return entry["text"]

    record = {}
    with pytest.raises(protect.WorkflowError) as failure:
        protect.compare_tests(Observations(), {name: Path(name) for name in ("original", "baseline", "protected")},
                              tmp_path, 1, record)
    assert failure.value.code == "BEHAVIOR_MISMATCH"
    assert record["tests"]["equivalent"] is False
    assert record["tests"]["observations"]["baseline"][0]["counts"] == \
           record["tests"]["observations"]["protected"][0]["counts"]


def test_runner_minimizes_environment_and_preserves_literal_argv(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_SYNTHETIC_SECRET", "must-not-be-inherited")
    runner = protect.Runner(tmp_path, 5)
    argument = '$(touch should-never-exist); `echo nope`'
    result = runner.run([sys.executable, "-c",
                         "import json,os,sys; print(json.dumps([sorted(os.environ),sys.argv[1]]))", argument])
    keys, observed = json.loads(runner.stdout(result))
    assert "AEGIS_SYNTHETIC_SECRET" not in keys and observed == argument
    assert not (tmp_path / "should-never-exist").exists()


def test_timeout_kills_descendant_process_group(tmp_path):
    runner = protect.Runner(tmp_path, 0.4)
    pidfile = tmp_path / "child.pid"
    script = ("import subprocess,sys,time,pathlib; "
              "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); "
              "pathlib.Path(sys.argv[1]).write_text(str(p.pid)); time.sleep(60)")
    with pytest.raises(protect.WorkflowError) as failure:
        runner.run([sys.executable, "-c", script, str(pidfile)])
    assert failure.value.code == "STAGE_TIMEOUT"
    pid = int(pidfile.read_text())
    for _ in range(30):
        proc = Path(f"/proc/{pid}/stat")
        if not proc.exists() or proc.read_text().split()[2] == "Z":
            break
        time.sleep(0.02)
    else:
        pytest.fail("Stage timeout left its descendant running")


def test_diagnostic_overflow_is_failure(tmp_path):
    runner = protect.Runner(tmp_path, 5)
    with pytest.raises(protect.WorkflowError) as failure:
        runner.run([sys.executable, "-c", f"import sys; sys.stdout.write('x'*{protect.LOG_LIMIT + 1})"])
    assert failure.value.code == "OUTPUT_TOO_LARGE"


def test_existing_output_is_not_modified(tmp_path, capsys):
    sentinel = tmp_path / "sentinel"
    sentinel.write_text("keep")
    code = protect.main(["--invocation", str(tmp_path / "absent"), "--output", str(tmp_path),
                         "--plugin", str(tmp_path / "absent.so")])
    assert code == 1 and sentinel.read_text() == "keep"
    assert json.loads(capsys.readouterr().out)["error"]["code"] == "UNSAFE_PATH"
