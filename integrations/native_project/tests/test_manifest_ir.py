import copy
import json
from pathlib import Path

import pytest

from ir import definitions, elf_functions, select
from runner import Failure
from workflow import load_manifest, normalize_flags, unit_options


@pytest.fixture
def manifest(tmp_path):
    project = tmp_path / "project with spaces"
    project.mkdir()
    (project / "test.cpp").write_text("unsigned f(unsigned a, unsigned b) { return a+b; }\n")
    path = tmp_path / "manifest.json"
    value = {"schema_version": 1, "project_root": str(project), "units": [
        {"source": "test.cpp", "arguments": ["-std=c++17"], "selection": {"mode": "integer-signatures"}}]}
    path.write_text(json.dumps(value))
    return path, value, project


@pytest.mark.parametrize("mutate", [
    lambda m: m.update(schema_version=True),
    lambda m: m.update(schema_version="1"),
    lambda m: m.update(optimization=2),
    lambda m: m.update(backend="fake"),
    lambda m: m.update(unknown=1),
    lambda m: m.update(units=[]),
    lambda m: m["units"][0].update(protect="yes"),
    lambda m: m["units"][0].update(protect=False),
    lambda m: m["units"][0].update(selection={"mode": "names"}),
    lambda m: m["units"][0].update(selection={"mode": "symbols", "symbols": []}),
    lambda m: m["units"][0].update(selection={"mode": "symbols", "symbols": ["f", "f"]}),
    lambda m: m["units"][0].update(selection={"mode": "annotated", "symbols": ["f"]}),
    lambda m: m.update(link={"arguments": ["-Wl,-T,/tmp/script"]}),
    lambda m: m.update(link={"runs": [{"args": [], "expected_exit": True}]}),
])
def test_invalid_manifests_fail(manifest, mutate):
    path, value, _ = manifest
    mutate(value)
    path.write_text(json.dumps(value))
    with pytest.raises(Failure):
        load_manifest(path)


def test_paths_containment_and_links(manifest, tmp_path):
    path, value, project = manifest
    value["units"][0]["source"] = "../escape.cpp"
    path.write_text(json.dumps(value))
    with pytest.raises(Failure, match="contained"):
        load_manifest(path)
    (project / "link.cpp").symlink_to(project / "test.cpp")
    value["units"][0]["source"] = "link.cpp"
    path.write_text(json.dumps(value))
    with pytest.raises(Failure, match="Symlinked"):
        load_manifest(path)


def test_duplicate_json_fields_rejected(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text('{"schema_version":1,"schema_version":1}')
    with pytest.raises(ValueError, match="Duplicate"):
        load_manifest(path)


@pytest.mark.parametrize("encoding", ["arguments", "command"])
def test_compile_database_preserves_argv_without_shell(manifest, tmp_path, encoding):
    path, value, project = manifest
    db = tmp_path / "compile_commands.json"
    argv = ["/usr/bin/clang++", "-DVALUE=$(touch nope)", "-I", str(project), "-O3", "-c",
            str(project / "test.cpp"), "-o", "old.o"]
    entry = {"directory": str(project), "file": "test.cpp"}
    if encoding == "arguments":
        entry[encoding] = argv
    else:
        import shlex
        entry[encoding] = shlex.join(argv)
    db.write_text(json.dumps([entry]))
    value["compile_database"] = str(db)
    value["units"][0].pop("arguments")
    path.write_text(json.dumps(value))
    plan = load_manifest(path)
    unit = plan["units"][0]
    flags, removed = normalize_flags(unit["arguments"], Path(unit["cwd"]), project / "test.cpp")
    assert flags == ["-DVALUE=$(touch nope)", "-I", str(project)]
    assert "-O3" in removed and "old.o" in removed
    assert plan["compile_database_entries"] == 1
    assert not (project / "nope").exists()
    db.write_text(json.dumps([entry, entry]))
    with pytest.raises(Failure, match="exactly one"):
        load_manifest(path)


@pytest.mark.parametrize("arg", ["@args.rsp", "-Xclang", "-fplugin=/tmp/foo.so", "-flto",
                                  "-save-temps", "-march=native", "-Ofast", "-fsanitize=address",
                                  "-x", "--target=aarch64-linux-gnu", ";", "&&", "other.cpp"])
def test_unsupported_compile_flags_are_errors(arg, tmp_path):
    with pytest.raises(Failure) as info:
        normalize_flags([arg], tmp_path)
    assert info.value.code == "INCOMPATIBLE_UNIT"


IR = '''define dso_local i32 @unsigned_add(i32 noundef %a, i32 noundef %b) #0 {
entry:
  %sum = add i32 %a, %b
  ret i32 %sum
}
define i32 @pointer(ptr %a) #0 {
  ret i32 0
}
define void @nothing() #0 {
  ret void
}
define i32 @blocked(i32 %a) #1 {
  ret i32 %a
}
define <2 x i32> @vector(<2 x i32> %a) #0 {
  ret <2 x i32> %a
}
attributes #0 = { nounwind }
attributes #1 = { noinline optnone }
'''


def test_integer_signature_selection_is_conservative():
    text, info = select(IR, {"mode": "integer-signatures"})
    assert info == {"definitions": 5, "integer_signature_candidates": 1,
                    "marked_by_integration": ["unsigned_add"]}
    assert text.count('"aegis.protect"') == 1
    assert len(definitions(text)) == 5
    assert select(IR, {"mode": "annotated"})[0] == IR


def test_explicit_selection_must_resolve():
    with pytest.raises(Failure) as info:
        select(IR, {"mode": "symbols", "symbols": ["pointer", "not_present"]})
    assert info.value.code == "INCOMPATIBLE_SELECTION"
    assert info.value.details["symbols"] == ["not_present", "pointer"]


def test_mangled_and_quoted_names():
    text = 'define i32 @"name\\20space"(i32 %a) local_unnamed_addr #0 {\n ret i32 %a\n}\n'
    selected, info = select(text, {"mode": "symbols", "symbols": ["name space"]})
    assert info["marked_by_integration"] == ["name space"]
    assert 'local_unnamed_addr  "aegis.protect" #0' in selected


def test_malformed_function_headers_are_rejected():
    with pytest.raises(Failure, match="single-line"):
        definitions("define i32 @multiline(\n i32 %a) {\n ret i32 %a\n}")


def test_unique_reproducible_mirage_seeds():
    base = {"seed": "42", "mirage-count": 3}
    a = unit_options(base, "llvm-shield-mirage", "a.cpp")
    b = unit_options(base, "llvm-shield-mirage", "b.cpp")
    assert a["mirage-seed"] != b["mirage-seed"]
    assert a == unit_options(copy.deepcopy(base), "llvm-shield-mirage", "a.cpp")
    assert a["seed"] == "42" and int(a["mirage-seed"]) < 2**63
    assert base == {"seed": "42", "mirage-count": 3}
    assert unit_options(base, "llvm-shield", "a.cpp") == base


@pytest.mark.parametrize("value", [True, 42, "-1", str(2**63), "", "a"])
def test_invalid_mirage_base_seed(value):
    with pytest.raises(Failure) as info:
        unit_options({"seed": value}, "llvm-shield-mirage", "a.cpp")
    assert info.value.code == "INVALID_OPTIONS"


def test_elf_parser_refuses_other_formats(tmp_path):
    path = tmp_path / "bad.o"
    path.write_bytes(b"not ELF")
    with pytest.raises(Failure) as info:
        elf_functions(path)
    assert info.value.code == "UNSUPPORTED_FORMAT"
