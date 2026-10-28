"""Shared stdlib-only tooling for integration tests and benchmarks."""
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def run(*args, ok=True):
    result = subprocess.run([str(a) for a in args], text=True, capture_output=True)
    if ok and result.returncode:
        raise AssertionError(f"command failed ({result.returncode}): {args}\n"
                             f"{result.stdout}\n{result.stderr}")
    return result


def transform(opt, plugin, source, output, options="", report=None, tail="verify"):
    if report:
        options = f"{options};report={report}".lstrip(";")
    pipeline = "aegis-shield" + (f"<{options}>" if options else "")
    return run(opt, "-load-pass-plugin", plugin, f"-passes={pipeline},{tail}",
               "-S", source, "-o", output)


def runtime_ir():
    bodies = []
    for width in (2, 3, 7, 8, 16, 32, 64, 65, 127, 128):
        abi = 32 if width <= 32 else 64 if width <= 64 else 128
        if width < abi:
            body = (f"%x = trunc i{abi} %a to i{width}\n"
                    f"%y = trunc i{abi} %b to i{width}\n"
                    f"%s = add i{width} %x, %y\n"
                    f"%r = zext i{width} %s to i{abi}\nret i{abi} %r")
        else:
            body = f"%s = add i{width} %a, %b\nret i{width} %s"
        bodies.append(f"define i{abi} @width{width}(i{abi} %a, i{abi} %b) #0 {{\n{body}\n}}")
    bodies.append("""
define i64 @chain(i64 %a, i64 %b) #0 {
  %x = add i64 %a, %b
  %y = add i64 %a, 17
  %z = xor i64 %x, %y
  %w = add i64 %z, %b
  %q = xor i64 %w, %a
  %r = add i64 %q, -1
  ret i64 %r
}
define i32 @cycle(i32 %a, i32 %n) #0 {
entry:
  %zero = icmp eq i32 %n, 0
  br i1 %zero, label %exit, label %loop
loop:
  %i = phi i32 [0, %entry], [%next, %loop]
  %v = phi i32 [0, %entry], [%sum, %loop]
  %sum = add i32 %v, %a
  %next = add i32 %i, 1
  %done = icmp eq i32 %next, %n
  br i1 %done, label %exit, label %loop
exit:
  %r = phi i32 [0, %entry], [%sum, %loop]
  ret i32 %r
}
define i64 @twice(i64 %a) #0 {
  %r = add i64 %a, %a
  ret i64 %r
}
define i64 @constant() #0 {
  %r = add i64 -1, 1
  ret i64 %r
}
attributes #0 = { noinline "aegis.protect" }
""")
    return "\n".join(bodies)


def validate_report(report):
    """Check the local v1 contract without a third-party JSON Schema dependency."""
    assert set(report) == {"schema_version", "backend", "llvm_version", "module",
                           "config", "transformed_sites", "functions"}
    assert report["schema_version"] == 1
    assert report["backend"] == "aegis-shield-llvm"
    config = report["config"]
    assert set(config) == {"seed", "max_sites_per_function", "enabled"}
    assert isinstance(config["seed"], str) and config["seed"].isascii() and config["seed"].isdigit()
    assert 0 <= int(config["seed"]) < 2**64
    assert type(config["max_sites_per_function"]) is int
    assert 0 <= config["max_sites_per_function"] <= 1000000
    assert type(config["enabled"]) is bool
    count = 0
    for row in report["functions"]:
        assert set(row) == {"name", "annotated", "status", "reason", "transformed_sites", "skipped_adds"}
        assert isinstance(row["name"], str) and type(row["annotated"]) is bool
        assert row["status"] in ("skipped", "transformed")
        assert bool(row["transformed_sites"]) == (row["status"] == "transformed")
        for value in row["skipped_adds"].values():
            assert type(value) is int and value > 0
        for site in row["transformed_sites"]:
            assert set(site) == {"add_index", "bit_width", "variant"}
            assert type(site["add_index"]) is int and site["add_index"] >= 0
            assert 2 <= site["bit_width"] <= 128
            assert site["variant"] in ("xor-carry", "or-carry")
            count += 1
    assert report["transformed_sites"] == count
    return report


def load_report(path):
    return validate_report(json.loads(Path(path).read_text()))
