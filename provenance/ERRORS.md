# Error Log and Solutions (Role D — Signature, Sentinel & Verification)

This file tracks errors, root causes, and solutions encountered during the development of the Signature, Sentinel & Verification modules.

---

### Error 001: Windows Process Kill Incompatibility
- **Context:** Running `test_timeout_kills_adapter` on Windows host in `core/tests/test_core_orchestrator.py`.
- **Symptom:** `AttributeError: module 'os' has no attribute 'killpg'`.
- **Root Cause:** `os.killpg` is a POSIX-only function not present in the Windows Python standard library. When `communicate(timeout=...)` expired, `_kill_process_group` called `os.killpg(proc.pid, signal.SIGKILL)`, raising an uncaught `AttributeError` instead of handling the timeout.
- **Solution:** In `core/src/aegis_core/adapter.py`, check `if hasattr(os, 'killpg'): os.killpg(...) else: proc.kill()`.
- **Outcome:** The adapter process is cleanly killed on timeout on both POSIX and Windows platforms. Test passed.

---

### Error 002: Windows Path Separator in Test Assertion
- **Context:** Running `test_untrusted_values_never_reach_a_shell` on Windows host in `core/tests/test_core_orchestrator.py`.
- **Symptom:** `AssertionError: assert False` where `argv[-1].endswith("adapter/request.json")` failed.
- **Root Cause:** Path in `argv[-1]` on Windows used backslashes `\` (`...\\.aegis\\jobs\\...\\adapter\\request.json`), failing the forward-slash string ending check.
- **Solution:** In `core/tests/test_core_orchestrator.py:241`, normalize path with `argv[-1].replace("\\", "/").endswith("adapter/request.json")`.
- **Outcome:** Passes on all platforms without weakening the assertion.

---

### Error 003: Pip Hang / Timeout on Host DNS Lookup for NGC Mirror
- **Context:** Installing Python packages into repository-local `.venv`.
- **Symptom:** Lengthy 30-second retries with `NameResolutionError("... Failed to resolve 'pypi.ngc.nvidia.com' ([Errno 11001] getaddrinfo failed)")`.
- **Root Cause:** Host system has global `pip.ini` configuring `https://pypi.ngc.nvidia.com` as an extra index with leading newline characters.
- **Solution:** Created local `.venv/pip.ini` explicitly setting `index-url = https://pypi.org/simple` and overriding `extra-index-url = ` to empty.
- **Outcome:** Pip dependency resolution and wheel builds run instantly from local/PyPI cache without DNS delays.

---

### Error 004: F-string Syntax Error in LLVM Metadata Node
- **Context:** Compiling `aegis_provenance/watermark/engine.py`.
- **Symptom:** `SyntaxError: f-string: valid expression required before '!'` on `meta_line = f'!aegis.watermark = !{!"AEGIS_WM_V1", !"{b64}", !"{crc_hex}"}'`.
- **Root Cause:** Python f-string parser interprets `{!` as an invalid format conversion character (such as `!r` or `!s`).
- **Solution:** Replaced f-string with direct string concatenation: `'!aegis.watermark = !{!"AEGIS_WM_V1", !"' + b64 + '", !"' + crc_hex + '"}'`.
- **Outcome:** Clean syntax and correct textual IR output.

---

### Error 005: Pytest Test Module Name Clashes across Packages
- **Context:** Running `pytest` across `provenance/tests` and `sentinel/tests`.
- **Symptom:** `import file mismatch: imported module 'test_cli' has this __file__ attribute... which is not the same as the test file we want to collect`.
- **Root Cause:** Both test directories contained a file named `test_cli.py`. When `__init__.py` was present in `tests/`, Pytest imported them into the same root package name, causing collisions.
- **Solution:** Removed package `__init__.py` from `tests/` and gave test files unique module basenames (`test_prov_*` and `test_sentinel_*`).
- **Outcome:** Pytest discovers and runs all 141 tests cleanly across all 5 test directories.
