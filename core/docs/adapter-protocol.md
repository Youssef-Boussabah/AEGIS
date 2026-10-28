# Adapter protocol `aegis.adapter.v1`

A protection backend is an executable registered in `aegis.toml`:

```toml
[adapters.mybackend]
command = ["/opt/aegis/bin/mybackend-adapter"]
tasks = ["protect"]
timeout_seconds = 300
```

## Invocation

For each job, the orchestrator runs:

```
<command...> --aegis-request <absolute path to request.json>
```

- No shell is involved (`shell=False`, argument array).
- stdin is `/dev/null`. The working directory is the job's `work/` directory.
- Environment: `PATH`, `LANG`/`LC_ALL=C.UTF-8`, `HOME` and `TMPDIR` set to the
  work directory, plus any variables listed in `env_passthrough`.
- The adapter runs in its own process group. When `timeout_seconds` is
  exceeded, the whole group gets `SIGKILL` and the job fails with
  `ADAPTER_TIMEOUT`.

## Request (`request.json`)

```json
{
  "protocol": "aegis.adapter.v1",
  "job_id": "3f2a...",
  "task": "protect",
  "backend": "mybackend",
  "policy_name": "default",
  "input_path": "/abs/.aegis/jobs/<id>/inputs/app.bin",
  "input_sha256": "…",
  "output_dir": "/abs/.aegis/jobs/<id>/outputs",
  "options": {"level": 3, "strip": true},
  "authorization": null
}
```

Treat `options` as untrusted user input. `authorization` is set only for
`attack_lab` tasks.

The adapter **must not modify** the input file. The orchestrator re-hashes it
after the run and fails the job with `ARTIFACT_INTEGRITY_ERROR` if it changed.

## Result (stdout)

Print exactly one JSON object to stdout and nothing else. Logs go to stderr,
which is captured into `adapter/stderr.log` and referenced from the report's
evidence.

```json
{
  "protocol": "aegis.adapter.v1",
  "status": "succeeded",
  "outputs": [{"path": "app.protected.bin"}],
  "evidence": [{"summary": "applied control-flow flattening", "data": {"functions": 41}}],
  "attack_evaluations": [],
  "error": null
}
```

On failure:

```json
{"protocol": "aegis.adapter.v1", "status": "failed",
 "error": {"code": "UNSUPPORTED_FORMAT", "message": "input is not an ELF file"}}
```

## Rules the orchestrator enforces

| Condition | Job result |
| --- | --- |
| executable not found / not executable | `ADAPTER_UNAVAILABLE` |
| exceeded timeout | `ADAPTER_TIMEOUT` |
| nonzero exit code (even if stdout says success) | `ADAPTER_FAILED` |
| `status: "failed"` | `ADAPTER_FAILED` (adapter error in `details.adapter_error`) |
| stdout empty, not JSON, too large, or schema mismatch | `ADAPTER_INVALID_OUTPUT` |
| output path missing, a symlink, or outside `output_dir` | `ADAPTER_INVALID_OUTPUT` |
| `protect` task succeeded with no outputs | `ADAPTER_INVALID_OUTPUT` |
| `attack_lab` task succeeded with no attack evaluations | `ADAPTER_INVALID_OUTPUT` |
| attack evaluations returned for a `protect` task | `ADAPTER_INVALID_OUTPUT` |
| input file changed | `ARTIFACT_INTEGRITY_ERROR` |

Output hashes are computed by the orchestrator. Adapter `evidence` and
`attack_evaluations` are recorded with `source: "adapter"`: they are the
adapter's claims and are not independently verified.

`attack_evaluations[].target` is `"input"`, one of the output paths, or `null`.
The orchestrator turns it into the target artifact's SHA-256.

A reference implementation used by the tests is
`core/src/aegis_core/testing/fake_adapter.py`. It does not protect anything.
