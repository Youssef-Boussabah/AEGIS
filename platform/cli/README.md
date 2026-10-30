# `aegis` CLI (`aegis_cli`)

For setup, see [core/README.md](../../core/README.md#setup). Every command
accepts `--config PATH` and `--json`.

```bash
aegis init [--dir DIR] [--force]       # write aegis.toml + create the local store
aegis inspect                          # health check (exit 1 if degraded)
aegis inspect <job_id>                 # job status
aegis protect <file> --backend NAME [--option KEY=VALUE ...] [--timeout SEC]
aegis protect <file> --backend NAME --task attack-lab \
    --authorized-by "security lead" --authorization-ref ENG-42 \
    --authorization-scope "app.bin build 1.2.3"
aegis report <job_id> [--output report.json]
aegis verify <job_id>                  # exit 0 only if every output's signature is verified
aegis evaluate <job_id> <sha256> --action {execute,analyze,redistribute,modify,attack_evaluate} \
    [--caller-id ID] [--environment ENV]   # Sentinel decision; exit 0 permitted, 1 denied
```

When `[provenance]` / `[sentinel]` are configured, `protect` signs every output
and attaches a Sentinel policy before the job becomes terminal, then prints each
output's verification status. A broken signing configuration fails with exit 3
before any job runs. See [ARCHITECTURE.md §8a](../../ARCHITECTURE.md).

`protect` runs the job to completion in the foreground and prints the job.
`--option` values that parse as JSON scalars (`true`, `3`, `1.5`) are typed;
anything else is passed as a string.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | success |
| 1 | the job ran and failed (report available), health is degraded, an output is not verified (`verify`), an action is denied (`evaluate`), or stored output bytes changed |
| 2 | invalid usage / request |
| 3 | config missing, invalid or already exists; storage error |
| 4 | `UNSUPPORTED_BACKEND` / `UNSUPPORTED_TASK` |
| 5 | `AUTHORIZATION_REQUIRED`, `POLICY_DENIED` |
| 6 | job, input or output artifact/manifest/policy not found (`ARTIFACT_NOT_FOUND`) |
| 7 | job conflict / report not ready |
| 70 | internal error |

Errors print as `error[CODE]: message` on stderr. With `--json`, they print as
`{"error": {...}}` on stdout.

## Tests

```bash
cd platform/cli && ../../.venv/bin/pytest
```
