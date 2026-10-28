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
```

`protect` runs the job to completion in the foreground and prints the job.
`--option` values that parse as JSON scalars (`true`, `3`, `1.5`) are typed;
anything else is passed as a string.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | success |
| 1 | the job ran and failed (report available), or health is degraded |
| 2 | invalid usage / request |
| 3 | config missing, invalid or already exists; storage error |
| 4 | `UNSUPPORTED_BACKEND` / `UNSUPPORTED_TASK` |
| 5 | `AUTHORIZATION_REQUIRED` |
| 6 | job or input not found |
| 7 | job conflict / report not ready |
| 70 | internal error |

Errors print as `error[CODE]: message` on stderr. With `--json`, they print as
`{"error": {...}}` on stdout.

## Tests

```bash
cd platform/cli && ../../.venv/bin/pytest
```
