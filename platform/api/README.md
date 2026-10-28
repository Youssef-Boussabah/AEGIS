# AEGIS API (`aegis_api`)

A FastAPI service over the local orchestrator in `aegis_core`. For setup, see
[core/README.md](../../core/README.md#setup).

## Run

```bash
export AEGIS_CONFIG=$PWD/aegis.toml     # or run from the directory holding aegis.toml
.venv/bin/aegis-api                     # 127.0.0.1:8000
# or: .venv/bin/uvicorn --factory aegis_api:create_app
```

- Binds to loopback by default. A non-loopback `--host` is refused unless
  `AEGIS_API_TOKEN` is set.
- When `AEGIS_API_TOKEN` is set, `/v1/*` requires
  `Authorization: Bearer <token>`. `/healthz` stays open.
- Interactive docs: `http://127.0.0.1:8000/docs`.

## Endpoints

| Method | Path | Result |
| --- | --- | --- |
| `GET` | `/healthz` | `200` ok / `503` degraded: storage writable, backends and whether their executables resolve. No filesystem paths. |
| `POST` | `/v1/jobs` | `202` + `ProtectionJob` (`pending`), `Location` header. The job runs in the background. |
| `GET` | `/v1/jobs/{job_id}` | `ProtectionJob` with the current status |
| `GET` | `/v1/jobs/{job_id}/report` | `ProtectionReport` once terminal; `409 REPORT_NOT_READY` before |

Request body for `POST /v1/jobs`:

```json
{
  "policy": {"backend": "mybackend", "task": "protect", "options": {"level": 3}},
  "input": {"name": "app.bin", "content_base64": "f0VMRg..."}
}
```

For attack-lab tasks, add
`"task": "attack_lab", "authorization": {"authorized_by": "…", "reference": "…", "scope": "…"}`.
This also requires `[attack_lab] enabled = true` in the config.

Every error response looks like
`{"error": {"code": "UNSUPPORTED_BACKEND", "message": "…", "details": {…}}}`.
Validation errors never echo the submitted values.

```bash
curl -s localhost:8000/healthz
curl -s -X POST localhost:8000/v1/jobs -H 'content-type: application/json' \
  -d "{\"policy\":{\"backend\":\"mybackend\"},\"input\":{\"name\":\"app.bin\",\"content_base64\":\"$(base64 -w0 app.bin)\"}}"
curl -s localhost:8000/v1/jobs/<job_id>
curl -s localhost:8000/v1/jobs/<job_id>/report
```

## Tests

```bash
cd platform/api && ../../.venv/bin/pytest
```
