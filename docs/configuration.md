# Configuration

All settings are environment variables. They keep the `CORPUS_` prefix they had
when the gate shipped inside the corpus image, so a deployment moving to this
image changes only its image and command.

| Variable | Purpose |
|---|---|
| `CORPUS_SCAN_GATE_ADAPTER` | gateway protocol adapter (default `envoy-ext-proc`) |
| `CORPUS_HOST` | address the gRPC server binds (default `0.0.0.0`) |
| `CORPUS_SCAN_GATE_PORT` | listen port (default `9002`) |
| `CORPUS_SCAN_GATE_WORKERS` | concurrent request streams (default `8`) |
| `CORPUS_SCAN_GATE_FAIL_OPEN` | pass a body that is not JSON (e.g. multipart audio) through unchanged; the default `false` refuses it. Accepts `true`/`false`, `1`/`0`, `yes`/`no`, `on`/`off` (and `t`/`f`, `y`/`n`), in any case; any other value fails at startup |
| `CORPUS_SCAN_GATE_BLOCK_TYPES` | comma-separated secret types refused with a 403 instead of redacted (default `private_key`) |
| `CORPUS_SCAN_GATE_SKIP_MODELS` | comma-separated model names passed unscanned because they are served locally (default none) |
| `CORPUS_SCAN_GATE_BATCH_CLIENTS` | comma-separated client ids of batch jobs (default none) |
| `CORPUS_SCAN_GATE_BATCH_MAX_BYTES` | largest body a batch client may send to a scanned model; larger gets a 413 (default `65536`) |
| `CORPUS_SCAN_GATE_GRPC_MAX_MESSAGE_BYTES` | envoy-ext-proc: largest gRPC message accepted and returned (default 50 MiB) |

Credentials are detected with corpus-detect's local credential rules only; the
gate runs no external scanner, so the image ships none.

## Telemetry

OpenTelemetry traces and metrics are exported over OTLP (gRPC) when
`OTEL_EXPORTER_OTLP_ENDPOINT` is set, and not at all otherwise. The service name
is `OTEL_SERVICE_NAME` when set, else `corpus-scan-gate`, the name the gate
reported under inside the corpus image, so existing dashboards and alerts keep
matching. The standard `OTEL_*` exporter variables apply.
