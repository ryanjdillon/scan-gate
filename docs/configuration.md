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
| `CORPUS_SCAN_GATE_PASS_UNPARSEABLE` | pass a body that is not a JSON object (e.g. multipart audio) through unscanned; the default `false` refuses it with a 403 (`unredactable`). Governs only that case: see [failures](#failures) |
| `CORPUS_SCAN_GATE_FAIL_OPEN` | **deprecated** alias of `CORPUS_SCAN_GATE_PASS_UNPARSEABLE`, removed in a later release; see [the alias](#the-deprecated-fail_open-alias) |
| `CORPUS_SCAN_GATE_BLOCK_TYPES` | comma-separated secret types refused with a 403 instead of redacted (default `private_key`) |
| `CORPUS_SCAN_GATE_SKIP_MODELS` | comma-separated model names passed unscanned because they are served locally (default none) |
| `CORPUS_SCAN_GATE_BATCH_CLIENTS` | comma-separated client ids of batch jobs (default none) |
| `CORPUS_SCAN_GATE_BATCH_MAX_BYTES` | largest body a batch client may send to a scanned model; larger gets a 413 (default `65536`) |
| `CORPUS_SCAN_GATE_GRPC_MAX_MESSAGE_BYTES` | envoy-ext-proc: largest gRPC message accepted and returned (default 50 MiB) |

Boolean settings accept `true`/`false`, `1`/`0`, `yes`/`no`, `on`/`off` (and
`t`/`f`, `y`/`n`), in any case; any other value fails at startup.

## Failures

A detector or policy error always refuses the request: a 403 `egress_policy`
error, "request could not be inspected", with the fixed reason `scan_error` in
the proxy's response details. No setting passes it, `PASS_UNPARSEABLE`
included. Only the exception's type is logged, server-side; its message, which
may quote the body, is not logged or returned.

The gate expects the proxy's `processingMode.request.body: Buffered`. An
unparseable body that is not the final chunk is always refused with a 403
`egress_policy` error and the fixed reason `unbuffered`: `PASS_UNPARSEABLE`
passes only a whole body. A parseable body is scanned as usual whether or not
it is final, so Buffered requests with trailers work. See
[the Envoy adapter](envoy.md#proxy-settings-it-relies-on).

What happens when the gate itself is down or unreachable is not set here: it is
the proxy's per-route `failure_mode_allow` (an Envoy Gateway
`EnvoyExtensionPolicy`), configured with the gateway. See
[the Envoy adapter](envoy.md#proxy-settings-it-relies-on).

## The deprecated `FAIL_OPEN` alias

`CORPUS_SCAN_GATE_FAIL_OPEN` once also passed bodies the policy raised on; it
now means exactly `CORPUS_SCAN_GATE_PASS_UNPARSEABLE`:

- set alone, it sets `PASS_UNPARSEABLE`, and the gate logs one deprecation
  warning at startup;
- set together with `PASS_UNPARSEABLE` to the same value, it is ignored (and
  still warned about); to a different value, the gate refuses to start;
- it never passes a body the policy raised on.

Credentials are detected with corpus-detect's local credential rules only; the
gate runs no external scanner, so the image ships none.

## Telemetry

OpenTelemetry traces and metrics are exported over OTLP (gRPC) when
`OTEL_EXPORTER_OTLP_ENDPOINT` is set, and not at all otherwise. The service name
is `OTEL_SERVICE_NAME` when set, else `corpus-scan-gate`, the name the gate
reported under inside the corpus image, so existing dashboards and alerts keep
matching. The standard `OTEL_*` exporter variables apply.
