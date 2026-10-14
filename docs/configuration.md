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
| `CORPUS_SCAN_GATE_BLOCK_TYPES` | comma-separated finding types refused with a 403 instead of redacted; an entry ending in `*` matches every type with that prefix (default `private_key,secret:betterleaks:*`). See [block types](#block-types) |
| `CORPUS_SCAN_GATE_SKIP_MODELS` | comma-separated model names passed unscanned because they are served locally (default none) |
| `CORPUS_SCAN_GATE_BATCH_CLIENTS` | comma-separated client ids of batch jobs (default none) |
| `CORPUS_SCAN_GATE_BATCH_MAX_BYTES` | largest body a batch client may send to a scanned model; larger gets a 413 (default `65536`) |
| `CORPUS_SCAN_GATE_GRPC_MAX_MESSAGE_BYTES` | envoy-ext-proc: largest gRPC message accepted and returned (default 50 MiB) |
| `CORPUS_SCAN_GATE_SECRETSCAN_ENABLED` | send each scanned body's text to the secretscan sidecar (default `true`); see [the sidecar](#the-secretscan-sidecar) |
| `CORPUS_SCAN_GATE_SECRETSCAN_SOCKET` | the sidecar's Unix socket (default `/run/secretscan/sock`, the sidecar's own default) |
| `CORPUS_SCAN_GATE_SECRETSCAN_TIMEOUT` | seconds the client allows a whole sidecar call: connect, send and read the full response (default `5`: a sidecar run with `SECRETSCAN_TIMEOUT=4s` plus a 1 s margin) |
| `CORPUS_SCAN_GATE_SECRETSCAN_MAX_BYTES` | largest request the client sends the sidecar; keep equal to its `SECRETSCAN_MAX_BYTES` (default 8 MiB) |

Boolean settings accept `true`/`false`, `1`/`0`, `yes`/`no`, `on`/`off` (and
`t`/`f`, `y`/`n`), in any case; any other value fails at startup.

## Block types

`CORPUS_SCAN_GATE_BLOCK_TYPES` lists the finding types that refuse a request
(403) instead of being redacted. An entry is a type name, matched exactly, or
a prefix ending in `*`. The default, `private_key,secret:betterleaks:*`, blocks
a private key and every secret the secretscan sidecar finds (each Betterleaks
rule is the type `secret:betterleaks:<rule id>`, with `.` read as `_`), without
listing its 463 rules. Setting the variable replaces the default, so a
deployment that sets it must list `secret:betterleaks:*` to keep blocking
Betterleaks secrets; without it they are redacted and the request goes on.
Narrow it to single rules (`secret:betterleaks:github-pat`) to block only some.
With the sidecar enabled, the gate logs a startup warning when no entry covers
`secret:betterleaks:` (that prefix with `*`, or a shorter `*` prefix of it such
as `secret:*`): Betterleaks findings are then redacted, not blocked.

A `*` is only a trailing prefix match. The gate refuses to start (exit 2, one
line naming the problem) on a bare `*`, which would block every finding, PII
included; on a `*` anywhere but the end of an entry, which would match nothing;
and on an empty entry (`a,,b` or a trailing comma). An empty value blocks
nothing.
Blocking is decided per matched span, so a secret masked under a corpus-detect
type because both detectors found it still counts under its Betterleaks type.

## The secretscan sidecar

The gate sends the text of every scanned body to the
[secretscan sidecar](../sidecar/secretscan/README.md) (`POST /scan` over its Unix
socket) in **one call per request**, and merges the secrets it finds into
corpus-detect's redaction. It fails closed:

- any failure refuses the request with a 403 `scan_error`, like any other
  policy error: the socket is missing or refuses, the client times out, the
  sidecar answers anything but 200 (400, 413, 500, 504…), or its reply is not
  a valid list of findings for the text; `PASS_UNPARSEABLE` does not change
  this;
- a request whose text, encoded for the sidecar, is over
  `CORPUS_SCAN_GATE_SECRETSCAN_MAX_BYTES` is refused with a 413
  `request_too_large` and the reason `too_large_to_scan` before anything is
  sent: never skipped. Keep this equal to the sidecar's `SECRETSCAN_MAX_BYTES`
  (8 MiB); image and audio parts are not text and do not count;
- bodies that are not scanned (a model in `SKIP_MODELS`, an unparseable body,
  a batch client's oversized body, a body with no text) are not sent.

**Timeout budget.** The sidecar answers 504 at its own deadline
(`SECRETSCAN_TIMEOUT`, 2 s by default), counting time queued for a scan slot. A
scan of a multi-MB body notices cancellation a few hundred ms late, so the
sidecar's 504 can arrive after its deadline. The client's timeout is one
deadline for the whole call (connect, send, and reading the full response), so
a sidecar that answers a byte at a time cannot hold a request past it. It must
exceed the sidecar's deadline by a margin, so the sidecar's own answer is the
one normally seen; the default 5 s covers a sidecar run with
`SECRETSCAN_TIMEOUT=4s` plus a 1 s margin. A reply later still is a client
timeout, also refused. Raise the two together. The proxy's ext_proc message
timeout must exceed this plus the in-process detectors' time.

`CORPUS_SCAN_GATE_SECRETSCAN_ENABLED=false` runs without the sidecar
(corpus-detect only), for local development; the gate logs a startup warning
saying so. Enabled, it logs the socket, timeout and limit at startup. Do not
disable it in a deployment: Betterleaks secrets would then be neither blocked
nor redacted.

## Failures

A detector, sidecar or policy error always refuses the request: a 403 `egress_policy`
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
  still warned about); to a different value, the gate refuses to start,
  printing one `scan-gate: invalid configuration: …` line and exiting with
  code 2;
- it never passes a body the policy raised on.

Credentials are detected by corpus-detect's credential rules, in process, and
by Betterleaks in the secretscan sidecar; the gate's image ships no scanner
binary.

## Telemetry

OpenTelemetry traces and metrics are exported over OTLP (gRPC) when
`OTEL_EXPORTER_OTLP_ENDPOINT` is set, and not at all otherwise. The service name
is `OTEL_SERVICE_NAME` when set, else `corpus-scan-gate`, the name the gate
reported under inside the corpus image, so existing dashboards and alerts keep
matching. The standard `OTEL_*` exporter variables apply.
