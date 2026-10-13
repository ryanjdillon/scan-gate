# scan-gate

A fail-closed egress redactor for LLM request bodies. An AI gateway sends every
request bound for a model provider through scan-gate first; scan-gate redacts
PII and credentials, refuses what must never leave (a private key, an oversized
batch body), and passes requests for locally served models unscanned. It logs
detection types and counts, never a matched value or a body.

It speaks Envoy's External Processing (`ext_proc`) gRPC protocol, so any
Envoy-based gateway can call it. The detectors come from
[corpus-detect](https://github.com/ryanjdillon/corpus/tree/main/packages/detect):
its PII recognisers and its local credential rules only, with no external
scanner binary.

## Deployment

The image is `ghcr.io/ryanjdillon/scan-gate:<tag>`, built by
`.github/workflows/docker.yml` on each `v*` tag. Its entrypoint is `scan-gate`,
which takes no arguments, so a pod runs it with no `command` and no `args`.
It is stateless: it needs no database, volume or provider key, only the
variables below.

```sh
docker run --rm -p 9002:9002 -e CORPUS_SCAN_GATE_FAIL_OPEN=false ghcr.io/ryanjdillon/scan-gate:v0.1.0
```

Configure the gateway's ext_proc filter to send request headers and the request
body in `Buffered` mode; see [the Envoy adapter](docs/envoy.md). Readiness is a
TCP probe on the gRPC port: allow the detectors' cold start (Presidio loads in
seconds).

## Environment

| Variable | Default |
|---|---|
| `CORPUS_SCAN_GATE_ADAPTER` | `envoy-ext-proc` |
| `CORPUS_HOST` | `0.0.0.0` |
| `CORPUS_SCAN_GATE_PORT` | `9002` |
| `CORPUS_SCAN_GATE_WORKERS` | `8` |
| `CORPUS_SCAN_GATE_FAIL_OPEN` | `false` |
| `CORPUS_SCAN_GATE_BLOCK_TYPES` | `private_key` |
| `CORPUS_SCAN_GATE_SKIP_MODELS` | none |
| `CORPUS_SCAN_GATE_BATCH_CLIENTS` | none |
| `CORPUS_SCAN_GATE_BATCH_MAX_BYTES` | `65536` |
| `CORPUS_SCAN_GATE_GRPC_MAX_MESSAGE_BYTES` | 50 MiB |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | unset: no telemetry |
| `OTEL_SERVICE_NAME` | `corpus-scan-gate` |

The names keep the `CORPUS_` prefix from when the gate shipped in the corpus
image. What each does: [Configuration](docs/configuration.md); what happens to a
body: [The egress policy](docs/policy.md).

## Development

```sh
nix develop
just setup   # uv venv + editable install with test and dev extras
just check   # lint, tests, coverage ratchet, commit lint: run before every PR
```

## License

[MPL-2.0](LICENSE).
