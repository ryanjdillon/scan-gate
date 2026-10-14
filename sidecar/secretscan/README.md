# secretscan

A sidecar that runs [Betterleaks](https://github.com/betterleaks/betterleaks)
as a Go library and tells scan-gate where the secrets in a text are. It builds
the detector from Betterleaks' default ruleset once at startup, so a request
pays only for the scan, and it answers with spans and rule ids, never a
matched value.

## API

HTTP/1.1 on a Unix domain socket, mode 0600. There is no TCP listener; the
scan-gate container reaches the socket through a volume shared within the pod.

`POST /scan` takes `{"text": "<string>"}` and returns

```json
{"findings": [{"start": 13, "end": 53, "rule_id": "github-pat"}]}
```

`start` and `end` are Unicode code point offsets into `text`, half-open, so
`text[start:end]` in Python is the match. Findings are sorted by `start`. A
secret found behind an encoding (base64, hex, percent) spans the encoded text
it came from.

| Status | When |
|---|---|
| 200 | scanned (`findings` may be empty) |
| 400 | the body is not a JSON object with a string `text` |
| 413 | the body is over the size limit |
| 504 | the scan did not finish within the deadline (time queued for a slot counts) |
| 500 | the scan failed: the detector returned a finding it could not place in `text`, or panicked |

Every non-200 means the text was not fully scanned; the caller must not treat
it as clean.

`rule_id` is Betterleaks' rule id, unchanged. In the pinned ruleset (v1.9.0,
463 rules) every id matches `^[a-z0-9][a-z0-9.-]{0,44}$`; the longest is 43
characters. A dot marks a versioned variant of a rule (`auth0-client-secret.1`;
55 reportable rules have one). A caller that needs a narrower charset maps the
id itself: corpus-detect span types (`^[a-z0-9:_-]{1,64}$`) take
`secret:betterleaks:` plus the id with `.` replaced by `_`, which is at most 62
characters. `TestRuleIDsKeepDocumentedShape` fails if a ruleset update breaks
this shape.

`GET /healthz` returns 200. The socket only exists once the detector is built,
so a successful call means the sidecar is ready.

## Configuration

| Variable | Default |
|---|---|
| `SECRETSCAN_SOCKET` | `/run/secretscan/sock` |
| `SECRETSCAN_MAX_BYTES` | `8388608` (8 MiB) |
| `SECRETSCAN_TIMEOUT` | `2s` |

The image runs as the distroless `nonroot` user (65532), which cannot create
`/run/secretscan`, so mount a writable volume there (an `emptyDir` shared with
the scan-gate container).

The size limit and the deadline go together. The detector scans roughly
4-7 MB/s per request, depending on the CPU, so a body much over 8 MiB cannot
finish in 2 s and would only burn CPU on its way to a 504; on a slow core even
an 8 MiB body can miss it. Raise both together, or neither.

## Concurrency and memory

At most `GOMAXPROCS` requests are past the header stage at once. Each takes a
slot *before* it reads its body, so a request queued behind them holds only
its headers, and at most `GOMAXPROCS` bodies are in memory however many
requests the gateway sends. Go sets `GOMAXPROCS` from the container's CPU
limit, so the CPU limit sets the bound.

Measured with 8 MiB bodies and eight concurrent requests, the process starts
at about 45 MiB resident and each busy slot adds 20-35 MiB (the JSON body,
the decoded text and the detector's working copies). Peak resident memory
was 106 MiB with 1 CPU, 126 MiB with 2 and 186 MiB with 4. Size the
container from

    GOMEMLIMIT ≈ 64 MiB + slots × 6 × SECRETSCAN_MAX_BYTES
    memory limit ≈ 1.25 × GOMEMLIMIT

which for a 2-CPU limit and the 8 MiB default is `GOMEMLIMIT=160MiB` and a
`200Mi` memory limit.

## No outbound network

The sidecar sees every cloud-bound request body, so it must have no way to
send one anywhere.

- It never enables Betterleaks' secret validation, the only feature that calls
  a provider. Validation is opt-in (`detect.ValidationOptions{}` leaves it off).
- Betterleaks' expression runtime still links HTTP bindings for validation.
  At startup the sidecar replaces `http.DefaultTransport` and
  `http.DefaultClient` with a transport that refuses every request, so even a
  ruleset that called them could not connect (`TestDenyOutboundHTTP`).
- It has no update check and loads no remote ruleset; the default ruleset and
  the tokenizer data are embedded in the Betterleaks module.
- The pod's NetworkPolicy denies all egress, which also covers code that would
  dial a socket directly.

Logs carry byte counts, finding counts, rule ids and durations only. The
library's own logger is held at error level because it logs secrets at trace
level. A panicking scan is recovered and logged by the panic value's type only,
and net/http's own error log is discarded, since it would print a panic value.

## Build

From source, with the modules pinned in `go.mod` and verified against `go.sum`
(`GOFLAGS=-mod=readonly`, `CGO_ENABLED=0`), on base images pinned by digest:
see [`deploy/secretscan.Dockerfile`](../../deploy/secretscan.Dockerfile). The
image is `ghcr.io/ryanjdillon/scan-gate-secretscan:<tag>`.

```sh
just secretscan-test    # unit tests
just secretscan-bench   # p50/p99 latency at 1 KB, 64 KB and 1 MB
just secretscan-image   # local image, tagged scan-gate-secretscan:dev
```

All test credentials are generated at test time; none is real.
