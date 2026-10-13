# Envoy ext_proc adapter

`CORPUS_SCAN_GATE_ADAPTER=envoy-ext-proc` (the default) serves Envoy's External
Processing gRPC protocol, which any Envoy-based proxy (Envoy Gateway, an Envoy AI
Gateway) can call. For each request the proxy streams its phases to the gate:
the adapter remembers the caller's `x-client-id` from the request-headers phase,
applies the [policy](policy.md) to the request body, and answers with one of:

- **continue** — the body is clean, or passed unscanned;
- **continue and replace** — the redacted body, with `content-length` removed so
  the proxy recomputes it (a stale length makes Envoy reject the mutated body
  with a 500);
- **immediate response** — a refusal: the status, an OpenAI-style JSON error and
  `content-type: application/json`; the proxy answers the client and stops.

Every other phase is acknowledged unchanged. An error inside the policy is
answered (refused, or passed when failing open), never left to end the stream,
so a fail-closed proxy does not return a bare 5xx with nothing in the log.

## Proxy settings it relies on

The envoy-ext-proc adapter expects the request body in `Buffered` processing
mode, where the proxy sends the whole body as one gRPC message, so
`CORPUS_SCAN_GATE_GRPC_MAX_MESSAGE_BYTES` must be at least the proxy's body
buffer limit. Request headers must be sent too (the default), so the adapter sees
`x-client-id`. Only the `text` of each message and content part is redacted;
image and audio parts pass through byte-identical.

What happens when the gate itself is unreachable is the proxy's choice, set per
route (Envoy's `failure_mode_allow`): fail closed on routes whose bodies must
never leave unscanned.
