# scan-gate docs

- [Configuration](configuration.md) — every environment variable, block types,
  the secretscan sidecar's settings and timeout budget, and telemetry.
- [The egress policy](policy.md) — what happens to each request body, in order,
  what is redacted, and how the secretscan sidecar's findings are merged and
  blocked.
- [Envoy ext_proc adapter](envoy.md) — how the gate plugs into an Envoy-based
  gateway, and the proxy settings it relies on.
- [Vendored ext_proc stubs](../src/scan_gate/_ext_proc/README.md) — why they are
  vendored and how to regenerate them.
