# scan-gate docs

- [Configuration](configuration.md) — every environment variable, and telemetry.
- [The egress policy](policy.md) — what happens to each request body, in order,
  and what is redacted.
- [Envoy ext_proc adapter](envoy.md) — how the gate plugs into an Envoy-based
  gateway, and the proxy settings it relies on.
- [Vendored ext_proc stubs](../src/scan_gate/_ext_proc/README.md) — why they are
  vendored and how to regenerate them.
