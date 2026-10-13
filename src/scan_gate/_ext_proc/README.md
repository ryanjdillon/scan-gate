# Vendored Envoy ext_proc stubs

The minimal protoc-generated closure of `envoy.service.ext_proc.v3` (18 `_pb2`
modules plus the service's `_pb2_grpc`, across `envoy`, `xds`, `udpa` and
`validate`), with every import rewritten from the proto package (`envoy.…`) to
this private namespace (`scan_gate._ext_proc.envoy.…`). Only the
`google.protobuf` well-known types are imported from outside, from the protobuf
runtime.

Not hand-maintained: ruff and coverage exclude this tree.

## Why vendored

The published `xds-protos` wheel carries the same stubs, but it also ships a
stale top-level `opentelemetry/proto` package. Installed after
`opentelemetry-proto`, it shadows it, and its `common_pb2` (which predates
`InstrumentationScope`) breaks OTLP export.

## Versions

Generated with protobuf gencode 6.31.1 and the gRPC Python plugin 1.74.0. The
generated code checks both at import, which is why `pyproject.toml` bounds
`grpcio>=1.74` and `protobuf>=6.31`.

## Regenerating

There is no script; the closure was generated once. To regenerate:

1. Fetch the `.proto` sources: `envoyproxy/envoy` `api/` (the `envoy/…` files),
   `cncf/xds` (`xds/…` and `udpa/…`) and `bufbuild/protoc-gen-validate`
   (`validate/validate.proto`).
2. With `grpcio-tools` at the gRPC version the stubs should require, run
   `python -m grpc_tools.protoc -I<each root> --python_out=out --grpc_python_out=out
   envoy/service/ext_proc/v3/external_processor.proto` plus every `.proto` it
   imports transitively, except `google/protobuf/*`. The `# source:` header of
   each module here lists the current closure.
3. Rewrite the imports: `from envoy.` → `from scan_gate._ext_proc.envoy.`, and
   likewise for `xds.`, `udpa.` and `validate.`; add an empty `__init__.py` to
   every directory.
4. Raise the `grpcio`/`protobuf` lower bounds in `pyproject.toml` to the new
   gencode versions, then run `just lock` and `just check`.
