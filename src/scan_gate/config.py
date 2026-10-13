"""Runtime configuration, sourced from environment variables.

The names keep the ``CORPUS_`` prefix they had when scan-gate shipped inside the
corpus image, so a deployment changes only its image and command.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings loaded from ``CORPUS_``-prefixed environment variables."""

    model_config = SettingsConfigDict(env_prefix="CORPUS_", extra="ignore")

    # The address the gRPC server binds.
    host: str = "0.0.0.0"

    # The gateway protocol adapter (see ``scan_gate.adapters.ADAPTERS``).
    scan_gate_adapter: str = "envoy-ext-proc"
    scan_gate_port: int = 9002
    scan_gate_workers: int = 8
    # Fail-open passes an unredactable body through unchanged (log-only, for a
    # shadow rollout); the default fails closed: an unparseable or erroring body
    # is blocked rather than leaked.
    scan_gate_fail_open: bool = False
    # Comma-separated secret types that force an outright 403 block instead of
    # redaction. Kept small and high-confidence.
    scan_gate_block_types: str = "private_key"
    # Comma-separated model names passed unscanned because they are served
    # locally. Exact names only, so a typo can only make the gate scan more.
    scan_gate_skip_models: str = ""
    # Comma-separated client ids (the gateway's x-client-id) of batch jobs, and the
    # largest body they may send to a scanned model; bigger bodies get a 413.
    scan_gate_batch_clients: str = ""
    scan_gate_batch_max_bytes: int = 65536
    # ext_proc transport: the largest gRPC message the gate accepts and returns.
    # With the request body in Buffered mode, the proxy sends the whole body as
    # one message, so this must be at least the proxy's body buffer limit. grpc's
    # 4 MiB default refuses a chat body carrying an inline image.
    scan_gate_grpc_max_message_bytes: int = 50 * 1024 * 1024


settings = Settings()
