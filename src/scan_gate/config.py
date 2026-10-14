"""Runtime configuration, sourced from environment variables.

The names keep the ``CORPUS_`` prefix they had when scan-gate shipped inside the
corpus image, so a deployment changes only its image and command.
"""

from __future__ import annotations

from functools import cache
from typing import Self

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

#: Logged at startup while the deprecated ``CORPUS_SCAN_GATE_FAIL_OPEN`` is set.
FAIL_OPEN_DEPRECATION = (
    "CORPUS_SCAN_GATE_FAIL_OPEN is deprecated and will be removed; "
    "set CORPUS_SCAN_GATE_PASS_UNPARSEABLE instead"
)


class Settings(BaseSettings):
    """Runtime settings loaded from ``CORPUS_``-prefixed environment variables."""

    model_config = SettingsConfigDict(env_prefix="CORPUS_", extra="ignore")

    # The address the gRPC server binds.
    host: str = "0.0.0.0"

    # The gateway protocol adapter (see ``scan_gate.adapters.ADAPTERS``).
    scan_gate_adapter: str = "envoy-ext-proc"
    scan_gate_port: int = 9002
    scan_gate_workers: int = 8
    # Pass a body that is not a JSON object (multipart audio) through unscanned.
    # Unset means false: such a body is refused. It never governs an error
    # inside the policy, which is always refused. Read it as ``pass_unparseable``.
    scan_gate_pass_unparseable: bool | None = None
    # Deprecated alias for ``scan_gate_pass_unparseable``, honoured only when that
    # is unset; the two set to different values is a startup error.
    scan_gate_fail_open: bool | None = None
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
    # The Betterleaks secret-scan sidecar (sidecar/secretscan). Enabled by default:
    # every scanned body's text is sent to it, and any failure refuses the request.
    # Disabling it (local development without the sidecar) is logged at startup.
    scan_gate_secretscan_enabled: bool = True
    scan_gate_secretscan_socket: str = "/run/secretscan/sock"
    # Seconds for a whole sidecar call: connect, send, and read the full
    # response, so a sidecar dripping bytes cannot hold a request past it. The
    # sidecar answers 504 at its own SECRETSCAN_TIMEOUT, but a scan on a
    # multi-MB body notices cancellation a few hundred ms late; this must exceed
    # it by a margin so the sidecar's own answer is the one seen. The default
    # covers a sidecar run with SECRETSCAN_TIMEOUT=4s plus a 1 s margin.
    scan_gate_secretscan_timeout: float = Field(default=5.0, gt=0)
    # The sidecar's SECRETSCAN_MAX_BYTES: a request body over it is refused (413)
    # without being sent. Keep the two equal.
    scan_gate_secretscan_max_bytes: int = Field(default=8 * 1024 * 1024, gt=0)

    @model_validator(mode="after")
    def _alias_agrees(self) -> Self:
        """Refuse to start when the deprecated alias contradicts its replacement."""
        new, old = self.scan_gate_pass_unparseable, self.scan_gate_fail_open
        if new is not None and old is not None and new != old:
            raise ValueError(
                f"CORPUS_SCAN_GATE_PASS_UNPARSEABLE={new} contradicts the deprecated "
                f"CORPUS_SCAN_GATE_FAIL_OPEN={old}; unset CORPUS_SCAN_GATE_FAIL_OPEN"
            )
        return self

    @property
    def pass_unparseable(self) -> bool:
        """Whether a body that is not a JSON object passes unscanned."""
        if self.scan_gate_pass_unparseable is not None:
            return self.scan_gate_pass_unparseable
        return bool(self.scan_gate_fail_open)

    def deprecations(self) -> list[str]:
        """Warnings for deprecated settings in use, to log once at startup."""
        return [FAIL_OPEN_DEPRECATION] if self.scan_gate_fail_open is not None else []


@cache
def get_settings() -> Settings:
    """The settings loaded from the environment, read on first use.

    Loading is deferred from import so an invalid environment fails where the
    command can report it, not as an import-time traceback.
    """
    return Settings()
