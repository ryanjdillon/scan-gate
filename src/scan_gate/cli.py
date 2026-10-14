"""The ``scan-gate`` command: run the egress gate behind its gateway adapter."""

from __future__ import annotations

import logging
from collections.abc import Callable

import click
from pydantic import ValidationError

from . import adapters
from .config import Settings, get_settings
from .egress.policy import warn_if_secrets_unblocked
from .telemetry import Telemetry, telemetry

#: The OTel service name when ``OTEL_SERVICE_NAME`` is unset.
SERVICE_NAME = "corpus-scan-gate"

log = logging.getLogger(__name__)


def run(
    serve: Callable[[], None] = adapters.serve,
    otel: Telemetry = telemetry,
    config: Settings | None = None,
) -> None:
    """Warn of deprecated or risky settings, configure telemetry, serve, then flush telemetry.

    ``config`` defaults to the settings loaded from the environment.
    """
    config = config or get_settings()
    for message in config.deprecations():
        log.warning(message)
    warn_if_secrets_unblocked(config)
    otel.configure(SERVICE_NAME)
    try:
        serve()
    finally:
        otel.shutdown()


@click.command(name="scan-gate")
@click.version_option(package_name="scan-gate")
@click.pass_context
def main(ctx: click.Context) -> None:
    """Run the egress gate behind the configured gateway adapter.

    The gateway sends LLM request bodies here on the way to model providers. The
    gate redacts PII/secrets (redact-by-default), refuses the highest-confidence
    classes and oversized batch bodies, and passes local models unscanned.
    Reports types + counts, never values. Configured by CORPUS_SCAN_GATE_*
    environment variables.
    """
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    # run()'s collaborators may be injected through the context object.
    collaborators = dict(ctx.obj or {})
    if "config" not in collaborators:
        try:
            collaborators["config"] = get_settings()
        except ValidationError as exc:
            reasons = "; ".join(error["msg"] for error in exc.errors())
            click.echo(f"scan-gate: invalid configuration: {reasons}", err=True)
            ctx.exit(2)
    run(**collaborators)


if __name__ == "__main__":  # pragma: no cover
    main()
