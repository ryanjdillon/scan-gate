"""The ``scan-gate`` command, with its server and telemetry injected."""

from __future__ import annotations

from unittest.mock import create_autospec

import pytest
from click.testing import CliRunner

from scan_gate import adapters, cli
from scan_gate.telemetry import Telemetry


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def serve():
    """The adapter's serve function, so no gRPC server binds a port."""
    return create_autospec(adapters.serve)


@pytest.fixture
def otel():
    return create_autospec(Telemetry, instance=True)


def test_command_serves_between_telemetry_setup_and_flush(runner, serve, otel):
    result = runner.invoke(cli.main, [], obj={"serve": serve, "otel": otel})
    assert result.exit_code == 0, result.output
    otel.configure.assert_called_once_with("corpus-scan-gate")
    serve.assert_called_once_with()
    otel.shutdown.assert_called_once_with()


def test_telemetry_is_flushed_when_the_server_fails(serve, otel):
    serve.side_effect = RuntimeError("bind failed")
    with pytest.raises(RuntimeError):
        cli.run(serve=serve, otel=otel)
    otel.shutdown.assert_called_once_with()


def test_help_describes_the_gate(runner):
    result = runner.invoke(cli.main, ["--help"])
    assert result.exit_code == 0
    assert "egress gate" in result.output


def test_version_is_the_distribution_version(runner):
    result = runner.invoke(cli.main, ["--version"])
    assert result.exit_code == 0
    assert result.output.startswith("scan-gate, version ")
