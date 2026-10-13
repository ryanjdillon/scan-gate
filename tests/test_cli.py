"""The ``scan-gate`` command, with its server and telemetry injected."""

from __future__ import annotations

from unittest.mock import create_autospec

import pytest
from click.testing import CliRunner

from scan_gate import adapters, cli
from scan_gate.config import FAIL_OPEN_DEPRECATION, Settings, get_settings
from scan_gate.telemetry import Telemetry


@pytest.fixture(autouse=True)
def fresh_settings():
    """Load settings from each test's own environment, not an earlier test's."""
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


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


def test_deprecated_setting_is_warned_once_at_startup(serve, otel, monkeypatch, caplog):
    monkeypatch.setenv("CORPUS_SCAN_GATE_FAIL_OPEN", "true")
    cli.run(serve=serve, otel=otel, config=Settings())
    warnings = [r for r in caplog.records if r.levelname == "WARNING"]
    assert [r.getMessage() for r in warnings] == [FAIL_OPEN_DEPRECATION]


def test_no_warning_without_deprecated_settings(serve, otel, caplog):
    cli.run(serve=serve, otel=otel, config=Settings())
    assert not [r for r in caplog.records if r.levelname == "WARNING"]


def test_conflicting_alias_exits_with_one_clear_line(runner, serve, otel, monkeypatch):
    monkeypatch.setenv("CORPUS_SCAN_GATE_PASS_UNPARSEABLE", "true")
    monkeypatch.setenv("CORPUS_SCAN_GATE_FAIL_OPEN", "false")
    result = runner.invoke(cli.main, [], obj={"serve": serve, "otel": otel})
    assert result.exit_code == 2
    lines = result.output.strip().splitlines()
    assert len(lines) == 1
    assert lines[0].startswith("scan-gate: invalid configuration: ")
    assert "contradicts the deprecated CORPUS_SCAN_GATE_FAIL_OPEN" in lines[0]
    assert "Traceback" not in result.output
    serve.assert_not_called()
    otel.configure.assert_not_called()


def test_injected_config_is_used_as_given(runner, serve, otel):
    result = runner.invoke(cli.main, [], obj={"serve": serve, "otel": otel, "config": Settings()})
    assert result.exit_code == 0, result.output
    serve.assert_called_once_with()
