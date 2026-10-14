"""Settings keep the environment names they had inside the corpus image."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from scan_gate.config import FAIL_OPEN_DEPRECATION, Settings


def test_defaults_match_the_corpus_scan_gate():
    loaded = Settings()
    assert (loaded.host, loaded.scan_gate_port, loaded.scan_gate_workers) == ("0.0.0.0", 9002, 8)
    assert loaded.scan_gate_adapter == "envoy-ext-proc"
    assert loaded.pass_unparseable is False
    assert loaded.deprecations() == []
    assert loaded.scan_gate_block_types == "private_key"
    assert loaded.scan_gate_batch_max_bytes == 65536
    assert loaded.scan_gate_grpc_max_message_bytes == 50 * 1024 * 1024


def test_secretscan_defaults_match_the_sidecar():
    loaded = Settings()
    assert loaded.scan_gate_secretscan_enabled is True
    assert loaded.scan_gate_secretscan_socket == "/run/secretscan/sock"
    # A sidecar run with SECRETSCAN_TIMEOUT=4s plus a 1 s margin for its late cancellation.
    assert loaded.scan_gate_secretscan_timeout == 5.0
    assert loaded.scan_gate_secretscan_max_bytes == 8 * 1024 * 1024


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("CORPUS_SCAN_GATE_SECRETSCAN_TIMEOUT", "0"),
        ("CORPUS_SCAN_GATE_SECRETSCAN_TIMEOUT", "-1"),
        ("CORPUS_SCAN_GATE_SECRETSCAN_MAX_BYTES", "0"),
        ("CORPUS_SCAN_GATE_SECRETSCAN_ENABLED", "maybe"),
    ],
)
def test_invalid_secretscan_settings_refuse_to_start(monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    with pytest.raises(ValidationError):
        Settings()


def test_reads_corpus_prefixed_variables(monkeypatch):
    monkeypatch.setenv("CORPUS_HOST", "127.0.0.1")
    monkeypatch.setenv("CORPUS_SCAN_GATE_PORT", "9100")
    monkeypatch.setenv("CORPUS_SCAN_GATE_PASS_UNPARSEABLE", "true")
    monkeypatch.setenv("CORPUS_DATABASE_URL", "postgresql://ignored")  # extra: ignored
    loaded = Settings()
    assert (loaded.host, loaded.scan_gate_port, loaded.pass_unparseable) == (
        "127.0.0.1",
        9100,
        True,
    )


@pytest.mark.parametrize("value", ["true", "1", "yes", "on", "TRUE"])
def test_fail_open_alone_is_the_deprecated_alias(monkeypatch, value):
    monkeypatch.setenv("CORPUS_SCAN_GATE_FAIL_OPEN", value)
    loaded = Settings()
    assert loaded.pass_unparseable is True
    assert loaded.deprecations() == [FAIL_OPEN_DEPRECATION]


def test_agreeing_alias_starts_but_is_still_deprecated(monkeypatch):
    monkeypatch.setenv("CORPUS_SCAN_GATE_FAIL_OPEN", "false")
    monkeypatch.setenv("CORPUS_SCAN_GATE_PASS_UNPARSEABLE", "false")
    loaded = Settings()
    assert loaded.pass_unparseable is False
    assert loaded.deprecations() == [FAIL_OPEN_DEPRECATION]


@pytest.mark.parametrize(("new", "old"), [("true", "false"), ("false", "true")])
def test_conflicting_alias_refuses_to_start(monkeypatch, new, old):
    monkeypatch.setenv("CORPUS_SCAN_GATE_PASS_UNPARSEABLE", new)
    monkeypatch.setenv("CORPUS_SCAN_GATE_FAIL_OPEN", old)
    with pytest.raises(ValidationError, match="contradicts the deprecated"):
        Settings()


def test_unrecognised_boolean_refuses_to_start(monkeypatch):
    monkeypatch.setenv("CORPUS_SCAN_GATE_PASS_UNPARSEABLE", "maybe")
    with pytest.raises(ValidationError):
        Settings()
