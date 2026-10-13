"""Settings keep the environment names they had inside the corpus image."""

from __future__ import annotations

from scan_gate.config import Settings


def test_defaults_match_the_corpus_scan_gate():
    loaded = Settings()
    assert (loaded.host, loaded.scan_gate_port, loaded.scan_gate_workers) == ("0.0.0.0", 9002, 8)
    assert loaded.scan_gate_adapter == "envoy-ext-proc"
    assert loaded.scan_gate_fail_open is False
    assert loaded.scan_gate_block_types == "private_key"
    assert loaded.scan_gate_batch_max_bytes == 65536
    assert loaded.scan_gate_grpc_max_message_bytes == 50 * 1024 * 1024


def test_reads_corpus_prefixed_variables(monkeypatch):
    monkeypatch.setenv("CORPUS_HOST", "127.0.0.1")
    monkeypatch.setenv("CORPUS_SCAN_GATE_PORT", "9100")
    monkeypatch.setenv("CORPUS_SCAN_GATE_FAIL_OPEN", "true")
    monkeypatch.setenv("CORPUS_DATABASE_URL", "postgresql://ignored")  # extra: ignored
    loaded = Settings()
    assert (loaded.host, loaded.scan_gate_port, loaded.scan_gate_fail_open) == (
        "127.0.0.1",
        9100,
        True,
    )
