"""OTLP setup: a no-op without an endpoint, idempotent with one."""

from __future__ import annotations

import io
from unittest.mock import create_autospec

from opentelemetry.sdk.metrics.export import ConsoleMetricExporter
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from scan_gate import telemetry as telemetry_mod
from scan_gate.telemetry import Telemetry


def test_enabled_reflects_env(monkeypatch):
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    assert telemetry_mod.enabled() is False
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")
    assert telemetry_mod.enabled() is True


def test_configure_is_a_noop_without_an_endpoint(monkeypatch):
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    span_exporter = create_autospec(telemetry_mod._otlp_span_exporter)
    otel = Telemetry(span_exporter=span_exporter)
    otel.configure("scan-gate-test")
    assert otel.configured is False
    span_exporter.assert_not_called()
    otel.shutdown()  # unconfigured: nothing to flush, no error


def test_configure_installs_providers_once_and_shuts_down_once(monkeypatch):
    # The OTLP exporters would dial the endpoint; the SDK's local exporters
    # stand in for them, so the real providers are exercised.
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")
    spans = InMemorySpanExporter()
    make_span_exporter = create_autospec(telemetry_mod._otlp_span_exporter, return_value=spans)
    make_metric_exporter = create_autospec(
        telemetry_mod._otlp_metric_exporter,
        return_value=ConsoleMetricExporter(out=io.StringIO()),
    )
    otel = Telemetry(span_exporter=make_span_exporter, metric_exporter=make_metric_exporter)
    try:
        otel.configure("scan-gate-test")
        otel.configure("scan-gate-test")  # second call is a no-op
        assert otel.configured is True
        make_span_exporter.assert_called_once_with()
        make_metric_exporter.assert_called_once_with()
    finally:
        otel.shutdown()
        otel.shutdown()  # idempotent


def test_default_exporters_are_otlp():
    from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

    span = telemetry_mod._otlp_span_exporter()
    metric = telemetry_mod._otlp_metric_exporter()
    try:
        assert isinstance(span, OTLPSpanExporter)
        assert isinstance(metric, OTLPMetricExporter)
    finally:
        span.shutdown()
        metric.shutdown()
