"""OpenTelemetry: export traces and metrics over OTLP.

No-op unless ``OTEL_EXPORTER_OTLP_ENDPOINT`` is set, so local runs and tests do
not export. The service name is ``OTEL_SERVICE_NAME`` when set, else the default
the caller passes (``corpus-scan-gate``, kept from when the gate shipped in the
corpus image so dashboards and alerts carry over). The SDK and exporter imports
are deferred to :meth:`Telemetry.configure`, so importing this module stays cheap.
"""

from __future__ import annotations

import atexit
import logging
import os
from collections.abc import Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from opentelemetry.sdk.metrics.export import MetricExporter
    from opentelemetry.sdk.trace.export import SpanExporter

log = logging.getLogger(__name__)


def enabled() -> bool:
    """Report whether an OTLP endpoint is configured."""
    return bool(os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))


def _otlp_span_exporter() -> SpanExporter:
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

    return OTLPSpanExporter()


def _otlp_metric_exporter() -> MetricExporter:
    from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter

    return OTLPMetricExporter()


class Telemetry:
    """The process's trace and metric providers, installed at most once.

    Args:
        span_exporter: Builds the span exporter (default: OTLP over gRPC).
        metric_exporter: Builds the metric exporter (default: OTLP over gRPC).
    """

    def __init__(
        self,
        span_exporter: Callable[[], SpanExporter] = _otlp_span_exporter,
        metric_exporter: Callable[[], MetricExporter] = _otlp_metric_exporter,
    ) -> None:
        self._span_exporter = span_exporter
        self._metric_exporter = metric_exporter
        self.configured = False
        self._shut_down = False

    def configure(self, default_service_name: str) -> None:
        """Install the OTLP trace and metric providers.

        No-op unless an OTLP endpoint is configured; safe to call more than once.
        """
        if self.configured or not enabled():
            return

        from opentelemetry import metrics, trace
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        service = os.getenv("OTEL_SERVICE_NAME", default_service_name)
        resource = Resource.create({"service.name": service})

        tracer_provider = TracerProvider(resource=resource)
        tracer_provider.add_span_processor(BatchSpanProcessor(self._span_exporter()))
        trace.set_tracer_provider(tracer_provider)

        reader = PeriodicExportingMetricReader(self._metric_exporter())
        metrics.set_meter_provider(MeterProvider(resource=resource, metric_readers=[reader]))

        atexit.register(self.shutdown)
        self.configured = True
        log.info("OpenTelemetry configured for %s", service)

    def shutdown(self) -> None:
        """Flush and shut down the providers; a no-op if never configured, or repeated."""
        if not self.configured or self._shut_down:
            return
        self._shut_down = True
        from opentelemetry import metrics, trace

        trace.get_tracer_provider().shutdown()
        metrics.get_meter_provider().shutdown()


#: The process's telemetry.
telemetry = Telemetry()
