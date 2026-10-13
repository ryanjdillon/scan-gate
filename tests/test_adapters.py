"""Adapter selection for ``scan-gate``."""

from __future__ import annotations

import pytest

from scan_gate import adapters
from scan_gate.egress import envoy


def test_envoy_adapter_is_selectable():
    assert adapters.adapter("envoy-ext-proc") is envoy.serve


def test_configured_adapter_defaults_to_envoy():
    assert adapters.adapter() is envoy.serve


def test_unknown_adapter_names_the_known_ones():
    with pytest.raises(ValueError, match="envoy-ext-proc"):
        adapters.adapter("kong")
