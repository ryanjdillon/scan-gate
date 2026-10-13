"""Egress control for LLM request bodies.

:mod:`scan_gate.egress.policy` decides what may leave the network and is
gateway-neutral. Each protocol adapter (:mod:`scan_gate.egress.envoy`, the Envoy
``ext_proc`` service) maps the policy's verdict onto its wire format.
``scan-gate`` runs the adapter named by ``CORPUS_SCAN_GATE_ADAPTER``.
"""
