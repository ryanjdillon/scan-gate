"""scan-gate: a fail-closed egress redactor for LLM request bodies.

:mod:`scan_gate.egress.policy` decides what may leave the network;
:mod:`scan_gate.egress.envoy` speaks Envoy's ``ext_proc`` protocol to an AI
gateway; :mod:`scan_gate.adapters` picks the adapter and :mod:`scan_gate.cli`
runs it.
"""
