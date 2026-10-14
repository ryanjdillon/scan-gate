"""The egress policy: what may leave the network in an LLM request body.

Gateway-neutral. :func:`inspect` takes a request body (and the calling client's
id, when the gateway forwards one) and returns a :class:`Verdict`: pass it
unchanged, replace it with a redacted body, or refuse it with a status code. The
protocol adapters in this package translate a verdict onto their wire format;
nothing here knows about Envoy, gRPC, or HTTP framing.

The policy, in order:

1. A body that is not a JSON object cannot be inspected. ``pass_unparseable``
   passes it through (multipart audio uploads take this path); otherwise it is
   refused. A body the gateway marks as not ``complete`` (a chunk of a larger
   body) is always refused instead: a fragment of JSON is unparseable, so
   passing it would send a streamed request out unscanned.
2. A request for a model in ``skip_models`` passes unscanned: it is served
   locally and never leaves the network. The list is exact names, so a typo can
   only make the gate scan more.
3. A batch client (``batch_clients``) may not send a body over
   ``batch_max_bytes`` to a scanned model. Batch jobs must cap their input before
   sending; this refuses an uncapped one (413) before it reaches a provider.
4. Every message's text is redacted, by corpus-detect together with the spans
   the Betterleaks sidecar finds (one sidecar call per body). A finding whose
   type is in ``block_types`` (an entry ending in ``*`` matches a prefix)
   refuses the request (403) instead. A body whose text is over the sidecar's
   size limit is refused (413, ``too_large_to_scan``) without being sent.

An exception raised while inspecting is not a step of the policy: the adapter
always refuses it, whatever ``pass_unparseable`` says. Any sidecar failure is
such an exception, so a body the sidecar did not fully scan never passes.

Only detection *types and counts* are logged, never a matched value or a body.
"""

from __future__ import annotations

import json
import logging
from bisect import bisect_right
from dataclasses import dataclass, field
from typing import Any

from corpus_detect import Span, redact

from ..config import Settings, get_settings
from .secretscan import TYPE_PREFIX, SecretScanner, SecretScanTooLarge

log = logging.getLogger(__name__)


def _names(csv: str) -> frozenset[str]:
    return frozenset(t.strip() for t in csv.split(",") if t.strip())


@dataclass(frozen=True)
class EgressPolicy:
    """The tunable parts of the policy; see the module docstring for the order."""

    pass_unparseable: bool = False
    block_types: frozenset[str] = frozenset({"private_key", "secret:betterleaks:*"})
    skip_models: frozenset[str] = field(default_factory=frozenset)
    batch_clients: frozenset[str] = field(default_factory=frozenset)
    batch_max_bytes: int = 65536

    @classmethod
    def from_settings(cls, config: Settings | None = None) -> EgressPolicy:
        """Build the policy from ``CORPUS_SCAN_GATE_*`` settings (default: the loaded ones)."""
        config = config or get_settings()
        return cls(
            pass_unparseable=config.pass_unparseable,
            block_types=_names(config.scan_gate_block_types),
            skip_models=_names(config.scan_gate_skip_models),
            batch_clients=_names(config.scan_gate_batch_clients),
            batch_max_bytes=config.scan_gate_batch_max_bytes,
        )

    def blocks(self, entity_type: str) -> bool:
        """Whether a finding of ``entity_type`` refuses the request.

        A ``block_types`` entry matches a type exactly, or, ending in ``*``,
        every type starting with what comes before it.
        """
        return any(
            entity_type.startswith(entry[:-1]) if entry.endswith("*") else entity_type == entry
            for entry in self.block_types
        )

    def blocks_every(self, prefix: str) -> bool:
        """Whether every type starting with ``prefix`` is blocked: some entry
        ending in ``*`` matches a prefix of it."""
        return any(
            entry.endswith("*") and prefix.startswith(entry[:-1]) for entry in self.block_types
        )


def warn_if_secrets_unblocked(config: Settings) -> None:
    """Log once at startup when the sidecar is on but its findings are not blocked.

    ``block_types`` replaces its default when set, so a deployment can drop
    ``secret:betterleaks:*`` without meaning to; its secrets are then redacted
    and the request still leaves.
    """
    if config.scan_gate_secretscan_enabled and not EgressPolicy.from_settings(
        config
    ).blocks_every(TYPE_PREFIX):
        log.warning(
            "egress: CORPUS_SCAN_GATE_BLOCK_TYPES does not cover %s*; Betterleaks findings "
            "will be redacted, not blocked",
            TYPE_PREFIX,
        )


@dataclass(frozen=True)
class Verdict:
    """The outcome for one request body.

    ``action`` is ``"pass"`` (forward unchanged), ``"replace"`` (forward ``body``
    instead), or ``"refuse"`` (answer ``status`` with ``body`` and stop).
    ``detail`` is a value-free summary for logs and proxy access logs.
    """

    action: str
    status: int = 200
    body: bytes = b""
    detail: str = ""


PASS = Verdict("pass")


def refusal(status: int, error_type: str, message: str, detail: str) -> Verdict:
    """A refusing verdict with an OpenAI-style JSON error body."""
    body = json.dumps({"error": {"type": error_type, "message": message}}).encode()
    return Verdict("refuse", status=status, body=body, detail=detail)


#: Joins a request's texts into the one text sent to the secret scanner. A
#: newline ends a token for every Betterleaks rule, so a secret inside one field
#: is matched as it would be alone.
SEPARATOR = "\n\n"

#: Where a text sits in the parsed body: its container and its key or index.
_Slot = tuple[Any, Any]


def _field_slots(container: dict[str, Any], key: str, slots: list[_Slot]) -> None:
    """Collect ``container[key]``'s text: a string, a list of strings, or parts."""
    value = container.get(key)
    if isinstance(value, str):
        slots.append((container, key))
    elif isinstance(value, list):
        for i, item in enumerate(value):
            if isinstance(item, str):
                slots.append((value, i))
            elif isinstance(item, dict):
                _part_slots(item, slots)


def _value_slots(obj: dict[str, Any] | list[Any], slots: list[_Slot]) -> None:
    """Collect every string inside *obj*, walking dicts and lists."""
    items = obj.items() if isinstance(obj, dict) else enumerate(obj)
    for key, value in items:
        if isinstance(value, str):
            slots.append((obj, key))
        elif isinstance(value, (dict, list)):
            _value_slots(value, slots)


def _part_slots(part: dict[str, Any], slots: list[_Slot]) -> None:
    """Collect one structured content part's text: its ``text``, nested ``content``
    (an Anthropic ``tool_result`` carries its own string or part list), and a
    ``tool_use`` part's ``input`` arguments."""
    _field_slots(part, "text", slots)
    _field_slots(part, "content", slots)
    if isinstance(part.get("input"), dict):
        _value_slots(part["input"], slots)


def _text_slots(data: dict[str, Any]) -> list[_Slot]:
    """Every text field of a model request body; see :func:`redact_payload`."""
    slots: list[_Slot] = []
    for key in ("system", "input", "prompt"):
        _field_slots(data, key, slots)
    messages = data.get("messages")
    if isinstance(messages, list):
        for message in messages:
            if not isinstance(message, dict):
                continue
            _field_slots(message, "content", slots)
            calls = message.get("tool_calls")
            for call in calls if isinstance(calls, list) else []:
                function = call.get("function") if isinstance(call, dict) else None
                if isinstance(function, dict):
                    _field_slots(function, "arguments", slots)
    return slots


def scan_texts(scanner: SecretScanner | None, texts: list[str]) -> list[list[Span]]:
    """The scanner's secret spans for each of ``texts``, from one scanner call.

    The texts are joined with :data:`SEPARATOR` and scanned once, and each span
    is mapped back to offsets in the texts it covers. A span reaching across a
    separator is clipped to each text it touches (masking a little more, never
    less), and a part of it lying only on the separator is dropped. No call is
    made without a scanner or without any text.
    """
    per_text: list[list[Span]] = [[] for _ in texts]
    if scanner is None or not any(texts):
        return per_text
    starts: list[int] = []
    offset = 0
    for text in texts:
        starts.append(offset)
        offset += len(text) + len(SEPARATOR)
    for span in scanner.spans(SEPARATOR.join(texts)):
        i = bisect_right(starts, span.start) - 1
        while i < len(texts) and starts[i] < span.end:
            lo = max(span.start, starts[i]) - starts[i]
            hi = min(span.end, starts[i] + len(texts[i])) - starts[i]
            if lo < hi:
                per_text[i].append(Span(lo, hi, span.entity_type, span.category))
            i += 1
    return per_text


def redact_payload(data: dict[str, Any], scanner: SecretScanner | None) -> dict[str, int]:
    """Redact every text field of a model request body in place.

    Covers the OpenAI and Anthropic shapes that carry user text:

    - chat: each message's ``content`` (a string or content parts, including an
      Anthropic ``tool_result`` part's nested ``content``) and each assistant
      ``tool_calls[].function.arguments``;
    - Anthropic's top-level ``system`` (a string or parts);
    - embeddings ``input`` and legacy completions ``prompt`` (a string or a list
      of strings; token-id arrays carry no text).

    Each text is redacted by corpus-detect together with the ``scanner``'s
    spans for it (one scanner call for the whole body; see :func:`scan_texts`).
    Image and audio parts are left untouched. Returns a value-free
    ``{type: count}`` tally of ``RedactResult.counts`` (each matched span
    counted once), plus every sidecar span type those counts leave out.
    """
    slots = _text_slots(data)
    texts = [container[key] for container, key in slots]
    counts: dict[str, int] = {}
    for (container, key), text, extra in zip(slots, texts, scan_texts(scanner, texts), strict=True):
        result = redact(text, extra_spans=extra)
        container[key] = result.text
        for entity_type, n in result.counts.items():
            counts[entity_type] = counts.get(entity_type, 0) + n
        # A sidecar span wholly covered by a detected one (the same token found
        # by both) is masked under the other's type, so ``redact`` does not count
        # it. Count it anyway: a block on the sidecar's types must not be
        # sidestepped by a coincident corpus-detect match.
        for span in extra:
            if span.entity_type not in result.counts:
                counts[span.entity_type] = counts.get(span.entity_type, 0) + 1
    return counts


def _unparseable(policy: EgressPolicy, reason: str, *, complete: bool) -> Verdict:
    if not complete:
        log.warning("egress: refusing an uninspectable partial body (%s)", reason)
        return refusal(403, "egress_policy", "request body was not buffered", "unbuffered")
    if policy.pass_unparseable:
        # Routine for multipart audio uploads, so not a warning.
        log.info("egress: passing an uninspectable body through (%s)", reason)
        return PASS
    log.warning("egress: refusing an uninspectable body (%s)", reason)
    return refusal(403, "egress_policy", "request body could not be inspected", "unredactable")


def inspect(
    body: bytes,
    client_id: str | None = None,
    *,
    policy: EgressPolicy,
    scanner: SecretScanner | None,
    complete: bool = True,
) -> Verdict:
    """Decide what may leave for one request body; see the module docstring.

    ``scanner`` is the secret-scan sidecar client, or ``None`` when it is
    disabled; any error it raises propagates, for the adapter to refuse.
    ``complete`` is false when ``body`` may be only part of the request body. A
    parseable part is still scanned as a whole body; only the unparseable path
    differs, refusing it whatever ``pass_unparseable`` says.
    """
    if not body:
        return PASS
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return _unparseable(policy, str(exc), complete=complete)
    if not isinstance(data, dict):
        return _unparseable(policy, "request body is not a JSON object", complete=complete)

    model = data.get("model")
    if isinstance(model, str) and model in policy.skip_models:
        return PASS

    if client_id in policy.batch_clients and len(body) > policy.batch_max_bytes:
        log.warning("egress: refusing %d-byte body from batch client %s", len(body), client_id)
        return refusal(
            413,
            "request_too_large",
            f"request body exceeds the batch-client limit of {policy.batch_max_bytes} bytes; "
            "cap the input before sending",
            f"batch body {len(body)} bytes",
        )

    try:
        counts = redact_payload(data, scanner)
    except SecretScanTooLarge:
        log.warning("egress: refusing a body whose text is too large to scan")
        return refusal(
            413,
            "request_too_large",
            "request text is too large to scan for secrets",
            "too_large_to_scan",
        )
    blocked = {t for t in counts if policy.blocks(t)}
    if blocked:
        log.warning("egress: refusing request body; types=%s", sorted(blocked))
        return refusal(
            403,
            "egress_policy",
            "request blocked by egress data policy",
            "blocked " + json.dumps(counts, sort_keys=True),
        )
    if not counts:
        return PASS
    log.info("egress: redacted request body; findings=%s", counts)
    return Verdict("replace", body=json.dumps(data).encode(), detail=json.dumps(counts))
