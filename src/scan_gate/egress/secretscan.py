"""Client for the Betterleaks secret-scan sidecar (``sidecar/secretscan``).

:class:`SecretScanner` has one method, :meth:`SecretScanner.spans`: it sends a
text to the sidecar's ``POST /scan`` over its Unix socket and returns the secrets
found as corpus-detect :class:`~corpus_detect.Span` values, ready to pass to
``redact(text, extra_spans=…)``.

The sidecar answers with code point offsets (Python ``str`` indices) and
Betterleaks' raw rule ids. A rule id becomes the span type
``secret:betterleaks:<id>`` with ``.`` replaced by ``_``, to fit corpus-detect's
type charset; every span is checked with :func:`corpus_detect.validate_spans`.

Anything short of a well-formed 200 raises :class:`SecretScanError`: the text
was not fully scanned, so it must not be treated as clean. A text whose request
would exceed the sidecar's body limit raises :class:`SecretScanTooLarge` before
any connection is made. No exception message carries the text or a response
body, only a status code or an exception type, so each is safe to log.
"""

from __future__ import annotations

import http.client
import json
import logging
import socket
import time
from typing import Any

from corpus_detect import Span, validate_spans

from ..config import Settings

log = logging.getLogger(__name__)

#: The span type prefix for every sidecar finding.
TYPE_PREFIX = "secret:betterleaks:"


class SecretScanError(Exception):
    """The sidecar did not return a complete scan; the text is not known to be clean."""


class SecretScanUnavailable(SecretScanError):
    """The sidecar could not be reached, or dropped the connection."""


class SecretScanTimeout(SecretScanError):
    """The sidecar did not answer in full within the client's deadline."""


class SecretScanStatus(SecretScanError):
    """The sidecar answered with a status other than 200."""

    def __init__(self, status: int) -> None:
        super().__init__(f"secretscan answered {status}")
        self.status = status


class SecretScanMalformed(SecretScanError):
    """The sidecar's 200 response was not a valid list of findings for the text."""


class SecretScanTooLarge(SecretScanError):
    """The text is over the sidecar's body limit, so it was not sent."""


class _DeadlineSocket(socket.socket):
    """A socket whose operations share one overall ``deadline`` (``time.monotonic``).

    A per-operation timeout restarts on every receive, so a peer dripping a
    byte at a time could hold the caller indefinitely. Each operation is instead
    given only the time left, and none starts once the deadline has passed.
    These are the operations ``http.client`` uses: connect, ``sendall`` and the
    ``recv_into`` behind its response reader.
    """

    deadline: float

    def _arm(self) -> None:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("deadline passed")
        self.settimeout(remaining)

    def connect(self, address: Any) -> None:
        self._arm()
        super().connect(address)

    def sendall(self, data: Any, flags: int = 0) -> None:
        self._arm()
        super().sendall(data, flags)

    def recv_into(self, buffer: Any, nbytes: int = 0, flags: int = 0) -> int:
        self._arm()
        return super().recv_into(buffer, nbytes, flags)


class _UnixHTTPConnection(http.client.HTTPConnection):
    """An HTTP/1.1 connection over a Unix domain socket, bounded by one deadline."""

    def __init__(self, path: str, deadline: float) -> None:
        super().__init__("localhost")
        self._path = path
        self._deadline = deadline

    def connect(self) -> None:
        sock = _DeadlineSocket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.deadline = self._deadline
        try:
            sock.connect(self._path)
        except BaseException:
            sock.close()
            raise
        self.sock = sock


def _encode(text: str) -> bytes:
    """The request body for ``text``, as small as JSON allows.

    Raw UTF-8 keeps a non-ASCII text near its own size. A lone surrogate (which
    a JSON body may carry as an escape) cannot be UTF-8 encoded, so such a text
    is sent with escapes instead; the sidecar decodes each escaped lone
    surrogate to one U+FFFD, keeping code point offsets aligned.
    """
    try:
        return json.dumps({"text": text}, ensure_ascii=False).encode()
    except UnicodeEncodeError:
        return json.dumps({"text": text}).encode()


def span_type(rule_id: str) -> str:
    """The corpus-detect span type for a Betterleaks rule id."""
    return TYPE_PREFIX + rule_id.replace(".", "_")


def _parse(payload: bytes, text_length: int) -> list[Span]:
    """Turn a 200 response body into validated spans, or raise :class:`SecretScanMalformed`."""
    try:
        findings: Any = json.loads(payload)["findings"]
        if not isinstance(findings, list):
            raise TypeError
        spans = [Span(f["start"], f["end"], span_type(f["rule_id"]), "secret") for f in findings]
        validate_spans(spans, text_length, name="findings")
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        # Chaining is suppressed: a JSON decode error holds the whole response.
        raise SecretScanMalformed(
            f"secretscan response is malformed ({type(exc).__name__})"
        ) from None
    return spans


class SecretScanner:
    """Finds secrets in a text through the secretscan sidecar."""

    def __init__(self, socket_path: str, *, timeout: float, max_bytes: int) -> None:
        """``timeout`` bounds a whole call (connect, send, and reading the full
        response), in seconds; ``max_bytes`` is the sidecar's request body limit
        (``SECRETSCAN_MAX_BYTES``)."""
        self._socket_path = socket_path
        self._timeout = timeout
        self._max_bytes = max_bytes

    @classmethod
    def from_settings(cls, config: Settings) -> SecretScanner:
        """A scanner configured by the ``CORPUS_SCAN_GATE_SECRETSCAN_*`` settings."""
        return cls(
            config.scan_gate_secretscan_socket,
            timeout=config.scan_gate_secretscan_timeout,
            max_bytes=config.scan_gate_secretscan_max_bytes,
        )

    def spans(self, text: str) -> list[Span]:
        """Return the secret spans in ``text``; raise :class:`SecretScanError` on any failure."""
        body = _encode(text)
        if len(body) > self._max_bytes:
            log.warning(
                "secretscan: %d-byte request over the %d-byte limit", len(body), self._max_bytes
            )
            raise SecretScanTooLarge("too_large_to_scan")
        conn = _UnixHTTPConnection(self._socket_path, time.monotonic() + self._timeout)
        try:
            conn.request("POST", "/scan", body=body, headers={"Content-Type": "application/json"})
            response = conn.getresponse()
            status, payload = response.status, response.read()
        except TimeoutError:
            raise SecretScanTimeout("secretscan timed out") from None
        except (OSError, http.client.HTTPException) as exc:
            raise SecretScanUnavailable(f"secretscan unavailable ({type(exc).__name__})") from None
        finally:
            conn.close()
        if status != 200:
            log.warning("secretscan: answered %d", status)
            raise SecretScanStatus(status)
        return _parse(payload, len(text))


def secret_scanner(config: Settings) -> SecretScanner | None:
    """The configured scanner, or ``None`` when the sidecar is disabled; logs the mode."""
    if not config.scan_gate_secretscan_enabled:
        log.warning(
            "secretscan: DISABLED (CORPUS_SCAN_GATE_SECRETSCAN_ENABLED=false); "
            "Betterleaks secrets are not detected, only corpus-detect's rules"
        )
        return None
    log.info(
        "secretscan: enabled, socket %s, timeout %ss, max %d bytes",
        config.scan_gate_secretscan_socket,
        config.scan_gate_secretscan_timeout,
        config.scan_gate_secretscan_max_bytes,
    )
    return SecretScanner.from_settings(config)
