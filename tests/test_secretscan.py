"""The secret-scan sidecar client, against a real HTTP server on a Unix socket.

The server is stdlib ``http.server`` on an AF_UNIX socket in a thread, so the
client's IO is real: nothing inside it is mocked. Each test sets the server's
next reply. All secrets are fake vectors.
"""

from __future__ import annotations

import json
import logging
import socketserver
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler

import pytest
from corpus_detect import Span

from scan_gate.config import Settings
from scan_gate.egress import envoy
from scan_gate.egress.policy import EgressPolicy, inspect
from scan_gate.egress.secretscan import (
    SecretScanError,
    SecretScanMalformed,
    SecretScanner,
    SecretScanStatus,
    SecretScanTimeout,
    SecretScanTooLarge,
    SecretScanUnavailable,
    _DeadlineSocket,
    secret_scanner,
    span_type,
)

FAKE_GHP = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
#: The client's deadline for a whole call in these tests.
TIMEOUT = 0.3
#: Generous slack over a deadline for a loaded CI host; a held or dripping
#: reply would take far longer than this without the deadline.
SLACK = 1.5


@dataclass
class Reply:
    """What the server answers next: a status and a raw body.

    ``hold`` waits, before answering, until the test releases the sidecar.
    ``drip`` writes the response one byte per that many seconds.
    """

    status: int = 200
    body: bytes = b'{"findings": []}'
    hold: bool = False
    drip: float = 0.0
    hang_up: bool = False


@dataclass
class Sidecar:
    """The test server's state: its socket, its next reply, and what it was sent."""

    path: str
    reply: Reply = field(default_factory=Reply)
    received: list[tuple[str, str, bytes]] = field(default_factory=list)
    release: threading.Event = field(default_factory=threading.Event)

    def findings(self, *found: tuple[int, int, str]) -> None:
        payload = {"findings": [{"start": s, "end": e, "rule_id": r} for s, e, r in found]}
        self.reply = Reply(body=json.dumps(payload).encode())


class _Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    block_on_close = False

    def handle_error(self, request: object, client_address: object) -> None:
        # A slow reply is written after the client gave up; that broken pipe is expected.
        pass


def _handler(sidecar: Sidecar) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers["Content-Length"]))
            sidecar.received.append((self.path, self.headers["Content-Type"], body))
            reply = sidecar.reply
            if reply.hold:
                sidecar.release.wait(30)
            if reply.hang_up:
                self.close_connection = True
                return
            if reply.drip:
                self._drip(reply)
                return
            self.send_response(reply.status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(reply.body)))
            self.end_headers()
            self.wfile.write(reply.body)

        def _drip(self, reply: Reply) -> None:
            self.close_connection = True
            response = (
                f"HTTP/1.1 {reply.status} OK\r\nContent-Type: application/json\r\n"
                f"Content-Length: {len(reply.body)}\r\n\r\n"
            ).encode() + reply.body
            for i in range(len(response)):
                if sidecar.release.wait(reply.drip):
                    return
                self.wfile.write(response[i : i + 1])
                self.wfile.flush()

        def log_message(self, format: str, *args: object) -> None:
            pass

    return Handler


@pytest.fixture(scope="module")
def server(tmp_path_factory) -> Iterator[Sidecar]:
    path = str(tmp_path_factory.mktemp("ss") / "sock")
    assert len(path) < 100, "AF_UNIX paths are limited to 108 bytes"
    sidecar = Sidecar(path)
    srv = _Server(path, _handler(sidecar))
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield sidecar
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def sidecar(server) -> Iterator[Sidecar]:
    server.reply = Reply()
    server.received.clear()
    server.release.clear()
    yield server
    server.release.set()


@pytest.fixture
def client(sidecar) -> SecretScanner:
    return SecretScanner(sidecar.path, timeout=TIMEOUT, max_bytes=1024)


# --------------------------------------------------------------------------- #
# the contract
# --------------------------------------------------------------------------- #
def test_posts_the_text_as_json_to_scan(client, sidecar):
    assert client.spans("nothing here") == []
    ((path, content_type, body),) = sidecar.received
    assert (path, content_type) == ("/scan", "application/json")
    assert json.loads(body) == {"text": "nothing here"}


def test_findings_become_mapped_validated_spans(client, sidecar):
    text = f"token {FAKE_GHP} and more"
    start = text.index(FAKE_GHP)
    sidecar.findings((start, start + len(FAKE_GHP), "github-pat"), (0, 5, "auth0-client-secret.1"))
    assert client.spans(text) == [
        Span(start, start + len(FAKE_GHP), "secret:betterleaks:github-pat", "secret"),
        Span(0, 5, "secret:betterleaks:auth0-client-secret_1", "secret"),
    ]


def test_non_ascii_text_is_sent_as_utf8_with_code_point_offsets(client, sidecar):
    text = "ærlig 😀 " + FAKE_GHP
    start = text.index(FAKE_GHP)
    sidecar.findings((start, len(text), "github-pat"))
    (span,) = client.spans(text)
    assert text[span.start : span.end] == FAKE_GHP
    (_, _, body) = sidecar.received[0]
    assert "😀".encode() in body


def test_a_lone_surrogate_is_sent_escaped(client, sidecar):
    client.spans("bad \ud800 text")
    (_, _, body) = sidecar.received[0]
    assert b"\\ud800" in body
    assert json.loads(body) == {"text": "bad \ud800 text"}


def test_rule_ids_map_to_corpus_detect_types():
    assert span_type("github-pat") == "secret:betterleaks:github-pat"
    assert span_type("auth0-client-secret.1") == "secret:betterleaks:auth0-client-secret_1"


# --------------------------------------------------------------------------- #
# every failure raises, carrying no text and no response body
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("status", [400, 413, 500, 504, 201, 302])
def test_any_status_but_200_raises(client, sidecar, status):
    sidecar.reply = Reply(status=status, body=b'{"error": "leaked ' + FAKE_GHP.encode() + b'"}')
    with pytest.raises(SecretScanStatus) as raised:
        client.spans("some text")
    assert raised.value.status == status
    assert str(raised.value) == f"secretscan answered {status}"


@pytest.mark.parametrize(
    "body",
    [
        b"not json " + FAKE_GHP.encode(),
        b"[]",
        b'"findings"',
        b"{}",
        b'{"findings": null}',
        b'{"findings": {"start": 0}}',
        b'{"findings": [{"start": 0, "end": 3}]}',
        b'{"findings": [{"start": 0, "end": 3, "rule_id": 7}]}',
        b'{"findings": [{"start": 0, "end": 3, "rule_id": "Has Spaces"}]}',
        b'{"findings": [{"start": 0, "end": 99, "rule_id": "github-pat"}]}',
        b'{"findings": [{"start": 3, "end": 3, "rule_id": "github-pat"}]}',
        b'{"findings": [{"start": "0", "end": 3, "rule_id": "github-pat"}]}',
        b'{"findings": [{"start": 0, "end": true, "rule_id": "github-pat"}]}',
        b'{"findings": [{"start": 0, "end": 3, "rule_id": "' + b"a" * 60 + b'"}]}',
        b"\xff\xfe",
    ],
)
def test_a_malformed_200_raises(client, sidecar, body):
    sidecar.reply = Reply(body=body)
    with pytest.raises(SecretScanMalformed) as raised:
        client.spans("some text")
    assert FAKE_GHP not in str(raised.value) and "some text" not in str(raised.value)
    assert raised.value.__cause__ is None and raised.value.__suppress_context__


def test_a_reply_held_past_the_deadline_raises(client, sidecar):
    sidecar.reply = Reply(hold=True)
    began = time.monotonic()
    with pytest.raises(SecretScanTimeout):
        client.spans("some text")
    elapsed = time.monotonic() - began
    # The server answers only once released, so only the deadline can end the call.
    assert TIMEOUT <= elapsed < TIMEOUT + SLACK


def test_a_dripping_reply_fails_at_the_overall_deadline(sidecar):
    # Each byte arrives well within the deadline, so a per-operation timeout
    # alone would never fire: the whole response would take 0.3 s per byte.
    deadline = 1.0
    sidecar.reply = Reply(body=b'{"findings": []}' + b" " * 64, drip=0.3)
    client = SecretScanner(sidecar.path, timeout=deadline, max_bytes=1024)
    began = time.monotonic()
    with pytest.raises(SecretScanTimeout, match="timed out"):
        client.spans("some text")
    elapsed = time.monotonic() - began
    assert deadline <= elapsed < deadline + SLACK


def test_no_socket_operation_starts_after_the_deadline():
    sock = _DeadlineSocket()
    sock.deadline = time.monotonic()
    with sock, pytest.raises(TimeoutError):
        sock.sendall(b"x")


def test_a_dropped_connection_raises(client, sidecar):
    sidecar.reply = Reply(hang_up=True)
    with pytest.raises(SecretScanUnavailable, match=r"\(RemoteDisconnected\)"):
        client.spans("some text")


def test_a_missing_socket_raises(tmp_path):
    client = SecretScanner(str(tmp_path / "absent"), timeout=TIMEOUT, max_bytes=1024)
    with pytest.raises(SecretScanUnavailable, match=r"\(FileNotFoundError\)"):
        client.spans("some text")


def test_a_path_that_is_not_a_socket_raises(tmp_path):
    (tmp_path / "file").write_text("")
    client = SecretScanner(str(tmp_path / "file"), timeout=TIMEOUT, max_bytes=1024)
    with pytest.raises(SecretScanError):
        client.spans("some text")


def test_errors_share_one_base():
    for error in (
        SecretScanUnavailable,
        SecretScanTimeout,
        SecretScanStatus,
        SecretScanMalformed,
        SecretScanTooLarge,
    ):
        assert issubclass(error, SecretScanError)


# --------------------------------------------------------------------------- #
# the size limit
# --------------------------------------------------------------------------- #
def test_a_request_over_the_limit_is_refused_without_a_call(sidecar):
    client = SecretScanner(sidecar.path, timeout=TIMEOUT, max_bytes=100)
    with pytest.raises(SecretScanTooLarge, match="too_large_to_scan"):
        client.spans("x" * 100)
    assert sidecar.received == []


def test_the_limit_counts_the_encoded_request_body(sidecar):
    text = "ø" * 20  # 40 bytes of UTF-8, 52 with the JSON around it
    assert SecretScanner(sidecar.path, timeout=TIMEOUT, max_bytes=52).spans(text) == []
    with pytest.raises(SecretScanTooLarge):
        SecretScanner(sidecar.path, timeout=TIMEOUT, max_bytes=51).spans(text)
    assert len(sidecar.received) == 1


# --------------------------------------------------------------------------- #
# end to end: the adapter refuses what the sidecar cannot scan
# --------------------------------------------------------------------------- #
def _chat(content: str) -> bytes:
    return json.dumps({"model": "m", "messages": [{"role": "user", "content": content}]}).encode()


@pytest.mark.parametrize(
    "reply",
    [Reply(status=500), Reply(status=504), Reply(body=b"nope"), Reply(hold=True)],
    ids=["500", "504", "malformed", "slow"],
)
def test_a_failing_sidecar_refuses_the_request(client, sidecar, reply):
    sidecar.reply = reply
    processor = envoy.EgressProcessor(client, policy=lambda: EgressPolicy(pass_unparseable=True))
    verdict = processor._decide(_chat("lunch at noon?"), None, complete=True)
    assert (verdict.action, verdict.status, verdict.detail) == ("refuse", 403, "scan_error")


def test_a_sidecar_finding_is_refused_by_default(client, sidecar):
    text = f"deploy with {FAKE_GHP}"
    sidecar.findings((text.index(FAKE_GHP), len(text), "github-pat"))
    verdict = inspect(_chat(text), policy=EgressPolicy(), scanner=client)
    assert (verdict.action, verdict.status) == ("refuse", 403)
    assert "secret:betterleaks:github-pat" in verdict.detail


# --------------------------------------------------------------------------- #
# settings and the startup mode line
# --------------------------------------------------------------------------- #
def test_settings_configure_the_client(monkeypatch, sidecar):
    monkeypatch.setenv("CORPUS_SCAN_GATE_SECRETSCAN_SOCKET", sidecar.path)
    monkeypatch.setenv("CORPUS_SCAN_GATE_SECRETSCAN_TIMEOUT", "0.5")
    monkeypatch.setenv("CORPUS_SCAN_GATE_SECRETSCAN_MAX_BYTES", "30")
    client = SecretScanner.from_settings(Settings())
    assert client.spans("short") == []
    with pytest.raises(SecretScanTooLarge):
        client.spans("long enough to pass thirty bytes")


def test_enabled_scanner_is_built_and_logged(caplog):
    with caplog.at_level(logging.INFO):
        scanner = secret_scanner(Settings())
    assert isinstance(scanner, SecretScanner)
    assert "secretscan: enabled, socket /run/secretscan/sock, timeout 5.0s" in caplog.text


def test_disabled_scanner_is_none_and_warned(monkeypatch, caplog):
    monkeypatch.setenv("CORPUS_SCAN_GATE_SECRETSCAN_ENABLED", "false")
    with caplog.at_level(logging.INFO):
        assert secret_scanner(Settings()) is None
    (record,) = caplog.records
    assert record.levelname == "WARNING" and "DISABLED" in record.getMessage()


def test_status_and_limit_are_logged_without_text(client, sidecar, caplog):
    sidecar.reply = Reply(status=500)
    small = SecretScanner(sidecar.path, timeout=TIMEOUT, max_bytes=10)
    with caplog.at_level(logging.DEBUG):
        with pytest.raises(SecretScanStatus):
            client.spans(f"secret {FAKE_GHP}")
        with pytest.raises(SecretScanTooLarge):
            small.spans(f"secret {FAKE_GHP}")
    assert "answered 500" in caplog.text and "over the 10-byte limit" in caplog.text
    assert FAKE_GHP not in caplog.text and "secret " not in caplog.text
