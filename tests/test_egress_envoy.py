"""The Envoy ext_proc adapter: phases in, ProcessingResponses out.

The processor is driven directly (no server binds a port), with the policy
injected.
"""

from __future__ import annotations

import json
import logging
from unittest.mock import create_autospec

import grpc
import pytest

from scan_gate._ext_proc.envoy.config.core.v3 import base_pb2 as core
from scan_gate._ext_proc.envoy.service.ext_proc.v3 import external_processor_pb2 as ep
from scan_gate.config import Settings
from scan_gate.egress import envoy
from scan_gate.egress.policy import EgressPolicy, Verdict
from scan_gate.egress.secretscan import (
    SecretScanMalformed,
    SecretScanner,
    SecretScanStatus,
    SecretScanTimeout,
    SecretScanUnavailable,
)


@pytest.fixture
def policy():
    return EgressPolicy(batch_clients=frozenset({"eval"}), batch_max_bytes=100)


@pytest.fixture
def scanner():
    """The secret-scan sidecar client, finding nothing unless a test says otherwise."""
    mock = create_autospec(SecretScanner, instance=True)
    mock.spans.return_value = []
    return mock


@pytest.fixture
def processor(policy, scanner):
    return envoy.EgressProcessor(scanner, policy=lambda: policy)


@pytest.fixture
def context():
    return create_autospec(grpc.ServicerContext, instance=True)


def headers(**values: str) -> ep.ProcessingRequest:
    return ep.ProcessingRequest(
        request_headers=ep.HttpHeaders(
            headers=core.HeaderMap(
                headers=[
                    core.HeaderValue(key=k.replace("_", "-"), raw_value=v.encode())
                    for k, v in values.items()
                ]
            )
        )
    )


def body(content: str, *, final: bool = True) -> ep.ProcessingRequest:
    payload = {"model": "DeepSeek-V4-Flash", "messages": [{"role": "user", "content": content}]}
    return ep.ProcessingRequest(
        request_body=ep.HttpBody(body=json.dumps(payload).encode(), end_of_stream=final)
    )


def raw_body(data: bytes, *, final: bool) -> ep.ProcessingRequest:
    return ep.ProcessingRequest(request_body=ep.HttpBody(body=data, end_of_stream=final))


def test_redacted_body_replaces_and_drops_content_length(processor, context):
    (response,) = processor.Process(iter([body("key AKIAIOSFODNN7EXAMPLE")]), context)
    common = response.request_body.response
    assert common.status == ep.CommonResponse.CONTINUE_AND_REPLACE
    assert b"AKIAIOSFODNN7EXAMPLE" not in common.body_mutation.body
    # Redaction changes the length; Envoy must recompute content-length or it
    # rejects the mutated body with a 500.
    assert list(common.header_mutation.remove_headers) == ["content-length"]


def test_clean_body_continues_unchanged(processor, context):
    (response,) = processor.Process(iter([body("lunch at noon?")]), context)
    common = response.request_body.response
    assert common.status == ep.CommonResponse.CONTINUE
    assert not common.HasField("body_mutation") and not common.HasField("header_mutation")


def test_refusal_is_an_immediate_json_response(processor, context):
    secret = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----"
    (response,) = processor.Process(iter([body(secret)]), context)
    immediate = response.immediate_response
    assert immediate.status.code == 403
    assert json.loads(immediate.body)["error"]["type"] == "egress_policy"
    assert [h.header.key for h in immediate.headers.set_headers] == ["content-type"]


def test_client_id_from_the_headers_phase_reaches_the_policy(processor, context):
    responses = list(
        processor.Process(iter([headers(x_client_id="eval"), body("x" * 200)]), context)
    )
    assert responses[0].WhichOneof("response") == "request_headers"
    assert responses[1].immediate_response.status.code == 413


def test_other_client_is_not_capped(processor, context):
    responses = list(
        processor.Process(iter([headers(x_client_id="orchestrator"), body("x" * 200)]), context)
    )
    assert responses[1].request_body.response.status == ep.CommonResponse.CONTINUE


def test_client_id_reads_plain_value_too():
    request = ep.HttpHeaders(
        headers=core.HeaderMap(headers=[core.HeaderValue(key="X-Client-Id", value="pi")])
    )
    assert envoy.client_id(request) == "pi"
    assert envoy.client_id(ep.HttpHeaders()) is None


def test_other_phases_are_acknowledged(processor, context):
    phases = [
        ep.ProcessingRequest(response_headers=ep.HttpHeaders()),
        ep.ProcessingRequest(response_body=ep.HttpBody(body=b"")),
        ep.ProcessingRequest(request_trailers=ep.HttpTrailers()),
        ep.ProcessingRequest(response_trailers=ep.HttpTrailers()),
    ]
    responses = list(processor.Process(iter(phases), context))
    assert [r.WhichOneof("response") for r in responses] == [
        "response_headers",
        "response_body",
        "request_trailers",
        "response_trailers",
    ]


@pytest.fixture
def failing_inspect():
    return create_autospec(envoy.inspect, side_effect=ValueError)


@pytest.mark.parametrize("pass_unparseable", [False, True])
def test_inspection_error_is_always_refused(context, failing_inspect, pass_unparseable):
    processor = envoy.EgressProcessor(
        scanner,
        policy=lambda: EgressPolicy(pass_unparseable=pass_unparseable),
        inspect=failing_inspect,
    )
    (response,) = processor.Process(iter([body("hi")]), context)
    immediate = response.immediate_response
    assert immediate.status.code == 403
    assert json.loads(immediate.body) == {
        "error": {"type": "egress_policy", "message": "request could not be inspected"}
    }
    assert immediate.details == "egress policy: scan_error"


@pytest.mark.parametrize(
    "env",
    [
        {},
        {"CORPUS_SCAN_GATE_PASS_UNPARSEABLE": "true"},
        {"CORPUS_SCAN_GATE_FAIL_OPEN": "true"},
        {"CORPUS_SCAN_GATE_PASS_UNPARSEABLE": "true", "CORPUS_SCAN_GATE_FAIL_OPEN": "true"},
    ],
)
def test_no_setting_passes_an_inspection_error(monkeypatch, context, env):
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    loaded = Settings()
    detector = create_autospec(
        envoy.inspect, side_effect=RuntimeError("leaked AKIAIOSFODNN7EXAMPLE")
    )
    processor = envoy.EgressProcessor(
        scanner, policy=lambda: EgressPolicy.from_settings(loaded), inspect=detector
    )
    (response,) = processor.Process(iter([body("hi")]), context)
    immediate = response.immediate_response
    assert immediate.status.code == 403
    # Neither the exception's type nor its message reaches the response.
    for text in (immediate.body.decode(), immediate.details):
        assert "AKIA" not in text and "RuntimeError" not in text


def test_unparseable_body_follows_pass_unparseable(context, scanner):
    multipart = ep.ProcessingRequest(
        request_body=ep.HttpBody(
            body=b"--boundary\r\nContent-Type: audio/wav\r\n\r\nRIFF", end_of_stream=True
        )
    )
    closed = envoy.EgressProcessor(scanner, policy=lambda: EgressPolicy(pass_unparseable=False))
    (refused,) = closed.Process(iter([multipart]), context)
    assert refused.immediate_response.status.code == 403
    opened = envoy.EgressProcessor(scanner, policy=lambda: EgressPolicy(pass_unparseable=True))
    (passed,) = opened.Process(iter([multipart]), context)
    assert passed.request_body.response.status == ep.CommonResponse.CONTINUE


def test_pass_verdict_maps_to_continue():
    assert envoy.to_response(Verdict("pass")).request_body.response.status == (
        ep.CommonResponse.CONTINUE
    )


def test_server_options_size_both_directions():
    assert dict(envoy.server_options(1234)) == {
        "grpc.max_receive_message_length": 1234,
        "grpc.max_send_message_length": 1234,
    }


def test_unavailable_policy_is_refused(context, scanner):
    def broken_policy():
        raise RuntimeError("bad config")

    processor = envoy.EgressProcessor(scanner, policy=broken_policy)
    (response,) = processor.Process(iter([body("hi")]), context)
    assert response.immediate_response.status.code == 403
    assert "bad config" not in response.immediate_response.details


def test_deeply_nested_body_is_refused_as_a_scan_error(processor, context):
    # The real parser overflows the recursion limit on this; nothing is mocked.
    (response,) = processor.Process(iter([raw_body(b"[" * 200_000, final=True)]), context)
    immediate = response.immediate_response
    assert immediate.status.code == 403
    assert json.loads(immediate.body)["error"]["type"] == "egress_policy"
    assert immediate.details == "egress policy: scan_error"


def test_inspection_error_logs_only_its_type(context, caplog, scanner):
    secret = "AKIAIOSFODNN7EXAMPLE"
    detector = create_autospec(envoy.inspect, side_effect=KeyError(f"leaked {secret}"))
    processor = envoy.EgressProcessor(scanner, policy=EgressPolicy, inspect=detector)
    with caplog.at_level(logging.DEBUG):
        processor.Process(iter([body(f"mail {secret} please")]), context).__next__()
    logged = "\n".join(r.getMessage() for r in caplog.records)
    assert "KeyError" in logged
    for leak in (secret, "leaked", "mail", "please"):
        assert leak not in logged
    assert all(r.exc_info is None for r in caplog.records)


def test_unknown_action_is_refused(caplog):
    with caplog.at_level(logging.ERROR):
        response = envoy.to_response(Verdict("quarantine"))
    immediate = response.immediate_response
    assert immediate.status.code == 403
    assert json.loads(immediate.body)["error"]["type"] == "egress_policy"
    assert immediate.details == "egress policy: internal"
    assert "quarantine" in caplog.text


def unbuffered(response: ep.ProcessingResponse) -> bool:
    immediate = response.immediate_response
    return (
        immediate.status.code == 403
        and json.loads(immediate.body)["error"]["type"] == "egress_policy"
        and immediate.details == "egress policy: unbuffered"
    )


@pytest.mark.parametrize("pass_unparseable", [False, True])
def test_non_final_unparseable_chunk_is_refused_unbuffered(context, pass_unparseable):
    processor = envoy.EgressProcessor(
        scanner, policy=lambda: EgressPolicy(pass_unparseable=pass_unparseable)
    )
    partial = raw_body(b'{"model": "DeepSeek-V4-Flash", "messa', final=False)
    (response,) = processor.Process(iter([partial]), context)
    assert unbuffered(response)


def test_non_final_json_body_is_scanned_as_a_whole_body(processor, context):
    # Buffered mode with request trailers: one body message, end_of_stream false.
    trailers = ep.ProcessingRequest(request_trailers=ep.HttpTrailers())
    phases = [body("mail jane@example.com", final=False), trailers]
    redacted, acknowledged = processor.Process(iter(phases), context)
    common = redacted.request_body.response
    assert common.status == ep.CommonResponse.CONTINUE_AND_REPLACE
    assert b"jane@example.com" not in common.body_mutation.body
    assert acknowledged.WhichOneof("response") == "request_trailers"


@pytest.mark.parametrize(
    ("pass_unparseable", "detail"), [(True, None), (False, "egress policy: unredactable")]
)
def test_final_unparseable_chunk_follows_pass_unparseable(context, pass_unparseable, detail):
    processor = envoy.EgressProcessor(
        scanner, policy=lambda: EgressPolicy(pass_unparseable=pass_unparseable)
    )
    (response,) = processor.Process(iter([raw_body(b"RIFF....WAVE", final=True)]), context)
    if detail is None:
        assert response.request_body.response.status == ep.CommonResponse.CONTINUE
    else:
        assert response.immediate_response.details == detail


def test_final_chunk_after_an_earlier_chunk_is_not_a_whole_body(context, scanner):
    # A streamed body whose first chunk parses on its own: the remainder is a
    # fragment, so pass_unparseable must not wave it through.
    processor = envoy.EgressProcessor(scanner, policy=lambda: EgressPolicy(pass_unparseable=True))
    phases = [body("hi", final=False), raw_body(b' "secret tail"}', final=True)]
    first, rest = processor.Process(iter(phases), context)
    assert first.request_body.response.status == ep.CommonResponse.CONTINUE
    assert unbuffered(rest)


@pytest.mark.parametrize(
    "error",
    [
        SecretScanUnavailable("secretscan unavailable (ConnectionRefusedError)"),
        SecretScanTimeout("secretscan timed out"),
        SecretScanStatus(400),
        SecretScanStatus(413),
        SecretScanStatus(500),
        SecretScanStatus(504),
        SecretScanMalformed("secretscan response is malformed (JSONDecodeError)"),
    ],
    ids=lambda e: type(e).__name__ + str(getattr(e, "status", "")),
)
@pytest.mark.parametrize("pass_unparseable", [False, True])
def test_every_sidecar_failure_is_refused_as_a_scan_error(
    context, scanner, error, pass_unparseable, caplog
):
    scanner.spans.side_effect = error
    processor = envoy.EgressProcessor(
        scanner, policy=lambda: EgressPolicy(pass_unparseable=pass_unparseable)
    )
    with caplog.at_level(logging.DEBUG):
        (response,) = processor.Process(iter([body("call me on lunch")]), context)
    immediate = response.immediate_response
    assert immediate.status.code == 403
    assert immediate.details == "egress policy: scan_error"
    assert type(error).__name__ in caplog.text
    assert "lunch" not in caplog.text


def test_the_processor_hands_its_scanner_to_the_policy(context, scanner):
    detector = create_autospec(envoy.inspect, return_value=Verdict("pass"))
    processor = envoy.EgressProcessor(scanner, policy=EgressPolicy, inspect=detector)
    list(processor.Process(iter([body("hi")]), context))
    assert detector.call_args.kwargs["scanner"] is scanner
