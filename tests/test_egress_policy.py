"""The gateway-neutral egress policy: verdicts for request bodies.

The policy is a value passed to ``inspect``, so each test states the rules it
relies on. The secret-scan sidecar client is a spec'd mock (its real IO is
tested in ``test_secretscan.py``). All secrets are fake vectors.
"""

from __future__ import annotations

import json
import logging
from unittest.mock import create_autospec

import pytest
from corpus_detect import Span

from scan_gate.config import Settings
from scan_gate.egress.policy import (
    SEPARATOR,
    EgressPolicy,
    inspect,
    redact_payload,
    scan_texts,
    warn_if_secrets_unblocked,
)
from scan_gate.egress.secretscan import (
    SecretScanError,
    SecretScanMalformed,
    SecretScanner,
    SecretScanStatus,
    SecretScanTimeout,
    SecretScanTooLarge,
    SecretScanUnavailable,
)

FAKE_PRIVATE_KEY = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB\n"
    "-----END OPENSSH PRIVATE KEY-----"
)


# A fake GitHub PAT: the right shape, never issued.
FAKE_GHP = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
GHP_TYPE = "secret:betterleaks:github-pat"
# A token only the (mocked) sidecar knows; corpus-detect finds nothing in it.
SIDECAR_ONLY = "zq" + "Xy7Wv3Ut9Sr1" * 3
SIDECAR_TYPE = "secret:betterleaks:generic-api-key"


@pytest.fixture
def scanner():
    """The sidecar client, finding nothing unless a test says otherwise."""
    mock = create_autospec(SecretScanner, instance=True)
    mock.spans.return_value = []
    return mock


def finds(scanner, needle: str, entity_type: str = GHP_TYPE) -> None:
    """Make ``scanner`` report every occurrence of ``needle`` in the text it is sent."""

    def spans(text: str) -> list[Span]:
        found, at = [], text.find(needle)
        while at >= 0:
            found.append(Span(at, at + len(needle), entity_type, "secret"))
            at = text.find(needle, at + 1)
        return found

    scanner.spans.side_effect = spans


@pytest.fixture
def policy():
    return EgressPolicy(
        skip_models=frozenset({"qwen3-coder"}),
        batch_clients=frozenset({"corpus-enrich"}),
        batch_max_bytes=200,
    )


def chat(content: str, model: str = "DeepSeek-V4-Flash") -> bytes:
    return json.dumps({"model": model, "messages": [{"role": "user", "content": content}]}).encode()


# --------------------------------------------------------------------------- #
# payload walking
# --------------------------------------------------------------------------- #
def test_redact_payload_openai_string_content(scanner):
    data = {"messages": [{"role": "user", "content": "key AKIAIOSFODNN7EXAMPLE"}]}
    counts = redact_payload(data, scanner)
    assert "AKIAIOSFODNN7EXAMPLE" not in data["messages"][0]["content"]
    assert counts == {"aws_access_key": 1}


def test_redact_payload_content_parts_and_anthropic_system(scanner):
    data = {
        "system": "contact alice@example.org",
        "messages": [
            {"role": "user", "content": [{"type": "text", "text": "card 4111 1111 1111 1111 now"}]}
        ],
    }
    counts = redact_payload(data, scanner)
    assert "alice@example.org" not in data["system"]
    assert "4111" not in data["messages"][0]["content"][0]["text"]
    assert counts == {"email": 1, "credit_card": 1}


def test_redact_payload_anthropic_system_parts(scanner):
    data = {"system": [{"type": "text", "text": "mail bob@example.net"}], "messages": []}
    redact_payload(data, scanner)
    assert "bob@example.net" not in data["system"][0]["text"]


def test_redact_payload_ignores_non_dict_messages(scanner):
    data = {"messages": ["not a dict", {"role": "user", "content": "key AKIAIOSFODNN7EXAMPLE"}]}
    assert redact_payload(data, scanner) == {"aws_access_key": 1}


# --------------------------------------------------------------------------- #
# verdicts
# --------------------------------------------------------------------------- #
def test_clean_body_passes(policy, scanner):
    assert inspect(chat("lunch at noon?"), policy=policy, scanner=scanner).action == "pass"


def test_dirty_body_is_replaced_with_a_redacted_one(policy, scanner):
    verdict = inspect(chat("key AKIAIOSFODNN7EXAMPLE"), policy=policy, scanner=scanner)
    assert verdict.action == "replace"
    assert "AKIAIOSFODNN7EXAMPLE" not in json.loads(verdict.body)["messages"][0]["content"]


def test_private_key_is_refused_403_without_echoing_it(policy, scanner):
    verdict = inspect(chat(FAKE_PRIVATE_KEY), policy=policy, scanner=scanner)
    assert (verdict.action, verdict.status) == ("refuse", 403)
    assert "private_key" in verdict.detail
    assert b"PRIVATE KEY" not in verdict.body and "PRIVATE KEY" not in verdict.detail


def test_without_block_types_a_private_key_is_redacted_instead(scanner):
    verdict = inspect(
        chat(FAKE_PRIVATE_KEY), policy=EgressPolicy(block_types=frozenset()), scanner=scanner
    )
    assert verdict.action == "replace"
    assert b"PRIVATE KEY" not in verdict.body


@pytest.mark.parametrize("body", [b"not json at all", b"[1, 2, 3]"])
def test_uninspectable_body_is_refused_by_default(body, scanner):
    verdict = inspect(body, policy=EgressPolicy(), scanner=scanner)
    assert (verdict.action, verdict.status, verdict.detail) == ("refuse", 403, "unredactable")


@pytest.mark.parametrize("body", [b"--boundary\r\n...", b"\xff\xfe\x00audio", b"[1, 2, 3]"])
def test_uninspectable_body_passes_when_pass_unparseable(body, scanner):
    # Multipart audio uploads take this path.
    assert (
        inspect(body, policy=EgressPolicy(pass_unparseable=True), scanner=scanner).action == "pass"
    )


@pytest.mark.parametrize("pass_unparseable", [False, True])
def test_incomplete_uninspectable_body_is_refused_unbuffered(pass_unparseable, scanner):
    policy = EgressPolicy(pass_unparseable=pass_unparseable)
    verdict = inspect(b'{"model": "m", "mess', policy=policy, complete=False, scanner=scanner)
    assert (verdict.action, verdict.status, verdict.detail) == ("refuse", 403, "unbuffered")


def test_incomplete_json_body_is_scanned_as_usual(scanner):
    verdict = inspect(
        chat("mail jane@example.com"), policy=EgressPolicy(), complete=False, scanner=scanner
    )
    assert verdict.action == "replace" and b"jane@example.com" not in verdict.body


def test_pass_unparseable_does_not_skip_scanning_json(scanner):
    verdict = inspect(
        chat(FAKE_PRIVATE_KEY), policy=EgressPolicy(pass_unparseable=True), scanner=scanner
    )
    assert (verdict.action, verdict.status) == ("refuse", 403)


@pytest.mark.parametrize(
    ("env", "expected"),
    [
        ({}, False),
        ({"CORPUS_SCAN_GATE_PASS_UNPARSEABLE": "true"}, True),
        ({"CORPUS_SCAN_GATE_FAIL_OPEN": "true"}, True),
        ({"CORPUS_SCAN_GATE_FAIL_OPEN": "false"}, False),
    ],
)
def test_policy_reads_pass_unparseable_or_its_alias(monkeypatch, env, expected):
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    assert EgressPolicy.from_settings(Settings()).pass_unparseable is expected


def test_empty_body_passes(policy, scanner):
    assert inspect(b"", policy=policy, scanner=scanner).action == "pass"


def test_image_parts_pass_through_byte_identical(policy, scanner):
    # Only text is redacted: an inline image must come back unchanged, or the
    # provider receives a corrupt image.
    image = "data:image/jpeg;base64," + "QUtJQUlPU0ZPRE5ON0VYQU1QTEU+/9j/4AAQ" * 2000
    body = json.dumps(
        {
            "model": "DeepSeek-V4-Flash",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "who is alice@example.org?"},
                        {"type": "image_url", "image_url": {"url": image}},
                    ],
                }
            ],
        }
    ).encode()
    parts = json.loads(inspect(body, policy=policy, scanner=scanner).body)["messages"][0]["content"]
    assert "alice@example.org" not in parts[0]["text"]
    assert parts[1] == {"type": "image_url", "image_url": {"url": image}}


# --------------------------------------------------------------------------- #
# local models and batch clients
# --------------------------------------------------------------------------- #
def test_skipped_local_model_passes_unscanned(policy, scanner):
    # Served locally, so even a private key never leaves the network.
    assert (
        inspect(chat(FAKE_PRIVATE_KEY, model="qwen3-coder"), policy=policy, scanner=scanner).action
        == "pass"
    )


def test_model_not_in_the_skip_list_is_scanned(policy, scanner):
    verdict = inspect(
        chat(FAKE_PRIVATE_KEY, model="DeepSeek-V4-Flash"), policy=policy, scanner=scanner
    )
    assert verdict.action == "refuse"


def test_skip_list_matches_exact_names_only(policy, scanner):
    # A near-miss name is scanned: a typo can only make the gate scan more.
    verdict = inspect(
        chat(FAKE_PRIVATE_KEY, model="qwen3-coder-cloud"), policy=policy, scanner=scanner
    )
    assert verdict.action == "refuse"


def test_batch_client_over_the_limit_on_a_scanned_model_gets_413(policy, scanner):
    verdict = inspect(chat("x" * 500), "corpus-enrich", policy=policy, scanner=scanner)
    assert (verdict.action, verdict.status) == ("refuse", 413)
    assert json.loads(verdict.body)["error"]["type"] == "request_too_large"


def test_batch_client_over_the_limit_on_a_local_model_passes(policy, scanner):
    assert (
        inspect(
            chat("x" * 500, model="qwen3-coder"), "corpus-enrich", policy=policy, scanner=scanner
        ).action
        == "pass"
    )


def test_other_client_over_the_limit_passes(policy, scanner):
    assert inspect(chat("x" * 500), "orchestrator", policy=policy, scanner=scanner).action == "pass"


def test_batch_client_under_the_limit_is_scanned_normally(policy, scanner):
    assert inspect(chat("hi"), "corpus-enrich", policy=policy, scanner=scanner).action == "pass"


def test_policy_reads_comma_separated_settings(monkeypatch):
    # Settings come from the environment; a fresh Settings() reads it.
    from scan_gate.config import Settings

    monkeypatch.setenv("CORPUS_SCAN_GATE_SKIP_MODELS", " qwen3-coder , local-embed ,")
    monkeypatch.setenv("CORPUS_SCAN_GATE_BATCH_CLIENTS", "corpus-enrich")
    loaded = EgressPolicy.from_settings(Settings())
    assert loaded.skip_models == frozenset({"qwen3-coder", "local-embed"})
    assert loaded.batch_clients == frozenset({"corpus-enrich"})


def test_non_string_model_is_scanned(policy, scanner):
    body = {"model": ["qwen3-coder"], "messages": [{"role": "user", "content": FAKE_PRIVATE_KEY}]}
    assert inspect(json.dumps(body).encode(), policy=policy, scanner=scanner).action == "refuse"


def test_body_without_a_model_is_scanned(policy, scanner):
    body = {"messages": [{"role": "user", "content": FAKE_PRIVATE_KEY}]}
    assert inspect(json.dumps(body).encode(), policy=policy, scanner=scanner).action == "refuse"


@pytest.mark.parametrize(
    "body",
    [
        {"model": "text-embedding-3", "input": FAKE_PRIVATE_KEY},
        {"model": "text-embedding-3", "input": ["fine", FAKE_PRIVATE_KEY]},
        {"model": "gpt-3.5-turbo-instruct", "prompt": FAKE_PRIVATE_KEY},
        {
            "model": "DeepSeek-V4-Flash",
            "messages": [
                {
                    "role": "assistant",
                    "tool_calls": [{"function": {"name": "f", "arguments": FAKE_PRIVATE_KEY}}],
                }
            ],
        },
        {
            "model": "claude-x",
            "messages": [
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "name": "f",
                            "input": {"q": [FAKE_PRIVATE_KEY], "n": 3},
                        },
                    ],
                }
            ],
        },
        {
            "model": "claude-x",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "content": [{"type": "text", "text": FAKE_PRIVATE_KEY}],
                        }
                    ],
                }
            ],
        },
    ],
    ids=[
        "embeddings",
        "embeddings-list",
        "completions",
        "tool-call-args",
        "nested-tool-result",
        "anthropic-tool-use-input",
    ],
)
def test_every_text_container_is_scanned(policy, body, scanner):
    assert inspect(json.dumps(body).encode(), policy=policy, scanner=scanner).action == "refuse"


def test_token_id_input_carries_no_text(policy, scanner):
    body = {"model": "text-embedding-3", "input": [[1, 2, 3]]}
    assert inspect(json.dumps(body).encode(), policy=policy, scanner=scanner).action == "pass"


def test_invalid_utf8_body_is_uninspectable(policy, scanner):
    assert inspect(b"\xff\xfe not utf8", policy=policy, scanner=scanner).action == "refuse"


def test_non_list_tool_calls_are_ignored(policy, scanner):
    body = {"model": "DeepSeek-V4-Flash", "messages": [{"role": "assistant", "tool_calls": "x"}]}
    assert inspect(json.dumps(body).encode(), policy=policy, scanner=scanner).action == "pass"


def test_tts_input_is_redacted(policy, scanner):
    # TTS text is the one non-chat JSON shape that goes to a cloud model.
    body = {"model": "kokoro", "input": "call jane@example.com tomorrow", "voice": "af_heart"}
    verdict = inspect(json.dumps(body).encode(), policy=policy, scanner=scanner)
    assert verdict.action == "replace"
    redacted = json.loads(verdict.body)
    assert "jane@example.com" not in redacted["input"]
    assert redacted["voice"] == "af_heart"


def test_anthropic_messages_body_is_redacted(policy, scanner):
    body = {
        "model": "claude-x",
        "system": [{"type": "text", "text": "owner: jane@example.com"}],
        "messages": [
            {"role": "user", "content": [{"type": "text", "text": "mail bob@example.net"}]}
        ],
    }
    redacted = json.loads(inspect(json.dumps(body).encode(), policy=policy, scanner=scanner).body)
    assert "jane@example.com" not in redacted["system"][0]["text"]
    assert "bob@example.net" not in redacted["messages"][0]["content"][0]["text"]


# --------------------------------------------------------------------------- #
# the secret-scan sidecar
# --------------------------------------------------------------------------- #
def test_sidecar_and_corpus_detect_spans_are_both_redacted(policy, scanner):
    finds(scanner, SIDECAR_ONLY, SIDECAR_TYPE)
    body = chat(f"mail jane@example.com with {SIDECAR_ONLY} please")
    verdict = inspect(body, policy=EgressPolicy(block_types=frozenset()), scanner=scanner)
    assert verdict.action == "replace"
    content = json.loads(verdict.body)["messages"][0]["content"]
    assert content == f"mail [REDACTED:email] with [REDACTED:{SIDECAR_TYPE}] please"
    assert json.loads(verdict.detail) == {"email": 1, SIDECAR_TYPE: 1}


def test_a_token_both_detectors_find_counts_under_both_types(scanner):
    # corpus-detect masks it as github_token (the identical span's smaller type
    # name), but the sidecar's finding is still counted, so a block on it holds.
    finds(scanner, FAKE_GHP)
    verdict = inspect(
        chat(f"use {FAKE_GHP}"), policy=EgressPolicy(block_types=frozenset()), scanner=scanner
    )
    assert json.loads(verdict.body)["messages"][0]["content"] == "use [REDACTED:github_token]"
    assert json.loads(verdict.detail) == {"github_token": 1, GHP_TYPE: 1}


def test_a_secret_overlapping_pii_wins(scanner):
    # The sidecar's span covers the whole line, the email inside it included.
    text = "token=jane@example.com:" + SIDECAR_ONLY
    finds(scanner, text, SIDECAR_TYPE)
    verdict = inspect(chat(text), policy=EgressPolicy(block_types=frozenset()), scanner=scanner)
    assert json.loads(verdict.body)["messages"][0]["content"] == f"[REDACTED:{SIDECAR_TYPE}]"
    assert json.loads(verdict.detail) == {SIDECAR_TYPE: 1}


@pytest.mark.parametrize(
    ("token", "rule"),
    [
        (FAKE_GHP, GHP_TYPE),
        (SIDECAR_ONLY, SIDECAR_TYPE),
        (SIDECAR_ONLY, "secret:betterleaks:auth0-client-secret_1"),
    ],
)
def test_a_betterleaks_finding_is_refused_with_the_default_block_types(scanner, token, rule):
    finds(scanner, token, rule)
    verdict = inspect(chat(f"use {token}"), policy=EgressPolicy(), scanner=scanner)
    assert (verdict.action, verdict.status) == ("refuse", 403)
    assert json.loads(verdict.body)["error"]["type"] == "egress_policy"
    assert rule in verdict.detail
    assert token not in verdict.detail and token.encode() not in verdict.body


def test_default_block_types_come_from_settings():
    loaded = EgressPolicy.from_settings(Settings())
    assert loaded.block_types == frozenset({"private_key", "secret:betterleaks:*"})


@pytest.mark.parametrize(
    ("entity_type", "blocked"),
    [
        ("private_key", True),
        ("secret:betterleaks:github-pat", True),
        ("secret:betterleaks:", True),
        ("secret:betterleak", False),
        ("private_key_x", False),
        ("aws_access_key", False),
        ("email", False),
    ],
)
def test_block_types_match_exact_names_and_star_prefixes(entity_type, blocked):
    assert EgressPolicy().blocks(entity_type) is blocked


def test_a_trailing_star_prefix_from_settings_still_matches(monkeypatch):
    monkeypatch.setenv("CORPUS_SCAN_GATE_BLOCK_TYPES", "secret:*")
    loaded = EgressPolicy.from_settings(Settings())
    assert loaded.blocks("secret:betterleaks:github-pat")
    assert not loaded.blocks("private_key")


@pytest.mark.parametrize(
    ("block_types", "covered"),
    [
        (frozenset({"secret:betterleaks:*"}), True),
        (frozenset({"secret:*"}), True),
        (frozenset({"private_key", "secret:betterleaks:github-pat"}), False),
        (frozenset({"secret:betterleaks:github*"}), False),
        (frozenset(), False),
    ],
)
def test_blocks_every_needs_a_star_prefix_covering_the_whole_prefix(block_types, covered):
    policy = EgressPolicy(block_types=block_types)
    assert policy.blocks_every("secret:betterleaks:") is covered


def _warnings(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]


@pytest.mark.parametrize("block_types", ["private_key", "secret:betterleaks:github-pat", ""])
def test_unblocked_betterleaks_findings_are_warned_at_startup(monkeypatch, caplog, block_types):
    monkeypatch.setenv("CORPUS_SCAN_GATE_BLOCK_TYPES", block_types)
    warn_if_secrets_unblocked(Settings())
    (message,) = _warnings(caplog)
    assert "secret:betterleaks:*" in message
    assert "Betterleaks findings will be redacted, not blocked" in message


@pytest.mark.parametrize("block_types", ["private_key,secret:betterleaks:*", "secret:*"])
def test_covered_betterleaks_findings_are_not_warned(monkeypatch, caplog, block_types):
    monkeypatch.setenv("CORPUS_SCAN_GATE_BLOCK_TYPES", block_types)
    warn_if_secrets_unblocked(Settings())
    assert _warnings(caplog) == []


def test_no_unblocked_warning_while_the_sidecar_is_disabled(monkeypatch, caplog):
    monkeypatch.setenv("CORPUS_SCAN_GATE_BLOCK_TYPES", "private_key")
    monkeypatch.setenv("CORPUS_SCAN_GATE_SECRETSCAN_ENABLED", "false")
    warn_if_secrets_unblocked(Settings())
    assert _warnings(caplog) == []


def test_block_types_override_from_env(monkeypatch, scanner):
    monkeypatch.setenv("CORPUS_SCAN_GATE_BLOCK_TYPES", "private_key")
    loaded = EgressPolicy.from_settings(Settings())
    finds(scanner, SIDECAR_ONLY, SIDECAR_TYPE)
    verdict = inspect(chat(f"use {SIDECAR_ONLY}"), policy=loaded, scanner=scanner)
    assert verdict.action == "replace"
    assert SIDECAR_ONLY.encode() not in verdict.body


@pytest.mark.parametrize(
    "error",
    [
        SecretScanUnavailable("x"),
        SecretScanTimeout("x"),
        SecretScanStatus(413),
        SecretScanStatus(500),
        SecretScanStatus(504),
        SecretScanMalformed("x"),
    ],
    ids=lambda e: type(e).__name__ + str(getattr(e, "status", "")),
)
def test_a_sidecar_failure_propagates_for_the_adapter_to_refuse(policy, scanner, error):
    scanner.spans.side_effect = error
    with pytest.raises(SecretScanError):
        inspect(chat("lunch at noon?"), policy=EgressPolicy(pass_unparseable=True), scanner=scanner)


def test_text_too_large_to_scan_is_refused_413(scanner):
    scanner.spans.side_effect = SecretScanTooLarge("too_large_to_scan")
    verdict = inspect(chat("x" * 100), policy=EgressPolicy(), scanner=scanner)
    assert (verdict.action, verdict.status, verdict.detail) == ("refuse", 413, "too_large_to_scan")
    assert json.loads(verdict.body)["error"]["type"] == "request_too_large"


def test_skipped_local_model_is_not_sent_to_the_sidecar(policy, scanner):
    inspect(chat("anything", model="qwen3-coder"), policy=policy, scanner=scanner)
    scanner.spans.assert_not_called()


@pytest.mark.parametrize("pass_unparseable", [False, True])
def test_unparseable_body_is_not_sent_to_the_sidecar(scanner, pass_unparseable):
    policy = EgressPolicy(pass_unparseable=pass_unparseable)
    inspect(b"--boundary\r\nRIFF", policy=policy, scanner=scanner)
    inspect(b"[1, 2]", policy=policy, scanner=scanner)
    scanner.spans.assert_not_called()


def test_batch_client_over_the_limit_is_not_sent_to_the_sidecar(policy, scanner):
    inspect(chat("x" * 500), "corpus-enrich", policy=policy, scanner=scanner)
    scanner.spans.assert_not_called()


def test_body_without_text_is_not_sent_to_the_sidecar(policy, scanner):
    inspect(json.dumps({"model": "m", "input": [[1, 2]]}).encode(), policy=policy, scanner=scanner)
    inspect(chat(""), policy=policy, scanner=scanner)
    scanner.spans.assert_not_called()


def test_without_a_scanner_corpus_detect_still_redacts(policy):
    verdict = inspect(chat("key AKIAIOSFODNN7EXAMPLE"), policy=policy, scanner=None)
    assert verdict.action == "replace"
    assert b"AKIAIOSFODNN7EXAMPLE" not in verdict.body


def test_every_text_field_goes_out_in_one_sidecar_call(policy, scanner):
    body = {
        "model": "claude-x",
        "system": "be brief",
        "messages": [
            {"role": "user", "content": "first"},
            {"role": "user", "content": [{"type": "text", "text": "second"}]},
            {"role": "assistant", "tool_calls": [{"function": {"arguments": "third"}}]},
            {"role": "assistant", "content": [{"type": "tool_use", "input": {"q": ["fourth"]}}]},
        ],
    }
    inspect(json.dumps(body).encode(), policy=policy, scanner=scanner)
    scanner.spans.assert_called_once_with(
        SEPARATOR.join(["be brief", "first", "second", "third", "fourth"])
    )


def test_sidecar_logging_carries_types_and_counts_only(policy, scanner, caplog):
    finds(scanner, FAKE_GHP)
    with caplog.at_level(logging.DEBUG):
        inspect(chat(f"tell me about {FAKE_GHP}"), policy=policy, scanner=scanner)
    assert GHP_TYPE in caplog.text
    assert FAKE_GHP not in caplog.text and "tell me" not in caplog.text


# --------------------------------------------------------------------------- #
# batching: one joined text, spans mapped back per field
# --------------------------------------------------------------------------- #
def returning(scanner, *spans: Span):
    scanner.spans.side_effect = None
    scanner.spans.return_value = list(spans)
    return scanner


def test_batched_offsets_map_back_to_each_field_with_non_ascii_text(scanner):
    texts = ["Hei på deg 😀 ", "ærlig talt: " + FAKE_GHP + " ✓", "", "ingen"]
    finds(scanner, FAKE_GHP)
    per_text = scan_texts(scanner, texts)
    start = texts[1].index(FAKE_GHP)
    assert per_text == [[], [Span(start, start + len(FAKE_GHP), GHP_TYPE, "secret")], [], []]
    assert texts[1][per_text[1][0].start : per_text[1][0].end] == FAKE_GHP


def test_span_crossing_a_field_boundary_is_clipped_to_each_field(scanner):
    texts = ["abc😀de", "fgh", "ijk"]
    # Joined: "abc😀de\n\nfgh\n\nijk"; this span runs from "d" into "g".
    joined = SEPARATOR.join(texts)
    returning(scanner, Span(joined.index("d"), joined.index("g") + 1, GHP_TYPE, "secret"))
    assert scan_texts(scanner, texts) == [
        [Span(4, 6, GHP_TYPE, "secret")],
        [Span(0, 2, GHP_TYPE, "secret")],
        [],
    ]


def test_span_ending_exactly_at_a_field_boundary_stays_in_its_field(scanner):
    texts = ["key " + FAKE_GHP, FAKE_GHP]
    finds(scanner, FAKE_GHP)
    first = Span(4, 4 + len(FAKE_GHP), GHP_TYPE, "secret")
    assert scan_texts(scanner, texts) == [[first], [Span(0, len(FAKE_GHP), GHP_TYPE, "secret")]]


def test_span_only_on_the_separator_is_dropped(scanner):
    texts = ["ab", "cd"]
    returning(scanner, Span(2, 4, GHP_TYPE, "secret"))
    assert scan_texts(scanner, texts) == [[], []]


def test_span_across_every_field_masks_each_one(scanner):
    texts = ["ab", "cd", "ef"]
    returning(scanner, Span(1, len(SEPARATOR.join(texts)), GHP_TYPE, "secret"))
    data = {"messages": [{"role": "user", "content": t} for t in texts]}
    counts = redact_payload(data, scanner)
    assert [m["content"] for m in data["messages"]] == [
        f"a[REDACTED:{GHP_TYPE}]",
        f"[REDACTED:{GHP_TYPE}]",
        f"[REDACTED:{GHP_TYPE}]",
    ]
    assert counts == {GHP_TYPE: 3}
