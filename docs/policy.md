# The egress policy

`scan_gate.egress.policy` decides what may leave the network in an LLM request
body. It is gateway-neutral: it takes a body (and the calling client's id, when
the gateway forwards one) and returns a verdict — pass, replace with a redacted
body, or refuse with a status code. A protocol adapter (today only
[Envoy ext_proc](envoy.md)) maps the verdict onto its gateway's wire format.
Only detection types and counts are logged, never a matched value or a body.

## Order

For each body, in order: a body that is not a JSON object is refused (or passed,
when `CORPUS_SCAN_GATE_PASS_UNPARSEABLE` is set and the body is complete; an
incomplete one, a chunk of a larger body, is always refused with `unbuffered`); a model in `CORPUS_SCAN_GATE_SKIP_MODELS` passes unscanned; a batch client's
oversized body gets a 413; otherwise every message's text is redacted, by
corpus-detect together with the [secretscan sidecar](#the-secret-scan-sidecar),
and a finding in `CORPUS_SCAN_GATE_BLOCK_TYPES` gets a 403. A body whose text
is too large for the sidecar gets a 413 (`too_large_to_scan`). Text is read from chat message content
(including nested tool results and tool-call arguments), Anthropic `system`,
embeddings `input` and completions `prompt`. An error inside the policy is
always refused (`scan_error`), never passed and never left to the proxy, whatever
the settings, and so is any sidecar failure. Refusals carry an OpenAI-style JSON error.
`SKIP_MODELS` takes exact names, not patterns, so a typo can only make the gate
scan more. Skipping trusts the body's `model` field, so it is sound only where the
gateway routes on that same field: a request naming a local model must not be
able to reach a cloud backend. Do not list a model if any route sends that name
off the network, and keep path-routed cloud endpoints off the skip path.

The client id is the caller's `x-client-id` request header, which the
gateway sets after authenticating the API key.

## What is redacted

Each match is replaced by a `[REDACTED:<type>]` placeholder by the
[corpus-detect detectors](https://github.com/ryanjdillon/corpus/blob/main/docs/detect.md):

[detectors](https://github.com/ryanjdillon/corpus/blob/main/docs/detect.md):

- credentials (`leaks`): private keys, API keys and tokens; a private key is
  blocked by default (`BLOCK_TYPES`) rather than redacted;
- identity and financial numbers (`pii`): IBANs and crypto wallets on format,
  and US SSNs, credit cards and US bank numbers only with a context word right
  beside them, so an order number that looks like a card passes. The context
  words are Presidio's English ones plus Norwegian ones for a card (`kort`,
  `kortnummer`…) and an account (`konto`, `kontonummer`…); see
  [Tiers](https://github.com/ryanjdillon/corpus/blob/main/docs/tiers.md#what-financial_id-does-not-find) for what still passes;
- Norwegian national id numbers (fødselsnummer, D-nummer, H-nummer, and the tax
  administration's Tenor synthetic test numbers), only when both mod-11 check
  digits and the birth date are valid;
- Norwegian bank account numbers, only when the mod-11 check digit is valid:
  dotted (`NNNN.NN.NNNNN`) or spaced (`NNNN NN NNNNN`, no-break spaces too) on
  format, and a bare 11-digit run only with an account word beside it (`konto`,
  `kontonummer`, `kontonr`, `account`, `bank`…). A bare run that is also a valid national id
  is reported as a national id;
- email addresses;
- phone numbers, only when they are clearly phones: an international prefix
  (`+47`, or `0047` followed by a separator), or a phone word within 32
  characters before the number (`tlf`, `telefon`, `mobil`, `mob`, `phone`, `tel`,
  `cell`, `direkte`, `fax`, including compounds such as `telefonnummer`, and
  allowing a bracket or one short word in between, as in `Tlf (privat)` or
  `Phone number:`). A bare digit run passes, because order numbers, references,
  dates and amounts look the same and redacting them would degrade what the
  model reads. The redaction ends once the number holds 8 digits after any
  country code, so a date or org number that follows stays readable.

Email addresses and phone numbers are redacted on egress only. They are too
common in mail to count as findings in the archive audit; the national id
and bank account numbers are counted there too.

## The secret-scan sidecar

Alongside corpus-detect, every scanned body's text goes to the
[secretscan sidecar](../sidecar/secretscan/README.md), which runs Betterleaks'
ruleset and returns code point spans and rule ids, never a value. Each finding
becomes a span of type `secret:betterleaks:<rule id>` (`.` replaced by `_`,
e.g. `secret:betterleaks:auth0-client-secret_1`), checked with corpus-detect's
`validate_spans`, and each text is redacted with
`redact(text, extra_spans=…)`. Where a sidecar span overlaps a corpus-detect
one, every character either covers is masked, and a secret wins over pii.

**One call per request.** The texts of a body (every field listed above) are
joined with a blank line (`\n\n`) and scanned in one call; each span is then
mapped back to offsets in the field it came from. A newline ends a token for
every Betterleaks rule, so a secret inside one field is found as it would be
alone. A span reaching across a separator, which a rule matching `key: value`
over a line break could produce, is clipped to each field it touches, masking
a little more rather than less, and counts once in each; a part lying only on
the separator is dropped.

**Blocking.** The default `BLOCK_TYPES` includes `secret:betterleaks:*`, so a
request carrying any secret Betterleaks finds is refused (403), not merely
masked. Blocking reads corpus-detect's per-span `counts`, plus every sidecar
span type those leave out: when both detectors find the same token, it is
masked under corpus-detect's type (`github_token`) but still counted under the
Betterleaks one, so the block holds. See
[block types](configuration.md#block-types).

**Fail closed.** Anything short of a well-formed 200 from the sidecar is an
error, and the adapter refuses it (`scan_error`). See
[the sidecar settings](configuration.md#the-secretscan-sidecar) for the timeout
budget and size limit. Logs carry types and counts, and the sidecar's status
code on a failure, never text.
