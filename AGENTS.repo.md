# scan-gate

scan-gate is the AI gateway's egress redactor: an Envoy `ext_proc` gRPC service
that inspects every LLM request body on its way to a model provider, redacts
PII and credentials, and refuses what must not leave. It **fails closed**: an error inside
the policy is always refused, and a body it cannot parse is refused unless
`CORPUS_SCAN_GATE_PASS_UNPARSEABLE` says otherwise. Keep it that way — a change that
lets an uninspected body through by default is a security regression, not a
fix. It logs detection types and counts, never a matched value or a body.

The detectors are not here: they are `corpus-detect`, from the corpus repo
(`packages/detect`). A detection change belongs there; this repo owns the
policy, the gateway adapter and the service around them.

`src/scan_gate/_ext_proc/` is vendored, generated code; see its README before
touching it.

## Commits

In addition to the base commit rules:

Use Conventional Commit messages (`feat:`, `fix:`, `docs:`, `refactor:`,
`test:`, `build:`, `ci:`, `chore:`, `revert:`). This is enforced against
`@commitlint/config-conventional` (`commitlint.config.mjs`) both in CI (the
`wagoid/commitlint-github-action` on every PR) and locally by `just commitlint`
— part of `just check`. Keep each commit atomic and its subject in the
imperative mood.

## Before opening a PR

Run **`nix develop -c just check`** and fix everything it reports **before**
pushing a branch or opening a PR. It runs the same lint (pinned ruff), tests,
coverage ratchet (`.github/coverage-baseline.txt`: coverage may not drop, and a
rise must raise the baseline in the same change) and commit-message lint as CI.

## Configuration names

The environment variables keep the `CORPUS_` prefix (`CORPUS_SCAN_GATE_*`,
`CORPUS_HOST`) from when the gate shipped in the corpus image,
so deployments carry over unchanged. Do not rename one without a migration.
