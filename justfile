import 'agents.just'

# scan-gate dev tasks. Enter the dev shell first: `nix develop`.

# Create the uv venv (from the dev shell's Python) and install test + dev deps.
# corpus-detect installs from its git reference in pyproject.toml.
setup:
    uv venv --python python3.12
    uv pip install -c deploy/constraints.txt -e '.[test,dev]'

# Re-pin the runtime and test dependencies the image and CI install
# (deploy/constraints.txt; the image ignores the test pins).
# Run after changing dependencies in pyproject.toml, or to take upstream updates.
# corpus-detect is left out: pip takes it from its git reference, which a
# constraints file cannot carry.
lock:
    uv pip compile pyproject.toml --extra test --python-version 3.12 --python-platform x86_64-unknown-linux-gnu --upgrade --no-emit-package corpus-detect --custom-compile-command "just lock" -o deploy/constraints.txt

# Unit tests.
test:
    uv run pytest

# Lint (uses the pinned ruff from the venv, matching CI).
lint:
    uv run ruff check .

# Coverage with the ratchet gate (.github/coverage-baseline.txt).
cov:
    uv run coverage run -m pytest
    uv run coverage report --precision=2
    uv run python scripts/coverage_gate.py "$(uv run coverage report --format=total --precision=2)" .github/coverage-baseline.txt

# Lint this branch's commit messages against Conventional Commits, mirroring the
# wagoid/commitlint CI. Checks commits not yet on BASE (auto-discovers
# commitlint.config.mjs); with no BASE yet (no remote), every commit.
commitlint BASE="origin/main":
    #!/usr/bin/env bash
    set -euo pipefail
    if git rev-parse --verify -q '{{BASE}}' >/dev/null; then
        commitlint --from '{{BASE}}' --to HEAD
    elif git rev-parse --verify -q HEAD >/dev/null; then
        for c in $(git rev-list HEAD); do git log -1 --format=%B "$c" | commitlint; done
    fi

# All pre-PR checks, mirroring CI. Run this (and fix any failures) before pushing.
check: lint cov commitlint

# Build the image locally (deploy/Dockerfile), tagged scan-gate:dev.
image:
    docker build -f deploy/Dockerfile -t scan-gate:dev .
