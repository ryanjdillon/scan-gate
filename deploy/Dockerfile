# Build into a virtualenv, then copy it into a slim runtime. The build stage has
# git because corpus-detect is a git dependency; the runtime needs neither git
# nor a compiler. Credential detection is corpus-detect's local rules, so the
# image carries no external scanner binary.
# python:3.12-slim
ARG PYTHON_IMAGE=python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1

FROM ${PYTHON_IMAGE} AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/*
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
# Install against the pinned constraints, so a rebuild of the same release gets the
# same dependency set (pyproject.toml only states ranges). `just lock` regenerates it.
COPY deploy/constraints.txt /tmp/constraints.txt
RUN pip install --no-cache-dir -c /tmp/constraints.txt .

FROM ${PYTHON_IMAGE}
ENV PYTHONUNBUFFERED=1 \
    PATH=/opt/venv/bin:$PATH
RUN useradd --create-home --uid 1000 scan-gate
COPY --from=build /opt/venv /opt/venv
USER scan-gate
EXPOSE 9002
ENTRYPOINT ["scan-gate"]
