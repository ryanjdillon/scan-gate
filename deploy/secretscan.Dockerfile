# The secretscan sidecar (sidecar/secretscan), built from source. Build with the
# sidecar directory as the context:
#   docker build -f deploy/secretscan.Dockerfile sidecar/secretscan
#
# Modules come from go.mod/go.sum only: -mod=readonly refuses to change them,
# and every download is checked against go.sum, so a tampered or re-tagged
# module fails the build. GOTOOLCHAIN=local stops Go fetching a toolchain.
# Both base images are pinned by digest; Dependabot proposes updates.
FROM golang:1.27.2-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61 AS build
ENV CGO_ENABLED=0 \
    GOFLAGS=-mod=readonly \
    GOTOOLCHAIN=local
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY *.go ./
RUN go build -trimpath -ldflags="-s -w -buildid=" -o /out/secretscan .

# A static binary needs no libc or shell; distroless/static adds only CA
# certificates, tzdata and the nonroot user.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/secretscan /secretscan
USER 65532:65532
ENTRYPOINT ["/secretscan"]
