# The secretscan sidecar (sidecar/secretscan), built from source. Build with the
# sidecar directory as the context:
#   docker build -f deploy/secretscan.Dockerfile sidecar/secretscan
#
# Modules come from go.mod/go.sum only: -mod=readonly refuses to change them,
# and every download is checked against go.sum, so a tampered or re-tagged
# module fails the build. GOTOOLCHAIN=local stops Go fetching a toolchain.
# Both base images are pinned by digest; Dependabot proposes updates.
FROM golang:1.27.4-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea AS build
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
