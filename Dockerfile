# syntax=docker/dockerfile:1.7
# Universal build — selects the command via KARAXYS_CMD build-arg.
# For production, use the dedicated per-service Dockerfiles.
# ── build ─────────────────────────────────────────────────────────────────────
FROM golang:1.26-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

ARG KARAXYS_CMD=api-server
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build \
      -trimpath \
      -ldflags="-s -w" \
      -o /out/karaxys \
      ./cmd/${KARAXYS_CMD}

# ── runtime ───────────────────────────────────────────────────────────────────
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="karaxys" \
      org.opencontainers.image.source="https://github.com/karaxys/karaxys"

COPY --from=build --chown=65532:65532 /src/contracts ./contracts
COPY --from=build --chown=65532:65532 /out/karaxys /usr/local/bin/karaxys

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/karaxys"]
