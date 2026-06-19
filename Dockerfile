FROM golang:1.26-bookworm AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG KARAXYS_CMD=api-server
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/karaxys ./cmd/${KARAXYS_CMD}

FROM debian:bookworm-slim

RUN useradd --system --uid 10001 --create-home karaxys

COPY --from=build /out/karaxys /usr/local/bin/karaxys

USER 10001
ENTRYPOINT ["/usr/local/bin/karaxys"]
