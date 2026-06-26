.PHONY: mongo redis minio redpanda infra services api api-queued ingestor runtime-analyzer dead-letter-consumer scanner-worker legacy-proxy local-bootstrap test test-fast test-scanner-worker test-scanner-integration

MONGO_URI ?= mongodb://127.0.0.1:27017/?directConnection=true
MONGO_DB_NAME ?= karaxys
TRAFFIC_LOG_MAX_EVENTS ?= 1000
TRAFFIC_LOG_TTL_HOURS ?= 24
MONGO_INDEX_TIMEOUT_SECONDS ?= 300

export MONGO_URI
export MONGO_DB_NAME
export TRAFFIC_LOG_MAX_EVENTS
export TRAFFIC_LOG_TTL_HOURS
export MONGO_INDEX_TIMEOUT_SECONDS

mongo:
	docker compose up -d mongo redis

redis:
	docker compose up -d redis

minio:
	docker compose up -d minio

redpanda:
	docker compose up -d redpanda redpanda-init

infra:
	docker compose up -d mongo redis minio redpanda redpanda-init

services:
	docker compose up -d api-server ingestor runtime-analyzer dead-letter-consumer scanner-worker

api:
	go run ./cmd/api-server

api-queued:
	KARAXYS_QUEUE_ENABLED=true go run ./cmd/api-server

ingestor:
	go run ./cmd/ingestor

runtime-analyzer:
	go run ./cmd/runtime-analyzer

dead-letter-consumer:
	go run ./cmd/dead-letter-consumer

scanner-worker:
	go run ./cmd/scanner-worker

legacy-proxy:
	go run ./cmd/cli

local-bootstrap:
	bash scripts/local-bootstrap.sh

test:
	go test ./...

test-fast:
	go test $$(go list ./... | grep -v '/cmd/scanner-worker')

test-scanner-worker:
	go test ./cmd/scanner-worker ./cmd/scanner-worker/internal/nucleiscanner ./internal/scanner ./internal/scancontrol ./internal/scanplan

test-scanner-integration:
	go test -tags=integration ./cmd/scanner-worker/internal/nucleiscanner
