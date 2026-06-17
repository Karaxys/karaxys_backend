.PHONY: mongo api scanner-worker legacy-proxy test

MONGO_URI ?= mongodb://127.0.0.1:27017/?directConnection=true
MONGO_DB_NAME ?= karaxys
TRAFFIC_LOG_MAX_EVENTS ?= 1000
TRAFFIC_LOG_TTL_HOURS ?= 24

export MONGO_URI
export MONGO_DB_NAME
export TRAFFIC_LOG_MAX_EVENTS
export TRAFFIC_LOG_TTL_HOURS

mongo:
	docker compose up -d mongo

api:
	go run ./cmd/api-server

scanner-worker:
	go run ./cmd/scanner-worker

legacy-proxy:
	go run ./cmd/cli

test:
	go test ./...
