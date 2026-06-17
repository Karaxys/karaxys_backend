.PHONY: mongo api scanner-worker legacy-proxy test

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
