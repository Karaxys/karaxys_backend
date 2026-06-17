# Karaxys Data Contracts

This directory owns the versioned message contracts shared by `ebpf_tracer`,
`karaxys_backend`, and `dashboard`.

The first production boundary is capture-source agnostic ingestion:

- `raw.network.v1`: raw syscall/network chunks emitted by the eBPF agent.
- `http.conversation.v1`: normalized request/response conversations emitted by
  the reassembler and accepted by backend ingestion.
- `scan.job.v1`: asynchronous active-testing jobs created by the backend API.
- `scan.result.v1`: normalized scan results emitted by scanner workers.

## Ownership

- `ebpf_tracer` owns capture and reassembly. It may emit `raw.network.v1` and
  `http.conversation.v1`, but it must not own inventory, risk scoring, secrets,
  user identity, or dashboard read models.
- `karaxys_backend` owns validation, authentication, redaction, persistence,
  inventory normalization, active scan orchestration, and read APIs.
- `dashboard` consumes backend APIs only. It must not depend directly on tracer
  Kafka topics, raw eBPF payloads, or database schemas.

## Compatibility Notes

The eBPF agent emits `schema_version: "raw.network.v1"`. The previous
`raw.v1` value is accepted as a temporary legacy alias for older agent builds.

Tenant, project, and agent identity fields are optional in these initial
schemas because the current runtime structs do not populate them yet. Production
ingestion should require those fields once authentication and multi-project
scoping are implemented.

## Validation

Schema and example JSON files can be syntax-checked with:

```sh
jq empty karaxys_backend/contracts/schemas/*.json karaxys_backend/contracts/examples/*.json
```
