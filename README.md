# Karaxys Backend

## Local Infrastructure

Karaxys can still connect to MongoDB Atlas by setting `MONGO_URI`, but local
development should use Docker MongoDB, Valkey, and Redpanda:

```sh
cp .env.example .env
make mongo
```

`make mongo` starts MongoDB plus Valkey for the current local backend path. Use
`make redpanda` when testing Phase 4 queues, `make minio` when testing
S3-compatible backup/archive writers locally, or `make infra` to start MongoDB,
Valkey, MinIO, and Redpanda together.

Default local values:

- `MONGO_URI=mongodb://127.0.0.1:27017/?directConnection=true`
- `MONGO_DB_NAME=karaxys`
- `KARAXYS_REDIS_ADDR=127.0.0.1:6379`
- `KARAXYS_OBJECTSTORE_ENDPOINT=http://127.0.0.1:9000`
- `KARAXYS_QUEUE_BROKERS=127.0.0.1:19092`
- `TRAFFIC_LOG_MAX_EVENTS=1000`
- `TRAFFIC_LOG_TTL_HOURS=24`

`traffic_logs` are short-retention capture data. The backend creates a TTL index
on `created_at` and prunes older records so only the newest configured events
are kept.

## Runtime Services

The eBPF ingestion path no longer needs the legacy forward proxy process.

Start MongoDB and Valkey for the current API/scanner workflow:

```sh
make mongo
```

Start all local infrastructure, including Redpanda for Phase 4 queue work:

```sh
make infra
```

Start the API server only:

```sh
KARAXYS_API_KEY=dev-api-key \
make api
```

`KARAXYS_API_KEY` is a compatibility key for local automation. The normal
dashboard/product flow uses user sessions from `/auth/signup` and `/auth/login`.
The normal eBPF flow uses per-agent tokens issued from enrollment tokens instead
of a shared global `KARAXYS_AGENT_TOKEN`.

For production automation, bind the compatibility API key to an account and a
role:

```sh
KARAXYS_API_KEY_ACCOUNT_ID=<mongodb-account-object-id>
KARAXYS_API_KEY_ROLE=scanner
```

Start the isolated Nuclei scanner worker:

```sh
make scanner-worker
```

The legacy proxy/browser workflow remains available for comparison:

```sh
make legacy-proxy
```

## Active Scanning Flow

`POST /scan` now creates a queued `scan_jobs` document and returns `202 Accepted`
with a `job_id`. The API server does not import or execute Nuclei directly.

The scanner worker claims queued jobs from MongoDB, executes Nuclei, writes
`scan_results`, and marks the job `completed` or `failed`.

Auth material supplied for auth-based scans is not stored in `scan_jobs`.
Instead, the API server encrypts it into `scan_secrets`, stores only an
`auth_secret_ref` on the scan job, and the scanner worker decrypts it after
claiming the job. Both API and scanner worker must use the same
`KARAXYS_SECRET_KEY_B64` value for auth-based scans.

Useful endpoints:

- `POST /auth/signup`
- `POST /auth/login`
- `POST /auth/refresh`
- `POST /auth/logout`
- `GET /auth/me`
- `GET /quick-start`
- `GET /data-sources`
- `POST /data-sources`
- `DELETE /data-sources/{id}`
- `POST /agent-enrollments`
- `POST /agents/register`
- `GET /settings/security`
- `PUT /settings/security`
- `POST /scan`
- `GET /scan-jobs/{id}`
- `GET /scan-results?job_id={id}`
- `GET /scan-results?inventory_id={id}`

Normal backend API endpoints require either:

- `Authorization: Bearer <access_token>` from `/auth/signup` or `/auth/login`.
- `X-API-Key: <KARAXYS_API_KEY>` for local automation compatibility.

The eBPF ingestion endpoint is intentionally separate. It accepts per-agent
tokens returned by `POST /agents/register`. `KARAXYS_AGENT_TOKEN` is still
supported only as a local compatibility fallback.

## Runtime Analyzer And Inventory

The runtime analyzer builds API inventory from captured conversations without
using process-memory endpoint clustering. Endpoint identity is deterministic:

- API version segments such as `/v1` are preserved.
- Numeric IDs, UUIDs, Mongo ObjectIDs, hashes, ULIDs, KSUID-like tokens, and
  prefixed IDs such as `user_123` are parameterized.
- Slug-like route segments are preserved unless they match an opaque identifier
  pattern.
- Each endpoint receives an `endpoint_fingerprint` derived from tenant, project,
  method, base URL, and normalized path pattern.

`api_inventory` records use `api.inventory.v2` fields for path examples,
request/response/header/query schemas, response status codes, content types,
auth observation, risk reasons, tags, request counts, first/last seen timestamps,
and redacted samples.

`api_parameters` stores parameter observations separately by endpoint
fingerprint, location, and name. Locations currently include path, query,
header, cookie, request body, and response body. Sample values are capped and
stored only after redaction.

`traffic_samples` stores short-retention redacted HTTP examples keyed by
endpoint fingerprint. The analyzer keeps the latest 20 samples per endpoint by
default, stores only 16 KiB request/response body excerpts, and records SHA-256
hashes for the redacted full bodies.

`sensitive_samples` stores the security evidence view of sensitive observations:
location, field name, detected tags, and a redacted sample marker. It is separate
from `traffic_samples` so the product can query sensitive evidence without
scanning every traffic example.

`traffic_metrics` stores aggregate hour/day counters using
Prometheus-compatible label dimensions: tenant, project, endpoint fingerprint,
method, normalized path, status code/class, auth observed, and risk level. These
counters are intended for dashboard charts and API security trend queries
without scanning short-retention raw logs. `traffic_metric_events` is a
short-retention dedupe ledger keyed by captured conversation and bucket, so a
replayed eBPF conversation does not double-increment hourly or daily metrics.

Endpoint lifecycle detection is configurable through either
`KARAXYS_ENDPOINT_RULES_JSON` or `KARAXYS_ENDPOINT_RULES_FILE`. Rules currently
support deprecated endpoint detection by regex against the original path and
normalized path pattern:

```json
{
  "deprecated": [
    {
      "name": "v1-retired",
      "path_regex": "^/api/v1/",
      "reason": "deprecated_version:v1",
      "tags": ["lifecycle:deprecated", "version:v1"],
      "risk_level": "HIGH"
    }
  ]
}
```

Redis/Valkey-backed coordination is available for distributed HTTP rate limits,
scanner job locks, and short-lived scan progress cache. If
`KARAXYS_REDIS_ADDR` is unset, local development falls back to the in-process
limiter and Mongo scan-job claim path.

S3-compatible object storage is abstracted through backend writers for MongoDB
dump artifacts and long-retention redacted conversation archives. Use AWS S3 in
production and MinIO for local or self-hosted validation.

Analytics and search now have repository interfaces. MongoDB remains the
current implementation for `traffic_metrics` and inventory search. Add
ClickHouse only when MongoDB aggregate reads become too expensive, and add
OpenSearch only when full-text investigation becomes a required product
workflow.

## Queue Layer

Phase 4 introduces a Kafka-compatible queue abstraction with Redpanda as the
local/self-hosted broker. The initial topics are:

- `karaxys.http.conversations`
- `karaxys.analyzer.jobs`
- `karaxys.ingest.dead_letter`

`internal/queue` contains the shared message envelope, producer/consumer
interfaces, an in-memory test broker, and a `franz-go` Kafka-compatible backend.
Docker Compose starts Redpanda and runs `rpk topic create` through
`redpanda-init` for local topic bootstrap.

## Security Baseline

Karaxys redacts common secrets before persistence in the current backend data
paths:

- request and response headers
- request and response bodies
- captured URLs
- ingestion dead-letter excerpts
- analyzer inventory samples
- scan result descriptions, proof commands, and response evidence

The redaction policy covers `Authorization`, `Cookie`, `Set-Cookie`,
`X-API-Key`, token-like headers, bearer/basic credentials, JWTs, API key fields,
password/secret fields, token query parameters, and AWS access key IDs.

The analyzer may inspect raw in-memory events to classify sensitive data, but
persisted samples are redacted. Scan auth material is stored through encrypted
short-lived secret references instead of raw `scan_jobs.config.manual_auth`.

Generate the local scan secret key with:

```sh
openssl rand -base64 32
```

Set the generated value as `KARAXYS_SECRET_KEY_B64` in `.env` or in the
environment of both `make api` and `make scanner-worker`. `BROKEN_USER_AUTH`
does not need this key because it intentionally removes auth.

Backend API security controls currently include:

- Email/password signup and login with access tokens and HttpOnly refresh-token
  cookies.
- Session authentication for dashboard/product APIs.
- RBAC roles for admin, analyst, scanner, read-only, and reserved agent
  principals.
- API-key compatibility for local automation, with optional production account
  and role scoping.
- Per-agent enrollment and token authentication for
  `POST /v1/ingest/conversations`.
- Account scoping for inventory, scan jobs, scan results, data sources, and
  agent enrollment flows.
- Admin-only data-source creation/deletion and agent enrollment.
- Configurable CORS through `KARAXYS_ALLOWED_ORIGINS`.
- Secure response headers on API responses.
- Write request body limiting through `KARAXYS_MAX_WRITE_BYTES`.
- Rate limiting by authenticated API key subject, falling back to client IP for
  unauthenticated/exempt paths.
- Audit log collection for auth, scan creation, data-source creation/deletion,
  settings updates, agent enrollment, and agent registration.
- Account-level security settings for log retention preferences and enforced
  redaction. Redaction cannot be disabled through the API.

Production mode is enabled with:

```sh
KARAXYS_ENV=production
```

In production mode, backend entrypoints validate required secrets and refuse to
start with missing placeholder values, weak configured compatibility API/agent
tokens, unscoped compatibility API keys, localhost CORS origins, or an invalid
scan secret key. The legacy proxy command also disables automatic Chrome launch
in production mode.

## End-To-End Local Workflow

Use this workflow to validate the current eBPF capture to backend ingestion to
active scanning path.

Prerequisites:

- Linux host with Docker and Docker Compose.
- eBPF privileges for the tracer agent. The tracer workflow may prompt for
  `sudo`.
- `jq` installed for the verification commands.

Terminal 1: start MongoDB, Valkey, and the API server.

```sh
cd /home/shion/Documents/Karaxys/karaxys_backend
make mongo
KARAXYS_API_KEY=dev-api-key \
make api
```

Expected API signals:

- `Connected to MongoDB successfully`
- `Backend running on http://localhost:8081`

Terminal 2: start the isolated scanner worker.

```sh
cd /home/shion/Documents/Karaxys/karaxys_backend
make scanner-worker
```

Expected worker signal:

- `Scanner worker started`

Terminal 3: create a user session, configure an eBPF data source, and generate
an enrollment token.

```sh
cd /home/shion/Documents/Karaxys/karaxys_backend

ACCESS_TOKEN="$(curl -s -X POST "http://127.0.0.1:8081/auth/signup" \
  -H "Content-Type: application/json" \
  -c /tmp/karaxys.cookies \
  -d '{"email":"admin@karaxys.local","password":"change-me-now-123","account_name":"Karaxys Local"}' \
  | jq -r '.access_token')"

DATA_SOURCE_ID="$(curl -s -X POST "http://127.0.0.1:8081/data-sources" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"type":"EBPF_LINUX","name":"Local VAmPI eBPF"}' \
  | jq -r '.id')"

ENROLLMENT_TOKEN="$(curl -s -X POST "http://127.0.0.1:8081/agent-enrollments" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"data_source_id\":\"${DATA_SOURCE_ID}\",\"name\":\"local-vampi-agent\",\"ttl_hours\":24}" \
  | jq -r '.enrollment_token')"

echo "${ENROLLMENT_TOKEN}"
```

If the user already exists, replace the signup command with login:

```sh
ACCESS_TOKEN="$(curl -s -X POST "http://127.0.0.1:8081/auth/login" \
  -H "Content-Type: application/json" \
  -c /tmp/karaxys.cookies \
  -d '{"email":"admin@karaxys.local","password":"change-me-now-123"}' \
  | jq -r '.access_token')"
```

Refresh a session using the HttpOnly refresh cookie:

```sh
ACCESS_TOKEN="$(curl -s -X POST "http://127.0.0.1:8081/auth/refresh" \
  -b /tmp/karaxys.cookies \
  -c /tmp/karaxys.cookies \
  | jq -r '.access_token')"
```

Terminal 4: start the eBPF local VAmPI capture workflow and send normalized
conversations to the backend. The script registers the agent with the enrollment
token, receives a per-agent token, and starts the worker with that token.

```sh
cd /home/shion/Documents/Karaxys/ebpf_tracer
KARAXYS_BACKEND_URL=http://127.0.0.1:8081 \
KARAXYS_ENROLLMENT_TOKEN="${ENROLLMENT_TOKEN}" \
make local-vampi
```

Terminal 5: generate sample API traffic.

```sh
cd /home/shion/Documents/Karaxys/ebpf_tracer
make smoke-traffic
```

Expected backend ingestion signals:

- `POST /v1/ingest/conversations | Status: 202`
- Analyzer logs for `/createdb`, `/users/v1/register`, and `/users/v1/login`
- `GET /inventory | Status: 200` when inventory is queried

Verify inventory from another shell:

```sh
curl -s "http://127.0.0.1:8081/inventory?limit=50" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  | jq
```

Verify account settings and the audited settings update path:

```sh
curl -s "http://127.0.0.1:8081/settings/security" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  | jq

curl -s -X PUT "http://127.0.0.1:8081/settings/security" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"retention_hours":24,"max_traffic_events":1000,"redaction_enabled":true}' \
  | jq
```

Pick the captured login endpoint and queue a broken-auth scan:

```sh
INVENTORY_ID="$(curl -s "http://127.0.0.1:8081/inventory?limit=50" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  | jq -r '.data[] | select(.PathPattern == "/users/{id}/login") | .ID' \
  | head -n 1)"

JOB_ID="$(curl -s -X POST "http://127.0.0.1:8081/scan" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"inventory_id\":\"${INVENTORY_ID}\",\"test_type\":\"BROKEN_USER_AUTH\"}" \
  | jq -r '.job_id')"

echo "${JOB_ID}"
```

Check job status and results:

```sh
curl -s "http://127.0.0.1:8081/scan-jobs/${JOB_ID}" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  | jq

curl -s "http://127.0.0.1:8081/scan-results?job_id=${JOB_ID}" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  | jq
```

Expected scan signals:

- API logs `Scan queued`
- Scanner worker logs `Claimed scan job`
- Scanner worker logs `Completed scan job`
- `GET /scan-jobs/{id}` returns `status: completed`
- `GET /scan-results?job_id={id}` returns persisted scan evidence

Optional dashboard check:

```sh
cd /home/shion/Documents/Karaxys/dashboard
npm run dev
```

The dashboard currently needs session-auth wiring before this optional browser
check works with authenticated backend endpoints. Use the curl checks above for
backend/eBPF validation until the UI sprint is resumed.

Cleanup:

```sh
cd /home/shion/Documents/Karaxys/karaxys_backend
curl -s -X DELETE "http://127.0.0.1:8081/data-sources/${DATA_SOURCE_ID}" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -o /dev/null -w "%{http_code}\n"
docker compose down
```
