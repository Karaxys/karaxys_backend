# Karaxys Backend

## Local MongoDB

Karaxys can still connect to MongoDB Atlas by setting `MONGO_URI`, but local
development should use Docker MongoDB:

```sh
cp .env.example .env
docker compose up -d mongo
```

Default local values:

- `MONGO_URI=mongodb://127.0.0.1:27017/?directConnection=true`
- `MONGO_DB_NAME=karaxys`
- `TRAFFIC_LOG_MAX_EVENTS=1000`
- `TRAFFIC_LOG_TTL_HOURS=24`

`traffic_logs` are short-retention capture data. The backend creates a TTL index
on `created_at` and prunes older records so only the newest configured events
are kept.

## Runtime Services

The eBPF ingestion path no longer needs the legacy forward proxy process.

Start MongoDB:

```sh
make mongo
```

Start the API server only:

```sh
KARAXYS_AGENT_TOKEN=dev-agent-token make api
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

Useful endpoints:

- `POST /scan`
- `GET /scan-jobs/{id}`
- `GET /scan-results?job_id={id}`
- `GET /scan-results?inventory_id={id}`

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
persisted samples are redacted. Auth material supplied to future auth-based scan
jobs still needs a secret-reference model before public or production exposure.

## End-To-End Local Workflow

Use this workflow to validate the current eBPF capture to backend ingestion to
active scanning path.

Prerequisites:

- Linux host with Docker and Docker Compose.
- eBPF privileges for the tracer agent. The tracer workflow may prompt for
  `sudo`.
- `jq` installed for the verification commands.

Terminal 1: start MongoDB and the API server.

```sh
cd /home/shion/Documents/Karaxys/karaxys_backend
make mongo
KARAXYS_AGENT_TOKEN=dev-agent-token make api
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

Terminal 3: start the eBPF local VAmPI capture workflow and send normalized
conversations to the backend.

```sh
cd /home/shion/Documents/Karaxys/ebpf_tracer
KARAXYS_BACKEND_URL=http://127.0.0.1:8081 \
KARAXYS_AGENT_TOKEN=dev-agent-token \
make local-vampi
```

Terminal 4: generate sample API traffic.

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
curl -s "http://127.0.0.1:8081/inventory?limit=50" | jq
```

Pick the captured login endpoint and queue a broken-auth scan:

```sh
INVENTORY_ID="$(curl -s "http://127.0.0.1:8081/inventory?limit=50" \
  | jq -r '.data[] | select(.PathPattern == "/users/{id}/login") | .ID' \
  | head -n 1)"

JOB_ID="$(curl -s -X POST "http://127.0.0.1:8081/scan" \
  -H "Content-Type: application/json" \
  -d "{\"inventory_id\":\"${INVENTORY_ID}\",\"test_type\":\"BROKEN_USER_AUTH\"}" \
  | jq -r '.job_id')"

echo "${JOB_ID}"
```

Check job status and results:

```sh
curl -s "http://127.0.0.1:8081/scan-jobs/${JOB_ID}" | jq
curl -s "http://127.0.0.1:8081/scan-results?job_id=${JOB_ID}" | jq
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

Open `http://localhost:7000/dashboard/logs` and verify the captured endpoints
are listed. Open `http://localhost:7000/dashboard/scan`, select the login
endpoint, launch a scan, and confirm the result appears after the worker
completes the job.

Cleanup:

```sh
cd /home/shion/Documents/Karaxys/karaxys_backend
docker compose down
```
