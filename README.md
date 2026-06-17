# Karaxys Backend

## Local MongoDB

Karaxys can still connect to MongoDB Atlas by setting `MONGO_URI`, but local
development should use Docker MongoDB:

```sh
cp .env.example .env
docker compose up -d mongo
```

Default local values:

- `MONGO_URI=mongodb://localhost:27017`
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
