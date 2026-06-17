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
