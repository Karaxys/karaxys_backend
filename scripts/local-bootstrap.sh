#!/usr/bin/env bash
set -euo pipefail

API_BASE_URL="${KARAXYS_API_BASE_URL:-http://127.0.0.1:8081}"
EMAIL="${KARAXYS_LOCAL_EMAIL:-admin@karaxys.local}"
PASSWORD="${KARAXYS_LOCAL_PASSWORD:-change-me-now-123}"
ACCOUNT_NAME="${KARAXYS_LOCAL_ACCOUNT_NAME:-Karaxys Local}"
DATA_SOURCE_NAME="${KARAXYS_LOCAL_DATA_SOURCE_NAME:-Local VAmPI eBPF}"
TARGET_URL="${KARAXYS_LOCAL_TARGET_URL:-http://127.0.0.1:3000}"
TARGET_PORTS="${KARAXYS_LOCAL_TARGET_PORTS:-5000}"
IGNORE_PORTS="${KARAXYS_LOCAL_IGNORE_PORTS:-9092,27017,6379}"
ACCESS_TOKEN_FILE="${KARAXYS_ACCESS_TOKEN_FILE:-/tmp/karaxys_access_token}"
ENROLLMENT_TOKEN_FILE="${KARAXYS_ENROLLMENT_TOKEN_FILE:-/tmp/karaxys_enrollment_token}"
DATA_SOURCE_ID_FILE="${KARAXYS_DATA_SOURCE_ID_FILE:-/tmp/karaxys_data_source_id}"
COOKIE_FILE="${KARAXYS_COOKIE_FILE:-/tmp/karaxys.cookies}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[karaxys] missing required command: $1" >&2
    exit 1
  fi
}

post_json() {
  local path="$1"
  local body="$2"
  local output="$3"
  curl -sS -o "${output}" -w "%{http_code}" \
    -X POST "${API_BASE_URL%/}${path}" \
    -H "Content-Type: application/json" \
    -c "${COOKIE_FILE}" \
    -b "${COOKIE_FILE}" \
    -d "${body}"
}

extract_token() {
  local response_file="$1"
  local token
  token="$(jq -r '.access_token // empty' "${response_file}")"
  if [[ -z "${token}" || "${token}" == "null" ]]; then
    echo "[karaxys] access_token missing in response:" >&2
    cat "${response_file}" >&2
    exit 1
  fi
  printf '%s' "${token}"
}

require_cmd curl
require_cmd jq

tmp_signup="$(mktemp)"
tmp_login="$(mktemp)"
tmp_source="$(mktemp)"
tmp_enrollment="$(mktemp)"
trap 'rm -f "${tmp_signup}" "${tmp_login}" "${tmp_source}" "${tmp_enrollment}"' EXIT

signup_body="$(jq -n \
  --arg email "${EMAIL}" \
  --arg password "${PASSWORD}" \
  --arg account_name "${ACCOUNT_NAME}" \
  '{email: $email, password: $password, account_name: $account_name}')"

signup_code="$(post_json "/auth/signup" "${signup_body}" "${tmp_signup}")"
if [[ "${signup_code}" == "201" ]]; then
  access_token="$(extract_token "${tmp_signup}")"
  echo "[karaxys] signed up local user ${EMAIL}"
elif [[ "${signup_code}" == "409" ]]; then
  login_body="$(jq -n \
    --arg email "${EMAIL}" \
    --arg password "${PASSWORD}" \
    '{email: $email, password: $password}')"
  login_code="$(post_json "/auth/login" "${login_body}" "${tmp_login}")"
  if [[ "${login_code}" != "200" ]]; then
    echo "[karaxys] login failed with HTTP ${login_code}:" >&2
    cat "${tmp_login}" >&2
    exit 1
  fi
  access_token="$(extract_token "${tmp_login}")"
  echo "[karaxys] logged in local user ${EMAIL}"
else
  echo "[karaxys] signup failed with HTTP ${signup_code}:" >&2
  cat "${tmp_signup}" >&2
  exit 1
fi

data_source_body="$(jq -n \
  --arg name "${DATA_SOURCE_NAME}" \
  --arg target_url "${TARGET_URL}" \
  --arg target_ports "${TARGET_PORTS}" \
  --arg ignore_ports "${IGNORE_PORTS}" \
  '{
    type: "EBPF_LINUX",
    name: $name,
    target_url: $target_url,
    config: {
      target_ports: $target_ports,
      ignore_ports: $ignore_ports,
      capture_inbound: "true",
      capture_outbound: "true",
      capture_read_syscalls: "true",
      capture_write_syscalls: "true",
      max_payload_size: "16384"
    }
  }')"

source_code="$(curl -sS -o "${tmp_source}" -w "%{http_code}" \
  -X POST "${API_BASE_URL%/}/data-sources" \
  -H "Authorization: Bearer ${access_token}" \
  -H "Content-Type: application/json" \
  -d "${data_source_body}")"
if [[ "${source_code}" != "201" ]]; then
  echo "[karaxys] data source creation failed with HTTP ${source_code}:" >&2
  cat "${tmp_source}" >&2
  exit 1
fi
data_source_id="$(jq -r '.id // empty' "${tmp_source}")"
if [[ -z "${data_source_id}" || "${data_source_id}" == "null" ]]; then
  echo "[karaxys] data source id missing in response:" >&2
  cat "${tmp_source}" >&2
  exit 1
fi

enrollment_body="$(jq -n \
  --arg data_source_id "${data_source_id}" \
  --arg name "local-vampi-agent" \
  '{data_source_id: $data_source_id, name: $name, ttl_hours: 24}')"

enrollment_code="$(curl -sS -o "${tmp_enrollment}" -w "%{http_code}" \
  -X POST "${API_BASE_URL%/}/agent-enrollments" \
  -H "Authorization: Bearer ${access_token}" \
  -H "Content-Type: application/json" \
  -d "${enrollment_body}")"
if [[ "${enrollment_code}" != "201" ]]; then
  echo "[karaxys] enrollment creation failed with HTTP ${enrollment_code}:" >&2
  cat "${tmp_enrollment}" >&2
  exit 1
fi
enrollment_token="$(jq -r '.enrollment_token // empty' "${tmp_enrollment}")"
if [[ -z "${enrollment_token}" || "${enrollment_token}" == "null" ]]; then
  echo "[karaxys] enrollment token missing in response:" >&2
  cat "${tmp_enrollment}" >&2
  exit 1
fi

umask 077
printf '%s\n' "${access_token}" >"${ACCESS_TOKEN_FILE}"
printf '%s\n' "${enrollment_token}" >"${ENROLLMENT_TOKEN_FILE}"
printf '%s\n' "${data_source_id}" >"${DATA_SOURCE_ID_FILE}"

echo "[karaxys] wrote ${ACCESS_TOKEN_FILE}"
echo "[karaxys] wrote ${ENROLLMENT_TOKEN_FILE}"
echo "[karaxys] wrote ${DATA_SOURCE_ID_FILE}"
