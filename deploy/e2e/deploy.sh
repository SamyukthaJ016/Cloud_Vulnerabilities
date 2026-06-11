#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MODE="${1:-}"
REMOTE_TARGET="${2:-}"
ENV_FILE="${3:-}"
REMOTE_DIR="${REMOTE_DIR:-/opt/cloudguard/app}"

usage() {
  echo "Usage: $0 <portal|worker> <ssh-target> <env-file>" >&2
  echo "Example: $0 portal ubuntu@203.0.113.10 .env.e2e.portal" >&2
  echo "Example: $0 worker ubuntu@203.0.113.11 .env.e2e.worker" >&2
}

if [[ "${MODE}" != "portal" && "${MODE}" != "worker" ]]; then
  usage
  exit 1
fi

if [[ -z "${REMOTE_TARGET}" || -z "${ENV_FILE}" ]]; then
  usage
  exit 1
fi

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "Env file not found: ${ENV_FILE}" >&2
  exit 1
fi

COMPOSE_FILE="deploy/e2e/${MODE}-compose.yml"
REMOTE_ENV_FILE=".env.${MODE}"

ssh "${REMOTE_TARGET}" "mkdir -p '${REMOTE_DIR}'"

rsync -az --delete \
  --exclude ".git/" \
  --exclude ".venv/" \
  --exclude ".venv311/" \
  --exclude "__pycache__/" \
  --exclude ".pytest_cache/" \
  --exclude ".mypy_cache/" \
  --exclude "node_modules/" \
  --exclude "logs/" \
  --exclude "reports/" \
  --exclude "deploy/e2e/runtime/" \
  --exclude ".DS_Store" \
  --exclude ".env" \
  --exclude ".env.*" \
  --exclude ".terraform/" \
  --exclude "**/.terraform/" \
  --exclude "*.tfstate" \
  --exclude "*.tfvars" \
  "${ROOT_DIR}/" "${REMOTE_TARGET}:${REMOTE_DIR}/"

scp "${ENV_FILE}" "${REMOTE_TARGET}:${REMOTE_DIR}/${REMOTE_ENV_FILE}"
ssh "${REMOTE_TARGET}" "chmod 600 '${REMOTE_DIR}/${REMOTE_ENV_FILE}'"

if [[ "${MODE}" == "worker" ]]; then
  ssh "${REMOTE_TARGET}" "\
    mkdir -p \
      '${REMOTE_DIR}/deploy/e2e/runtime/worker/reports' \
      '${REMOTE_DIR}/deploy/e2e/runtime/worker/logs' \
      '${REMOTE_DIR}/deploy/e2e/runtime/connectors/inbox' \
      '${REMOTE_DIR}/deploy/e2e/runtime/connectors/processed' \
      '${REMOTE_DIR}/deploy/e2e/runtime/connectors/failed' \
    && chown -R 1000:1000 '${REMOTE_DIR}/deploy/e2e/runtime'"
fi

ssh "${REMOTE_TARGET}" "cd '${REMOTE_DIR}' && COMPOSE_IGNORE_ORPHANS=true docker compose -f '${COMPOSE_FILE}' --env-file '${REMOTE_ENV_FILE}' up -d --build"
ssh "${REMOTE_TARGET}" "cd '${REMOTE_DIR}' && COMPOSE_IGNORE_ORPHANS=true docker compose -f '${COMPOSE_FILE}' --env-file '${REMOTE_ENV_FILE}' ps"
