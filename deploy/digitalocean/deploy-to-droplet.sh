#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REMOTE_TARGET="${1:-}"
ENV_FILE="${2:-${ROOT_DIR}/.env.digitalocean.local}"
REMOTE_DIR="${REMOTE_DIR:-/opt/cloudguard/app}"

if [[ -z "${REMOTE_TARGET}" ]]; then
  echo "Usage: $0 <ssh-target> [env-file]" >&2
  echo "Example: $0 cloudguard@203.0.113.10 .env.digitalocean.local" >&2
  exit 1
fi

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "Env file not found: ${ENV_FILE}" >&2
  echo "Generate one with deploy/digitalocean/generate-env.sh or copy .env.digitalocean.example." >&2
  exit 1
fi

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
  --exclude ".DS_Store" \
  --exclude ".env" \
  --exclude ".env.local" \
  --exclude ".env.production" \
  "${ROOT_DIR}/" "${REMOTE_TARGET}:${REMOTE_DIR}/"

scp "${ENV_FILE}" "${REMOTE_TARGET}:${REMOTE_DIR}/.env"

ssh "${REMOTE_TARGET}" "cd '${REMOTE_DIR}' && docker compose -f deploy/digitalocean/docker-compose.yml --env-file .env up -d --build"
ssh "${REMOTE_TARGET}" "cd '${REMOTE_DIR}' && docker compose -f deploy/digitalocean/docker-compose.yml --env-file .env ps"
ssh "${REMOTE_TARGET}" "curl -fsS http://localhost/health || true"

echo "Deployment command completed. After DNS points to the Droplet, check https://\$(grep '^DOMAIN=' '${ENV_FILE}' | cut -d= -f2)/health"
