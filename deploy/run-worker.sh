#!/bin/sh
set -eu

PORT_VALUE="${PORT:-8000}"
WEB_CONCURRENCY_VALUE="${WEB_CONCURRENCY:-2}"

exec python -m uvicorn backend.worker_app:app \
  --host 0.0.0.0 \
  --port "${PORT_VALUE}" \
  --workers "${WEB_CONCURRENCY_VALUE}"
