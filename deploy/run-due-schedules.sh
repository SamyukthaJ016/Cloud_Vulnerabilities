#!/bin/sh
set -eu

exec python -m backend.run_due_schedules_once
