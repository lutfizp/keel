#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/.."
PY="${PYTHON:-python3}"
exec "$PY" scripts/bootstrap.py "$@"
