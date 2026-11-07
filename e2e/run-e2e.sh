#!/usr/bin/env bash
# Brings the demo stack up from nothing, runs the scenarios, and tears it down.
set -euo pipefail
cd "$(dirname "$0")"

uv run --project .. python gen_demo_tls.py
compose=(docker compose -f docker-compose.yml)
trap '"${compose[@]}" --profile test down --volumes --remove-orphans >/dev/null 2>&1' EXIT

# Start from clean volumes, so every run is a fresh stack: no keys, no records.
"${compose[@]}" --profile test down --volumes --remove-orphans >/dev/null 2>&1
"${compose[@]}" --profile test build
"${compose[@]}" up --detach --wait seller buyer cfbot front
if ! "${compose[@]}" run --rm runner; then
    "${compose[@]}" logs --no-color seller buyer cfbot | tail -n 200
    exit 1
fi
