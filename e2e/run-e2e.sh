#!/usr/bin/env bash
# Brings the demo stack up from nothing, runs the scenarios, and tears it down.
set -euo pipefail
cd "$(dirname "$0")"
source ../deploy/compose.sh

uv run --project .. python gen_demo_tls.py
# The front serves the production Caddy snippet, rewritten for the containers.
mkdir -p generated/logs
python3 ../deploy/local_caddy.py ../deploy/Caddyfile.snippet generated/Caddyfile

compose=(docker compose --env-file generated/demo.env -f docker-compose.yml --profile test)
trap '"${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1' EXIT
compose_run "seller buyer cfbot front" scenarios
