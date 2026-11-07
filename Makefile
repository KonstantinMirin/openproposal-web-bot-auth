.PHONY: test e2e live-local live-config lint

# Unit tests: the record rules against the specification's examples.
test:
	uv run pytest

# The whole demo: build, start, run every scenario, tear down.
e2e:
	./e2e/run-e2e.sh

# The live deployment, rehearsed locally: prod compose, the Caddy snippet, one live run.
live-local:
	./deploy/localhost/run.sh

# Validate the production compose file.
live-config:
	WBA_ENV_FILE=/dev/null docker compose -f deploy/docker-compose.prod.yml config --quiet

lint:
	uv run ruff check .
