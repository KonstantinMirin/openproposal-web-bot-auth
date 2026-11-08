.PHONY: quality lint typecheck test e2e live-local live-config

# Every gate, in order; the first failing stage stops the run.
quality: lint typecheck test

# Formatting, the ruff rule set, and cfbot's ESLint.
lint: cfbot/node_modules
	uv run ruff format --check .
	uv run ruff check .
	cd cfbot && npx --no-install eslint server.mjs

cfbot/node_modules: cfbot/package-lock.json
	cd cfbot && npm ci --no-audit --no-fund
	touch cfbot/node_modules

# mypy strict, with the pydantic plugin and the disallow_any_explicit tier.
typecheck:
	uv run mypy

# The behavior suite, with branch coverage and the floor in pyproject.toml: each
# agent's app over a real SQLite store and the real library (both agents in
# process for the buyer, the runner, and the read models), and the protocol
# package against the specification's documents.
test:
	uv run pytest --cov --cov-branch

# The whole demo: build, start, run every scenario, tear down.
e2e:
	./e2e/run-e2e.sh

# The live deployment, rehearsed locally: prod compose, the Caddy snippet, one live run.
live-local:
	./deploy/localhost/run.sh

# Validate the production compose file, and keep the test-only fault switch
# (seller/faults.py) out of it.
live-config:
	WBA_ENV_FILE=/dev/null docker compose -f deploy/docker-compose.prod.yml config --quiet
	WBA_ENV_FILE=/dev/null docker compose -f deploy/docker-compose.prod.yml config \
		| { ! grep -q DEMO_FAULT_INJECTION; }
