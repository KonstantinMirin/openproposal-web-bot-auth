.PHONY: quality lint typecheck guards test e2e live-local live-config

# Every gate, in order; the first failing stage stops the run.
quality: lint typecheck guards test

# Formatting, the ruff rule set, the layer bans, and cfbot's ESLint.
lint: cfbot/node_modules
	uv run ruff format --check .
	uv run ruff check .
	uv run ruff check --config ruff-domain.toml
	uv run ruff check --config ruff-environment.toml
	uv run ruff check --config ruff-buyer.toml
	cd cfbot && npx --no-install eslint server.mjs

cfbot/node_modules: cfbot/package-lock.json
	cd cfbot && npm ci --no-audit --no-fund
	touch cfbot/node_modules

# mypy strict, with the pydantic plugin and the disallow_any_explicit tier.
typecheck:
	uv run mypy

# Structural rules and import-layer contracts.
guards:
	uv run ast-grep scan --config sgconfig.yml
	uv run lint-imports

# Unit tests: the record rules against the specification's examples, the
# documents, attribution, evidence, keyring, offer checks, and the runner's
# report, with branch coverage and the floor in pyproject.toml.
test:
	uv run pytest --cov --cov-branch

# The whole demo: build, start, run every scenario, tear down.
e2e:
	./e2e/run-e2e.sh

# The live deployment, rehearsed locally: prod compose, the Caddy snippet, one live run.
live-local:
	./deploy/localhost/run.sh

# Validate the production compose file.
live-config:
	WBA_ENV_FILE=/dev/null docker compose -f deploy/docker-compose.prod.yml config --quiet
