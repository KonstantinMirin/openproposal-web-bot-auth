.PHONY: quality lint placeholders typecheck guards test e2e live-local live-config

# Every gate, in order; the first failing stage stops the run.
quality: lint typecheck guards test

# Formatting, the ruff rule set, the layer bans, ESLint over cfbot, the site, and the
# node test (eslint.config.mjs), and no placeholder.
lint: cfbot/node_modules placeholders
	uv run ruff format --check .
	uv run ruff check .
	uv run ruff check --ignore-noqa --config ruff-domain.toml
	uv run ruff check --ignore-noqa --config ruff-environment.toml
	uv run ruff check --ignore-noqa --config ruff-buyer.toml
	uv run ruff check --ignore-noqa --config ruff-digest.toml
	uv run ruff check --ignore-noqa --config ruff-observers.toml
	cfbot/node_modules/.bin/eslint eslint.config.mjs cfbot site tests

# A placeholder for a link or a value left in the tree. The seed template's own
# placeholders (seller/seed/proposal.yaml) are the seller's to fill in, so they stay.
PLACEHOLDERS := LIBRARY_URL|SPEC_URL|PLACEHOLDER
placeholders:
	@! grep -rnIE '$(PLACEHOLDERS)' --exclude-dir=.git --exclude-dir=.venv \
		--exclude-dir=node_modules --exclude-dir=vendor --exclude-dir=generated \
		--exclude-dir=.ruff_cache --exclude-dir=.mypy_cache --exclude-dir=.pytest_cache \
		--exclude=Makefile --exclude=proposal.yaml .

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

# The behavior suite, with branch coverage and the floor in pyproject.toml: each
# agent's app over a real SQLite store and the real library (both agents in
# process for the buyer, the runner, and the read models), and the protocol
# package against the specification's documents. Then site/run.js renders the
# report the runner's test published (tests/site/render.test.mjs).
test:
	uv run pytest --cov --cov-branch
	node --test tests/site/render.test.mjs

# The whole demo: build, start, run every scenario, tear down.
e2e:
	./e2e/run-e2e.sh

# The live deployment, rehearsed locally: prod compose, the Caddy snippet, one live run.
live-local:
	./deploy/localhost/run.sh

# Validate the production compose file, and keep the test-only fault switch
# (seller/faults.py) out of it. The secrets are stand-ins: Compose requires each one.
LIVE_CONFIG := SELLER_OPERATOR_KEY=- BUYER_OPERATOR_KEY=- CFBOT_OPERATOR_KEY=- \
	DEMO_BEARER_TOKEN=- docker compose --env-file /dev/null -f deploy/docker-compose.prod.yml config
live-config:
	$(LIVE_CONFIG) --quiet
	$(LIVE_CONFIG) | { ! grep -q DEMO_FAULT_INJECTION; }
