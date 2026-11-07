.PHONY: test e2e lint

# Unit tests: the record rules against the specification's examples.
test:
	uv run pytest

# The whole demo: build, start, run every scenario, tear down.
e2e:
	./e2e/run-e2e.sh

lint:
	uv run ruff check .
