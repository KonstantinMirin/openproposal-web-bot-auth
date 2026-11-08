# Two stages: `base`, the image of the seller, the buyer, and the live runner,
# and `scenarios`, the base plus the e2e scenarios and the dev group they run with.
#
# deploy/compose.base.yml builds `base` for every service; only the scenarios
# service of e2e/docker-compose.yml builds `scenarios`, so the live image holds
# no test code. Their additional context `wba-lib` is the iab-agentic-primitives
# checkout, which lands at the same relative path as on the host, so
# pyproject.toml's path source resolves unchanged.
FROM python:3.12-slim AS base
COPY --from=ghcr.io/astral-sh/uv:0.11.28 /uv /bin/uv
ENV UV_LINK_MODE=copy UV_PROJECT_ENVIRONMENT=/venv PATH=/venv/bin:$PATH \
    PYTHONPATH=/src/openproposal-web-bot-auth PYTHONDONTWRITEBYTECODE=1

COPY --from=wba-lib pyproject.toml README.md /src/iab-agentic-primitives/
COPY --from=wba-lib src /src/iab-agentic-primitives/src
WORKDIR /src/openproposal-web-bot-auth
COPY pyproject.toml uv.lock ./
COPY vendor vendor
RUN uv sync --no-install-project --no-dev

COPY protocol protocol
COPY persistence persistence
COPY shared shared
COPY transport transport
COPY seller seller
COPY buyer buyer
COPY runner runner

# /data holds an agent's database and /keys its signing keys, each its own volume.
RUN useradd --uid 10001 app && mkdir /data /keys && chown app /data /keys && chmod 700 /keys
USER app

# The e2e scenarios (pytest e2e/scenarios), which run as the same user.
FROM base AS scenarios
USER root
RUN uv sync --no-install-project
COPY e2e/scenarios e2e/scenarios
USER app
