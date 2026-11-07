# One image for the seller, the buyer, and the e2e runner.
#
# Build it through e2e/docker-compose.yml: its additional context `wba-lib` is
# the iab-agentic-primitives checkout, which lands at the same relative path as
# on the host, so pyproject.toml's path source resolves unchanged.
FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:0.11.28 /uv /bin/uv
ENV UV_LINK_MODE=copy UV_PROJECT_ENVIRONMENT=/venv PATH=/venv/bin:$PATH \
    PYTHONPATH=/src/openproposal-web-bot-auth PYTHONDONTWRITEBYTECODE=1

COPY --from=wba-lib pyproject.toml README.md /src/iab-agentic-primitives/
COPY --from=wba-lib src /src/iab-agentic-primitives/src
WORKDIR /src/openproposal-web-bot-auth
COPY pyproject.toml uv.lock ./
COPY vendor vendor
RUN uv sync --no-install-project

COPY demo_types demo_types
COPY shared shared
COPY seller seller
COPY buyer buyer
COPY e2e/scenarios e2e/scenarios

RUN useradd --uid 10001 app && mkdir /data && chown app /data
