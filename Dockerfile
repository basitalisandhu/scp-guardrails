# syntax=docker/dockerfile:1
#
# The scp-guardrails CLI as an image. Build and run with:
#   docker build -t scp-guardrails .
#   docker run --rm -v "$PWD:/work" scp-guardrails build --spec spec.yaml --out scps
#   docker run --rm -v "$PWD:/work:ro" scp-guardrails lint policies/
#
# The base image is pinned by digest (python:3.12-slim, multi-arch index).
ARG PYTHON_IMAGE=python:3.12-slim@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016

# Build the wheel in a throwaway stage so the build backend never reaches the runtime image.
FROM ${PYTHON_IMAGE} AS build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
WORKDIR /src
COPY pyproject.toml README.md LICENSE CHANGELOG.md ./
COPY src/ src/
RUN pip wheel --no-deps --wheel-dir /wheels .

FROM ${PYTHON_IMAGE}
ARG VERSION=0.0.0-dev
LABEL org.opencontainers.image.title="scp-guardrails" \
      org.opencontainers.image.description="AWS service control policy builder and linter: build, lint, diff and explain SCPs" \
      org.opencontainers.image.source="https://github.com/basitalisandhu/scp-guardrails" \
      org.opencontainers.image.url="https://github.com/basitalisandhu/scp-guardrails" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN --mount=type=bind,from=build,source=/wheels,target=/wheels \
    pip install --no-deps /wheels/*.whl \
 && useradd --uid 1000 --user-group --no-create-home --shell /usr/sbin/nologin app
# Mount the directory with your spec and policies at /work.
WORKDIR /work
USER 1000:1000
ENTRYPOINT ["scp-guardrails"]
CMD ["--help"]
