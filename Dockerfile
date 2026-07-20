FROM python:3.10-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN python -m pip install --upgrade pip \
    && python -m pip install "semgrep>=1.70,<2"

COPY pyproject.toml README.md ./
COPY src ./src
COPY configs ./configs
COPY examples ./examples
COPY docs ./docs

RUN python -m pip install .

RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /artifacts \
    && chown -R appuser:appuser /artifacts

USER appuser

ENV ARTIFACT_ROOT=/artifacts \
    REPORT_DIR=/artifacts/reports \
    EVALUATION_DIR=/artifacts/evaluation \
    OLLAMA_BASE_URL=http://host.docker.internal:11434

ENTRYPOINT ["vuln-agent"]
CMD ["doctor"]
