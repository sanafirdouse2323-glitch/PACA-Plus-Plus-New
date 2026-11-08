FROM python:3.13-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

# Build the package and collect all API runtime dependencies into a wheelhouse.
COPY pyproject.toml README.md LICENSE ./
COPY paca ./paca
COPY paca_executor.py ./paca_executor.py

RUN python -m pip wheel --no-cache-dir --wheel-dir=/wheels ".[api]"


FROM python:3.13-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install only the built package and its declared API dependencies.
COPY --from=builder /wheels /wheels

RUN python -m pip install --no-cache-dir --no-index --find-links=/wheels "paca-plus-plus[api]" \
    && rm -rf /wheels \
    && useradd --create-home --uid 10001 paca

USER paca

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)" || exit 1

# This reference API is not a production effect executor; bind the host port to loopback for local use.
CMD ["uvicorn", "paca_executor:app", "--host", "0.0.0.0", "--port", "8000"]
