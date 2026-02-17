FROM python:3.11.6-slim AS base

ENV PYTHONFAULTHANDLER=1 \
    PYTHONHASHSEED=random \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies for confluent-kafka (librdkafka)
RUN apt-get update && apt-get install -y \
    librdkafka-dev \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Creating a virtual environment and installing dependencies
ENV PIP_DEFAULT_TIMEOUT=100 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    POETRY_VERSION=1.3.2 \
    PYTHON_KEYRING_BACKEND=keyring.backends.null.Keyring

RUN pip install "poetry==$POETRY_VERSION"
RUN python -m venv /venv
COPY pyproject.toml poetry.lock ./
RUN . /venv/bin/activate && poetry install --no-root

# Setting the virtual environment path
ENV PYTHONPATH="/app"
ENV PATH="/venv/bin:${PATH}"
ENV VIRTUAL_ENV="/venv"


# Copy application code
COPY . /app

# Expose ports
# 8082 - Health check endpoint
# 8083 - Prometheus metrics
EXPOSE 8082 8083

# Default environment variables
ENV MESSAGING_TYPE=KAFKA \
    PROMETHEUS_METRICS_PORT=8083 \
    HEALTH_CHECK_PORT=8082

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8082/health || exit 1

# Run the standalone consumer (no gunicorn)
CMD ["python", "consumer_main.py"]
