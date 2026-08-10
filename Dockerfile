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
# 8092 - Health check endpoint
# 8094 - Prometheus metrics
#
# These MUST match src/consumer_main.py's defaults. config() reads os.environ
# first and Docker ENV lands in os.environ, so the ENV block below wins over
# the code defaults -- which meant the container served metrics on 8083 while
# the code, CLAUDE.md, .claude/rules/event-handler.md and VAULT all documented
# 8094. A scrape target written from the documentation collected nothing.
EXPOSE 8092 8094

# Default environment variables
ENV MESSAGING_TYPE=KAFKA \
    PROMETHEUS_METRICS_PORT=8094 \
    HEALTH_CHECK_PORT=8092

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8092/health || exit 1

# Run the standalone consumer (no gunicorn)
CMD ["python", "-m", "src.consumer_main"]
