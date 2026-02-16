FROM python:3.11.6-slim as base

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
ENV PYTHONPATH="/app:${PYTHONPATH}"
ENV PATH="/venv/bin:${PATH}"
ENV VIRTUAL_ENV="/venv"


# Copy application code
# Common and Shared Modules
COPY keep/common /app/keep/common
COPY keep/providers /app/keep/providers
COPY keep/workflowmanager /app/keep/workflowmanager
COPY keep/secretmanager /app/keep/secretmanager
COPY keep/rulesengine /app/keep/rulesengine
COPY keep/identitymanager /app/keep/identitymanager
COPY keep/contextmanager /app/keep/contextmanager
COPY keep/actions /app/keep/actions
COPY keep/step /app/keep/step
COPY keep/functions /app/keep/functions
COPY keep/exceptions /app/keep/exceptions
COPY keep/validation /app/keep/validation
COPY keep/throttles /app/keep/throttles
COPY keep/topologies /app/keep/topologies
COPY keep/conditions /app/keep/conditions
COPY keep/iohandler /app/keep/iohandler
COPY keep/searchengine /app/keep/searchengine
COPY keep/parser /app/keep/parser
COPY keep/event_subscriber /app/keep/event_subscriber
COPY keep/alembic.ini /app/keep/alembic.ini

# Service Specific
COPY keep/event_handler /app/keep/event_handler

# Enterprise Edition
COPY ee /app/ee

# Expose ports
# 8080 - Health check endpoint
# 8081 - Prometheus metrics
EXPOSE 8080 8081

# Default environment variables
ENV MESSAGING_TYPE=KAFKA \
    PROMETHEUS_METRICS_PORT=8081 \
    HEALTH_CHECK_PORT=8080

# Health check
# HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
#     CMD curl -f http://localhost:8080/health || exit 1

# Run the standalone consumer (no gunicorn)
CMD ["python", "-m", "keep.event_handler.consumer_main"]
