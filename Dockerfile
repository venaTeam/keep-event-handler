FROM python:3.11.6-slim as base

ENV PYTHONFAULTHANDLER=1 \
    PYTHONHASHSEED=random \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Creating a virtual environment and installing dependencies
ENV PIP_DEFAULT_TIMEOUT=100 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    POETRY_VERSION=1.3.2 \
    PYTHON_KEYRING_BACKEND=keyring.backends.null.Keyring

RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

RUN pip install "poetry==$POETRY_VERSION"
RUN python -m venv /venv
COPY pyproject.toml poetry.lock ./
RUN . /venv/bin/activate && poetry install --no-root

# Setting the virtual environment path
ENV PYTHONPATH="/app:${PYTHONPATH}"
ENV PATH="/venv/bin:${PATH}"
ENV VIRTUAL_ENV="/venv"


# Copy application code
COPY alert_deduplicator /app/alert_deduplicator
COPY api /app/api
COPY bl /app/bl
COPY config /app/config
COPY contextmanager /app/contextmanager
COPY controllers /app/controllers
COPY core /app/core
COPY event_managment /app/event_managment
COPY event_subscriber /app/event_subscriber
COPY functions /app/functions
COPY identitymanager /app/identitymanager
COPY models /app/models
COPY parser /app/parser
COPY providers /app/providers
COPY rulesengine /app/rulesengine
COPY secretmanager /app/secretmanager
COPY utils /app/utils
COPY *.py /app/
COPY __init__.py /app/__init__.py

# Worker command
# We use Gunicorn with Uvicorn workers for production stability
# The number of workers is controlled by KEEP_EVENT_WORKERS env var (default in config or here)
CMD ["sh", "-c", "gunicorn main:app --bind 0.0.0.0:8080 --workers ${KEEP_EVENT_WORKERS:-1} --worker-class uvicorn.workers.UvicornWorker --timeout 120"]
