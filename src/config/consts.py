import os
import enum
from src.config.config import config

class SecretManagerTypes(enum.Enum):
    FILE = "file"
    GCP = "gcp"
    K8S = "k8s"
    VAULT = "vault"
    AWS = "aws"
    DB = "db"


KEEP_ARQ_TASK_POOL = config("KEEP_ARQ_TASK_POOL", default="all")

KEEP_ARQ_TASK_POOL_ALL = "all"  # All arq workers enabled for this service
KEEP_ARQ_TASK_POOL_BASIC_PROCESSING = "basic_processing"  # Everything except AI
# Define queues for different task types
KEEP_ARQ_QUEUE_BASIC = "basic_processing"

AUTH_TYPE = "KEYCLOAK"
LOG_LEVEL = "DEBUG"
MAX_PROCESSING_RETRIES = 3

KAFKA_BOOTSTRAP_SERVERS = "localhost:29092"
KAFKA_TOPIC = "keep-events"
KAFKA_CONSUMER_GROUP = "keep-event-handler"
KAFKA_SECURITY_PROTOCOL = "PLAINTEXT"
KAFKA_SASL_MECHANISM = "PLAIN"
KAFKA_SASL_USERNAME = "admin"
KAFKA_SASL_PASSWORD = "admin"
KAFKA_SSL_CAFILE = None
KAFKA_SSL_CERTFILE = None
KAFKA_SSL_KEYFILE = None

ARQ_KEEP_RESULT = 3600
ARQ_EXPIRES = 3600

KEEP_OTEL_ENABLED= True

ENV_VAR_KEY = "KEEP_PROVIDERS"



# TODO: all for now deal with later
WATCHER_LAPSED_TIME = int(os.environ.get("KEEP_WATCHER_LAPSED_TIME", 60))

RUNNING_IN_CLOUD_RUN = os.environ.get("K_SERVICE") is not None
DB_CONNECTION_STRING = config("DATABASE_CONNECTION_STRING", default="postgresql://keep:keep@localhost:5432/keep")  # pylint: disable=invalid-name
DB_POOL_SIZE = config("DATABASE_POOL_SIZE", default=5, cast=int)  # pylint: disable=invalid-name
DB_MAX_OVERFLOW = config("DATABASE_MAX_OVERFLOW", default=10, cast=int)  # pylint: disable=invalid-name
DB_ECHO = config("DATABASE_ECHO", default=False, cast=bool)  # pylint: disable=invalid-name
KEEP_FORCE_CONNECTION_STRING = config(
    "KEEP_FORCE_CONNECTION_STRING", default=False, cast=bool
)  # pylint: disable=invalid-name
KEEP_DB_PRE_PING_ENABLED = config("KEEP_DB_PRE_PING_ENABLED", default=True, cast=bool)  # pylint: disable=invalid-name
DB_POOL_RECYCLE = config("DATABASE_POOL_RECYCLE", default=300, cast=int)  # pylint: disable=invalid-name
DB_POOL_TIMEOUT = config("DATABASE_POOL_TIMEOUT", default=10, cast=int)  # pylint: disable=invalid-name


KEEP_AUDIT_EVENTS_ENABLED = config("KEEP_AUDIT_EVENTS_ENABLED", cast=bool, default=True)

KEEP_FORCE_RESET_DEFAULT_PASSWORD = config(
    "KEEP_FORCE_RESET_DEFAULT_PASSWORD", default="false", cast=bool
)
DEFAULT_USERNAME = config("KEEP_DEFAULT_USERNAME", default="keep")
DEFAULT_PASSWORD = config("KEEP_DEFAULT_PASSWORD", default="keep")

TENANT_CONFIGURATION_RELOAD_TIME = config(
                "TENANT_CONFIGURATION_RELOAD_TIME", default=5, cast=int
            )

KEEP_CORRELATION_ENABLED = os.environ.get("KEEP_CORRELATION_ENABLED", "true") == "true"
MAINTENANCE_WINDOW_ALERT_STRATEGY = os.environ.get(
    "MAINTENANCE_WINDOW_STRATEGY", "default"
)  # recover_previous_status or default


ENRICHMENT_DISABLED = config("KEEP_ENRICHMENT_DISABLED", default="false", cast=bool)

KEEP_API_URL = config("KEEP_API_URL")

SECRET_MANAGER_TYPE = SecretManagerTypes[
                config("SECRET_MANAGER_TYPE", default="FILE").upper()
            ]

PROVIDERS_CACHE_FILE = os.environ.get("PROVIDERS_CACHE_FILE", "providers_cache.json")
READ_ONLY_MODE = config("KEEP_READ_ONLY", default="false") == "true"

VERIFY_SSL_CERT = config.get("K8S_VERIFY_SSL_CERT", cast=bool, default=True)
KEEP_READ_ONLY_BYPASS_KEY = config("KEEP_READ_ONLY_BYPASS_KEY", default="")

KEEP_STORE_PROVIDER_LOGS = config("KEEP_STORE_PROVIDER_LOGS", cast=bool, default=False)

KEEP_IMPERSONATION_ENABLED = (
            config("KEEP_IMPERSONATION_ENABLED", default="false") == "true"
        )
KEEP_IMPERSONATION_USER_HEADER = config(
            "KEEP_IMPERSONATION_USER_HEADER", default="X-KEEP-USER"
        )
KEEP_IMPERSONATION_ROLE_HEADER = config(
            "KEEP_IMPERSONATION_ROLE_HEADER", default="X-KEEP-ROLE"
        )
KEEP_IMPERSONATION_AUTO_PROVISION = (
            config("KEEP_IMPERSONATION_AUTO_PROVISION", default="false") == "true"
        )
KEEP_UPDATE_KEY_INTERVAL = config("KEEP_UPDATE_KEY_INTERVAL", default=60)
KEEP_READ_ONLY_BYPASS_KEY = config("KEEP_READ_ONLY_BYPASS_KEY", default="")
KEEP_CLOUDWATCH_DISABLE_API_KEY = config("KEEP_CLOUDWATCH_DISABLE_API_KEY", default=False)

KEEP_DEDUPLICATION_DISTRIBUTION_ENABLED = config("KEEP_DEDUPLICATION_DISTRIBUTION_ENABLED", default=True)
KEEP_CUSTOM_DEDUPLICATION_DISTRIBUTION_ENABLED = config("KEEP_CUSTOM_DEDUPLICATION_DISTRIBUTION_ENABLED", default=True)

# --- SC-04 consumer hardening (defaults reproduce the current baseline) ---

# SSE notify offload (extends PR #13's _sse_pool). Workers stays at 1 to
# preserve #13's strict-FIFO baseline.
SSE_NOTIFY_WORKERS = config("SSE_NOTIFY_WORKERS", default=1, cast=int)
# Max pending notify items before backpressure kicks in (replaces #13's
# hardcoded _SSE_MAX_PENDING).
SSE_NOTIFY_MAX_PENDING = config("SSE_NOTIFY_MAX_PENDING", default=1000, cast=int)
# Coalesce duplicate (tenant_id, event_type) notify signals while pending.
SSE_NOTIFY_COALESCE_ENABLED = config(
    "SSE_NOTIFY_COALESCE_ENABLED", default=True, cast=bool
)

# Batch consume. BATCH_SIZE=1 reproduces today's single-message loop exactly.
KAFKA_CONSUMER_BATCH_SIZE = config("KAFKA_CONSUMER_BATCH_SIZE", default=1, cast=int)
KAFKA_CONSUMER_BATCH_TIMEOUT_SECONDS = config(
    "KAFKA_CONSUMER_BATCH_TIMEOUT_SECONDS", default=1.0, cast=float
)

# Bounded, batch-wide retry budget.
KAFKA_RETRY_MAX_SLEEP_SECONDS = config(
    "KAFKA_RETRY_MAX_SLEEP_SECONDS", default=30, cast=int
)
# Abort remaining retries once elapsed since last poll reaches
# this fraction of max.poll.interval.ms, to avoid a rebalance.
KAFKA_RETRY_POLL_GAP_SAFETY_FACTOR = config(
    "KAFKA_RETRY_POLL_GAP_SAFETY_FACTOR", default=0.8, cast=float
)

# Error-storm guard for AlertRaw(error=True) writes.
KEEP_ERROR_STORM_WINDOW_SECONDS = config(
    "KEEP_ERROR_STORM_WINDOW_SECONDS", default=60, cast=int
)
KEEP_ERROR_STORM_MAX_PER_KEY = config(
    "KEEP_ERROR_STORM_MAX_PER_KEY", default=1, cast=int
)
KEEP_ERROR_GUARD_MAX_ENTRIES = config(
    "KEEP_ERROR_GUARD_MAX_ENTRIES", default=10000, cast=int
)

# --- Automations trigger index (B4) ---------------------------------------
# The matcher hydrates the gateway-owned `automations` table from the SAME
# database this service already reads (DATABASE_CONNECTION_STRING above), so
# there is no DSN to configure here. Only intervals, caps and Redis.
#
# Every interval is clamped at read time in src/bl/automations/settings.py:
# config() performs no validation and accepts a literal "0", which would turn
# the reload timer into a hot loop -- a pure-Python thread spinning against the
# GIL steals time from the single synchronous Kafka consumer thread. Precedent
# for the clamp: kafka_consumer.py's `max(1, KAFKA_CONSUMER_BATCH_SIZE)`.
AUTOMATION_INDEX_RELOAD_SECONDS = config(
    "AUTOMATION_INDEX_RELOAD_SECONDS", default=30, cast=int
)
# +/- this fraction, so N replicas don't stampede the shared pool in lockstep
# after a rolling restart.
AUTOMATION_INDEX_RELOAD_JITTER_FRACTION = config(
    "AUTOMATION_INDEX_RELOAD_JITTER_FRACTION", default=0.1, cast=float
)
# Collapses a burst of `reload` publishes into one hydrate.
AUTOMATION_INDEX_RELOAD_DEBOUNCE_SECONDS = config(
    "AUTOMATION_INDEX_RELOAD_DEBOUNCE_SECONDS", default=0.5, cast=float
)
# Wall-clock floor between ANY two hydrates. Debounce coalesces a burst; only
# this bounds a sustained publish rate. The `reload` channel is unauthenticated
# and the database it hydrates against is the one serving alert ingestion.
AUTOMATION_INDEX_MIN_HYDRATE_INTERVAL_SECONDS = config(
    "AUTOMATION_INDEX_MIN_HYDRATE_INTERVAL_SECONDS", default=5, cast=int
)
AUTOMATION_INDEX_BOOT_RETRY_SECONDS = config(
    "AUTOMATION_INDEX_BOOT_RETRY_SECONDS", default=5, cast=int
)
AUTOMATION_INDEX_SHUTDOWN_TIMEOUT_SECONDS = config(
    "AUTOMATION_INDEX_SHUTDOWN_TIMEOUT_SECONDS", default=3, cast=int
)
AUTOMATION_INDEX_STATEMENT_TIMEOUT_MS = config(
    "AUTOMATION_INDEX_STATEMENT_TIMEOUT_MS", default=10000, cast=int
)

# Caps. A defect in one row skips that row; a condition that indicts the whole
# result set refuses the swap. Never truncate -- a silently truncated index is
# a set of automations that stop firing with no signal.
AUTOMATION_INDEX_MAX_ROWS = config(
    "AUTOMATION_INDEX_MAX_ROWS", default=2000, cast=int
)
AUTOMATION_INDEX_MAX_VALUE_BYTES = config(
    "AUTOMATION_INDEX_MAX_VALUE_BYTES", default=512, cast=int
)
AUTOMATION_INDEX_MAX_TOTAL_BYTES = config(
    "AUTOMATION_INDEX_MAX_TOTAL_BYTES", default=8 * 1024 * 1024, cast=int
)

# Empty is a defined, quiet degradation: the reload worker still runs on its
# timer, only sub-second convergence is lost. Not an off switch.
REDIS_URL = config("REDIS_URL", default="")
AUTOMATION_RELOAD_CHANNEL = config("AUTOMATION_RELOAD_CHANNEL", default="reload")
AUTOMATION_PUBSUB_RECONNECT_MAX_BACKOFF_SECONDS = config(
    "AUTOMATION_PUBSUB_RECONNECT_MAX_BACKOFF_SECONDS", default=30, cast=int
)
