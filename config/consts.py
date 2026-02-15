import os
import enum
from config.config import config

class SecretManagerTypes(enum.Enum):
    FILE = "file"
    GCP = "gcp"
    K8S = "k8s"
    VAULT = "vault"
    AWS = "aws"
    DB = "db"


# TODO: check
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
DB_CONNECTION_STRING = config("DATABASE_CONNECTION_STRING", default=None)  # pylint: disable=invalid-name
DB_POOL_SIZE = config("DATABASE_POOL_SIZE", default=5, cast=int)  # pylint: disable=invalid-name
DB_MAX_OVERFLOW = config("DATABASE_MAX_OVERFLOW", default=10, cast=int)  # pylint: disable=invalid-name
DB_ECHO = config("DATABASE_ECHO", default=False, cast=bool)  # pylint: disable=invalid-name
KEEP_FORCE_CONNECTION_STRING = config(
    "KEEP_FORCE_CONNECTION_STRING", default=False, cast=bool
)  # pylint: disable=invalid-name
KEEP_DB_PRE_PING_ENABLED = config("KEEP_DB_PRE_PING_ENABLED", default=False, cast=bool)  # pylint: disable=invalid-name


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
