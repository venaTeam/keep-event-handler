KEEP_ARQ_TASK_POOL_ALL = "all"  # All arq workers enabled for this service
KEEP_ARQ_TASK_POOL_BASIC_PROCESSING = "basic_processing"  # Everything except AI
# Define queues for different task types
KEEP_ARQ_QUEUE_BASIC = "basic_processing"

AUTH_TYPE = "KEYCLOAK"
LOG_LEVEL = "DEBUG"
MAX_PROCESSING_RETRIES = 3

KAFKA_BOOTSTRAP_SERVERS = "kafka:9092"
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