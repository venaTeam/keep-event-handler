KEEP_ARQ_TASK_POOL_ALL = "all"  # All arq workers enabled for this service
KEEP_ARQ_TASK_POOL_BASIC_PROCESSING = "basic_processing"  # Everything except AI
# Define queues for different task types
KEEP_ARQ_QUEUE_BASIC = "basic_processing"

REDIS = os.environ.get("REDIS", "false") == "true"

if REDIS:
    KEEP_ARQ_TASK_POOL = os.environ.get("KEEP_ARQ_TASK_POOL", KEEP_ARQ_TASK_POOL_ALL)
else:
    KEEP_ARQ_TASK_POOL = os.environ.get("KEEP_ARQ_TASK_POOL", None)


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


MESSAGING_TYPE = "KAFKA"

WATCHER_LAPSED_TIME = int(os.environ.get("KEEP_WATCHER_LAPSED_TIME", 60))
ARQ_KEEP_RESULT = 3600
ARQ_EXPIRES = 3600

KEEP_OTEL_ENABLED= True