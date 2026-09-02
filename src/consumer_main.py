#!/usr/bin/env python3
"""
Standalone Kafka consumer entrypoint for the event handler service.

This script runs the Kafka consumer in a synchronous loop without gunicorn.
Prometheus metrics are exposed via start_http_server on a separate thread.

Usage:
    python -m keep.event_handler.consumer_main
    
Environment Variables:
    KAFKA_BOOTSTRAP_SERVERS: Kafka broker addresses (default: localhost:9092)
    KAFKA_TOPIC: Topic to consume from (default: keep-events)
    KAFKA_CONSUMER_GROUP: Consumer group ID (default: keep-event-handler)
    PROMETHEUS_METRICS_PORT: Port for Prometheus metrics (default: 8081)
    HEALTH_CHECK_PORT: Port for health checks (default: 8080)
    LOG_LEVEL: Logging level (default: INFO)
"""
import json
import logging
import signal
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from dotenv import find_dotenv, load_dotenv
from prometheus_client import start_http_server
from src import logging_conf
from src.bl.automations.producer import get_matched_producer
from src.config.config import config
from src.core.consumer_health import consumer_health

# Load environment variables before any other imports
load_dotenv(find_dotenv())
logging_conf.setup_logging()

logger = logging.getLogger(__name__)


def init_services():
    """Initialize database and other required services."""
    logger.info("Initializing services...")
    from src.core.init import init_services as _init_services
    
    auth_type = config("AUTH_TYPE", default="noauth")
    _init_services(auth_type=auth_type, skip_ngrok=True)
    logger.info("Services initialized successfully")


def start_metrics_server(port: int):
    """Start Prometheus metrics HTTP server in a background thread."""
    logger.info(f"Starting Prometheus metrics server on port {port}")
    
    # start_http_server runs in a daemon thread by default
    start_http_server(port)
    
    logger.info(f"Prometheus metrics available at http://0.0.0.0:{port}/metrics")


READINESS_PATHS = ("/readyz",)
# `/`, `/health`, `/healthz` and `/ready` are LEGACY ALIASES and load-bearing:
# production probes target `/`. Serving only /livez would 404 there and kill
# every pod the moment this image landed, with no chart change to revert.
#
# `/ready` is deliberately in the LIVENESS set even though its name suggests
# otherwise. It used to answer an unconditional 200, so any existing probe
# pointing at it -- including a liveness probe -- must keep passing during the
# schema wait. Giving it real readiness semantics would kill every pod on an
# image-only deploy: exactly the outage these aliases exist to prevent. Real
# readiness is /readyz only.
LIVENESS_PATHS = ("/livez", "/", "/health", "/healthz", "/ready")


def create_health_server(port: int):
    """
    Create the K8s probe server.

    Two behaviours behind six paths, both backed by real consumer state:
      readiness -- consuming, partitions assigned (or inside the revoke grace),
                   recent poll. This is what gates the rollout.
      liveness  -- the consume loop is still polling. Green while starting or
                   draining, so a slow schema wait is never killed.
    """
    class HealthHandler(BaseHTTPRequestHandler):
        def _respond(self, ok: bool, reason: str, probe: str):
            body = json.dumps(
                {
                    "status": "ok" if ok else "unhealthy",
                    "probe": probe,
                    "reason": reason,
                    **consumer_health.snapshot(),
                }
            ).encode()
            self.send_response(200 if ok else 503)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path in READINESS_PATHS:
                ok, reason = consumer_health.is_ready()
                try:
                    producer_ok, producer_reason = get_matched_producer().health()
                    if not producer_ok:
                        logger.warning(
                            "Readiness failed: matched producer is unhealthy (%s)",
                            producer_reason,
                        )
                        ok, reason = False, producer_reason
                except Exception:
                    logger.exception("Matched producer readiness check failed")
                    ok, reason = False, "matched producer health check failed"
                self._respond(ok, reason, "readiness")
            elif path in LIVENESS_PATHS:
                ok, reason = consumer_health.is_live()
                self._respond(ok, reason, "liveness")
            else:
                self.send_response(404)
                self.end_headers()

        # A client that opens a socket and never finishes its request line
        # would otherwise wedge a single-threaded server forever -- and with
        # both probes served here, that kills a perfectly healthy consumer.
        timeout = 5

        def log_message(self, format, *args):
            # Suppress access logs for health checks
            pass

    server = ThreadingHTTPServer(("0.0.0.0", port), HealthHandler)
    server.daemon_threads = True
    
    def serve():
        logger.info(f"Health check server started on port {port}")
        server.serve_forever()
    
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return server


_startup_shutdown = threading.Event()


def _install_startup_signal_handlers():
    """Handle SIGTERM/SIGINT during the pre-consume phase.

    The schema wait now retries indefinitely, so without this a pod told to
    terminate while the gateway is still migrating would ignore the signal
    until the kubelet SIGKILLed it. KafkaEventConsumer.start() replaces these
    handlers with its own once the consume loop owns the process.

    The db import is deferred: importing it at module scope would build the DB
    engine before the probe server binds, which is the ordering this file
    exists to avoid.
    """

    def handler(signum, frame):
        logger.info("Received signal %s during startup; aborting startup", signum)
        _startup_shutdown.set()
        try:
            from src.core.db.db_on_start import request_schema_wait_abort

            request_schema_wait_abort()
        except Exception:
            logger.exception("Failed to abort the schema wait")

    signal.signal(signal.SIGTERM, handler)
    signal.signal(signal.SIGINT, handler)


def _start_trigger_index_safely():
    """Start the automations trigger index without ever risking the consumer.

    The IMPORT is inside the try, not just the call. main()'s `except Exception`
    calls sys.exit(1), so a bare module-level import of the new package would
    let any import-time error -- a missing redis wheel, a bad
    PROMETHEUS_MULTIPROC_DIR, a typo -- crashloop the entire alert-ingestion
    consumer. That is precisely the outcome fail-open exists to prevent: the
    index degrading must never be able to stop alerts flowing.
    """
    try:
        from src.bl.automations.reloader import start_trigger_index

        if start_trigger_index():
            logger.info("Automations trigger index started")
        else:
            logger.info(
                "Automations trigger index is switched off "
                "(AUTOMATION_INDEX_ENABLED); alerts are processed as before"
            )
    except Exception:
        logger.exception(
            "Failed to start the automations trigger index; "
            "alert processing continues without automation matching"
        )


def _stop_trigger_index_safely():
    """Stop it, in its own try so it can never mask the SSE pool flush."""
    try:
        from src.bl.automations.reloader import stop_trigger_index

        stop_trigger_index()
    except Exception:
        logger.exception("Failed to stop the automations trigger index")


def _start_matched_producer_safely():
    try:
        producer = get_matched_producer()
        if not producer.start():
            logger.error("Matched producer is not ready; /readyz remains unhealthy")
    except Exception:
        logger.exception("Failed to start matched producer")


def _stop_matched_producer_safely():
    try:
        get_matched_producer().stop()
    except Exception:
        logger.exception("Failed to stop matched producer")


def main():
    """Main entrypoint for the Kafka consumer service."""
    logger.info("=" * 60)
    logger.info("Starting Keep Event Handler - Kafka Consumer")
    logger.info("=" * 60)
    
    # Get configuration
    messaging_type = config("MESSAGING_TYPE", default="KAFKA").upper()
    metrics_port = int(config("PROMETHEUS_METRICS_PORT", default="8094"))
    health_port = int(config("HEALTH_CHECK_PORT", default="8092"))
    
    if messaging_type != "KAFKA":
        logger.error(f"This entrypoint only supports KAFKA messaging, got: {messaging_type}")
        logger.error("For Redis/ARQ, use the FastAPI-based entrypoint (main.py with gunicorn)")
        sys.exit(1)
    
    try:
        # Step 1: Start the metrics and probe servers BEFORE anything blocking.
        #
        # This ordering is the fix for the startup CrashLoop. init_services()
        # blocks on the schema wait, which during a full ArgoCD sync runs for
        # minutes while keep-api-gateway is itself rolling. Binding the probe
        # server after it meant kubelet got connection-refused for that entire
        # window, and the production liveness probe (initialDelay 60 +
        # failureThreshold 3 x period 10) killed the pod at ~90s -- always
        # before the internal schema-wait timeout could even be reached.
        # Bound first, the pod answers "alive, not ready" and the startupProbe
        # budget is what decides whether to give up on it.
        _install_startup_signal_handlers()
        start_metrics_server(metrics_port)
        create_health_server(health_port)

        # Step 2: Initialize services (DB, etc.) -- blocking, and slow by
        # design while the gateway's migrations settle.
        try:
            init_services()
        except BaseException:
            if _startup_shutdown.is_set():
                # An aborted schema wait raises rather than returning, so
                # nothing downstream runs against an unverified schema. A
                # deliberate terminate must still exit 0, not look like a crash.
                logger.info(
                    "Startup aborted by a shutdown signal; exiting cleanly"
                )
                return
            raise

        if _startup_shutdown.is_set():
            logger.info(
                "Shutdown requested during startup; exiting before the "
                "consume loop"
            )
            return

        # Step 3: Start the automations trigger index (non-blocking).
        # After init_services because hydration reads the shared schema, and
        # before the blocking consume loop.
        _start_trigger_index_safely()
        _start_matched_producer_safely()

        # Step 4: Create and start Kafka consumer (blocking)
        from src.core.kafka_consumer import KafkaEventConsumer
        
        # Hand over the startup event: a SIGTERM that landed between the check
        # above and the consumer installing its own handlers would otherwise be
        # lost, and the pod would run until SIGKILL.
        consumer = KafkaEventConsumer(shutdown_event=_startup_shutdown)

        logger.info("Starting Kafka consumer loop (blocking)...")
        consumer.start()  # This blocks until shutdown signal
        
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt, shutting down...")
    except Exception as e:
        logger.exception(f"Fatal error in event handler: {e}")
        sys.exit(1)
    finally:
        # Ordering is load-bearing: the trigger index stop is BOUNDED, while
        # shutdown_sse_pool wraps ThreadPoolExecutor.shutdown, which takes no
        # timeout on 3.11 and is genuinely unbounded. Stopping the bounded half
        # first guarantees it completes inside the k8s grace period even when
        # the SSE flush hangs.
        _stop_trigger_index_safely()
        _stop_matched_producer_safely()

        # Flush any pending SSE notifications queued on the background pool so
        # they aren't lost on a graceful shutdown of the standalone consumer.
        try:
            from src.event_management.process_event_task import shutdown_sse_pool

            shutdown_sse_pool(wait=True)
        except Exception:
            logger.exception("Failed to shutdown SSE notify pool")
        logger.info("Event handler shutdown complete")


if __name__ == "__main__":
    main()
