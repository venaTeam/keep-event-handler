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

Kubernetes probes (see create_health_server):
    /readyz  readiness — partitions assigned + recent poll (gates the rollout)
    /livez   liveness  — consume-loop heartbeat
"""
import json
import logging
import signal
import sys
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from dotenv import find_dotenv, load_dotenv
from prometheus_client import start_http_server
from src import logging_conf
from src.config.config import config
from src.core.db.db_on_start import abort_schema_wait
from src.core.consumer_health import consumer_health
from src.core.db.db_on_start import SchemaWaitAborted
from src.core.kafka_consumer import KafkaEventConsumer

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


class _ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """One thread per probe request, so a slow/blocked probe can't queue up
    behind another and make every probe time out at once."""

    daemon_threads = True
    # Probes reconnect constantly; don't sit in TIME_WAIT on restart.
    allow_reuse_address = True


def create_health_server(port: int):
    """
    Create the health-check HTTP server used by the Kubernetes probes.

    Exactly two endpoints, both JSON, both backed by real consumer state (see
    `src/core/consumer_health.py`). Anything else is a 404, so a probe aimed at
    the wrong path fails loudly instead of getting a meaningless 200:

    * ``/readyz`` — 200 only when the consume loop is running, partitions are
      assigned (or were revoked inside the rebalance grace window), and the last
      poll is recent. The event-handler takes no inbound HTTP traffic, so
      readiness gates the *rollout*: with ``maxUnavailable: 0`` / ``maxSurge: 1``
      it is what stops Kubernetes tearing down an old pod before the new one
      consumes. A ``startupProbe`` should point here too.
    * ``/livez`` — consume-loop heartbeat, *not* "the HTTP thread answers".
      Startup and shutdown always report alive. Keep `failureThreshold` high in
      the Deployment: an aggressive liveness on a consumer amplifies a rebalance
      storm instead of fixing it.

    Started **before** the blocking `init_services()`: connection-refused for
    the whole schema wait is what let the ~90 s prod liveness probe kill booting
    pods (CrashLoopBackOff).
    """

    def _payload(ok: bool, payload: dict) -> bytes:
        body = dict(payload)
        body["status"] = "ok" if ok else "unavailable"
        return json.dumps(body).encode("utf-8")

    class HealthHandler(BaseHTTPRequestHandler):
        # Probes are HTTP/1.1 clients; answering 1.0 forces a new connection per
        # check, which is fine and keeps the handler simple.
        protocol_version = "HTTP/1.0"

        def _respond(self, ok: bool, payload: dict):
            body = _payload(ok, payload)
            self.send_response(200 if ok else 503)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        ROUTES = {
            "/readyz": consumer_health.readiness,
            "/livez": consumer_health.liveness,
        }

        def do_GET(self):
            path = self.path.split("?", 1)[0].rstrip("/") or "/"
            probe = self.ROUTES.get(path)

            if probe is None:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()

                return

            try:
                self._respond(*probe())
            except Exception:
                # An unhandled raise here reads as connection-reset to kubelet,
                # i.e. a probe failure unrelated to the consumer's actual state.
                logger.exception("Health handler failed")
                self._respond(False, {"reason": "health handler error"})

        def log_message(self, format, *args):
            # Suppress access logs for health checks
            pass

    server = _ThreadingHTTPServer(("0.0.0.0", port), HealthHandler)

    def serve():
        logger.info(f"Health check server started on port {port}")
        server.serve_forever()

    thread = threading.Thread(target=serve, daemon=True, name="health-server")
    thread.start()
    return server


# Set when a shutdown signal arrives before the consumer takes over signal
# handling, so startup can bail instead of going on to join the consumer group
# moments before Kubernetes kills the pod.
_startup_shutdown = threading.Event()


def _install_startup_signal_handlers():
    """Make SIGTERM/SIGINT actionable during the *startup* phase.

    `KafkaEventConsumer.start()` installs its own handlers, but until it runs the
    process may be parked in `init_services()` waiting for the gateway to finish
    its migrations. Without this, a SIGTERM there either kills the process
    mid-wait or is ignored; with it, the schema wait wakes up immediately and the
    pod exits cleanly inside its grace period.
    """


    def _handler(signum, frame):
        logger.info(
            "Received signal %s during startup, aborting startup wait", signum
        )
        _startup_shutdown.set()
        consumer_health.mark_stopping(f"signal {signum} received during startup")
        abort_schema_wait()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, _handler)
        except (ValueError, OSError):
            # Not on the main thread / unsupported platform — non-fatal.
            logger.debug("Could not install startup handler for signal %s", sig)


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
        # Bring the probe endpoints up FIRST, before anything that can block.
        consumer_health.mark_starting("initializing services")
        create_health_server(health_port)

        # Start Prometheus metrics server (also useful during boot).
        start_metrics_server(metrics_port)

        # Signal handlers that cover the startup phase.
        _install_startup_signal_handlers()

        # Initialize services (DB schema wait, provisioning, ...).
        init_services()

        # Create and start Kafka consumer (blocking)
        if _startup_shutdown.is_set():
            # Signalled during init: don't join the consumer group just to be
            # killed — joining and leaving costs the group two rebalances.
            logger.info("Shutdown signalled during startup; not starting consumer")

            return

        consumer = KafkaEventConsumer()

        logger.info("Starting Kafka consumer loop (blocking)...")
        consumer.start()  # This blocks until shutdown signal

    except SchemaWaitAborted:
        logger.info("Startup aborted by shutdown signal; exiting cleanly")
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt, shutting down...")
    except Exception as e:
        logger.exception(f"Fatal error in event handler: {e}")
        consumer_health.mark_stopped(f"fatal error: {type(e).__name__}")
        sys.exit(1)
    finally:
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
