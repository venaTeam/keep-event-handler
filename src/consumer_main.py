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
import logging
import sys
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

from dotenv import find_dotenv, load_dotenv
from prometheus_client import start_http_server
from src import logging_conf
from src.config.config import config

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


def create_health_server(port: int):
    """
    Create a simple health check HTTP server.
    This can be used for K8s liveness/readiness probes.
    """
    class HealthHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path in ["/health", "/healthz", "/ready", "/"]:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status": "ok"}')
            else:
                self.send_response(404)
                self.end_headers()
        
        def log_message(self, format, *args):
            # Suppress access logs for health checks
            pass
    
    server = HTTPServer(("0.0.0.0", port), HealthHandler)
    
    def serve():
        logger.info(f"Health check server started on port {port}")
        server.serve_forever()
    
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return server


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
        # Step 1: Initialize services (DB, etc.)
        init_services()
        
        # Step 2: Start Prometheus metrics server
        start_metrics_server(metrics_port)
        
        # Step 3: Start health check server (for K8s probes)
        create_health_server(health_port)

        # Step 3.5: Start the automations trigger index (non-blocking).
        # After the metrics/health servers so the first hydrate attempt is
        # already scrapable, and before the blocking consume loop.
        _start_trigger_index_safely()

        # Step 4: Create and start Kafka consumer (blocking)
        from src.core.kafka_consumer import KafkaEventConsumer
        
        consumer = KafkaEventConsumer()
        
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
