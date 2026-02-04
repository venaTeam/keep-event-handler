import logging
import uvicorn
from fastapi import FastAPI
from dotenv import find_dotenv, load_dotenv
from prometheus_fastapi_instrumentator import Instrumentator

import logging_conf
# TODO: remove 
import keep.common.observability
from config.consts import KEEP_OTEL_ENABLED
from api.routes.v1 import health, metrics
from core.lifespan import lifespan

# Load environment variables
load_dotenv(find_dotenv())
logging_conf.setup_logging()
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Keep Event Handler",
    description="Microservice for handling background tasks and events",
    lifespan=lifespan,
)

# Include routers
app.include_router(health.router, prefix="/v1", tags=["health"])
app.include_router(metrics.router, prefix="/v1", tags=["metrics"])
# For backward compatibility / ease of use, logic at root is also handled in health router via @router.get("/")
app.include_router(health.router, tags=["root"])

if bool(KEEP_OTEL_ENABLED):
    keep.common.observability.setup(app)

Instrumentator(
    excluded_handlers=["/metrics", "/health"],
    should_group_status_codes=False,
).instrument(app=app, metric_namespace="keep")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
