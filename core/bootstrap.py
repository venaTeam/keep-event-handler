import asyncio
import logging
import os
import sys

from config.consts import 
    KEEP_ARQ_QUEUE_BASIC,
    KEEP_ARQ_TASK_POOL,
    KEEP_ARQ_TASK_POOL_ALL,
    KEEP_ARQ_TASK_POOL_BASIC_PROCESSING,
    AUTH_TYPE,
    LOG_LEVEL


from core.init import init_services

logger = logging.getLogger(__name__)


class Bootstrap:
    @staticmethod
    async def get_instance():
        return Bootstrap()

    async def run_on_starting(self):
        """Runs the legacy on_starting hooks in a separate thread."""
        try:
            # TODO: get rid of import
            # Default to noauth if not specified
            auth_type = A

            def on_starting_helper():
                # Create a new event loop for this thread
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    # Pass skip_ngrok=True to avoid trying to start ngrok in event handler
                    init_services(auth_type=auth_type, skip_ngrok=True)
                finally:
                    loop.close()

            logger.info("Running application initialization (on_starting)")
            # Run sync on_starting in a separate thread to avoid "loop already running" issues with Alembic/SQLAlchemy
            await asyncio.to_thread(on_starting_helper)
            logger.info("Application initialization complete")
        except Exception as e:
            logger.exception("Failed to run application initialization")
            # We might want to crash here, but legacy behavior was just log?
            # Review plan suggested crashing if vital, but lets stick to current behavior + cleanup
            raise e

   

    async def run_arq_worker(self, worker_id, number_of_errors_before_restart=0):
        print(f"DEBUG: run_arq_worker started for {worker_id}")
        logger.info(f"Starting ARQ Worker {worker_id} (PID: {os.getpid()})")

        queue_name = self._determine_queue_name()
        if not queue_name:
            logger.info("No task pools configured to run - exiting")
            sys.exit(1)

        self._apply_debug_patches()

        # Get and run the ARQ worker
        logger.info(f"Getting ARQ worker for queue {queue_name}")
        worker = get_arq_worker(queue_name)
        logger.info("Starting safe_run_worker")
        await safe_run_worker(
            worker, number_of_errors_before_restart=number_of_errors_before_restart
        )
        logger.info(f"ARQ Worker {worker_id} finished")

    def _determine_queue_name(self):
        if not KEEP_ARQ_TASK_POOL:
            return KEEP_ARQ_TASK_POOL_ALL
        elif KEEP_ARQ_TASK_POOL in [
            KEEP_ARQ_TASK_POOL_ALL,
            KEEP_ARQ_TASK_POOL_BASIC_PROCESSING,
        ]:
            return KEEP_ARQ_QUEUE_BASIC
        else:
            raise ValueError(f"Invalid task pool: {KEEP_ARQ_TASK_POOL}")

    def _apply_debug_patches(self):
        if LOG_LEVEL == "DEBUG":
            logger.info("Applying ARQ debug patches")
            # Legacy logic placeholder
