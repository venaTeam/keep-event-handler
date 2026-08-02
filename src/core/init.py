import logging
import os

from src.alert_deduplicator.deduplication_rules_provisioning import (
    provision_deduplication_rules_from_env,
)
from src.core.db.db_on_start import migrate_db, try_create_single_tenant
from src.core.dependencies import SINGLE_TENANT_UUID
from src.core.tenant_configuration import TenantConfiguration
from src.identitymanager.identitymanagerfactory import IdentityManagerTypes
from src.providers.providers_factory import ProvidersFactory
from src.providers.providers_service import ProvidersService

logger = logging.getLogger(__name__)

# keep-api-gateway owns the schema and owns provisioning. Defaulting to false
# keeps provisioning off the consumer's critical path: otherwise all 15 consumer
# pods provision providers + dedup rules concurrently against the same DB while
# the gateway does the same, delaying consumption and turning a bad provider in
# a new image into a startup crash on every pod. Set true for a standalone/dev
# deployment with no gateway.
PROVISION_RESOURCES = os.environ.get("PROVISION_RESOURCES", "false") == "true"
# Provisioning is best-effort by default: a provisioning failure must not stop a
# consumer from consuming. Set KEEP_PROVISIONING_FATAL=true to get the old
# fail-fast behaviour (useful in CI, where a bad provider file should fail loud).
PROVISIONING_FATAL = os.environ.get("KEEP_PROVISIONING_FATAL", "false") == "true"


def provision_resources(provision_dashboards_func=None):
    if not PROVISION_RESOURCES:
        logger.info(
            "Provisioning resources is disabled (keep-api-gateway owns "
            "provisioning; set PROVISION_RESOURCES=true to override)"
        )
        return

    # Each step is independently guarded: all are idempotent, so a failure in
    # one must not skip the others or stop the consume loop from starting.
    steps = [
        (
            "providers",
            lambda: ProvidersService.provision_providers(SINGLE_TENANT_UUID),
        ),
    ]
    if provision_dashboards_func:
        steps.append(
            ("dashboards", lambda: provision_dashboards_func(SINGLE_TENANT_UUID))
        )
    steps.append(
        (
            "deduplication rules",
            lambda: provision_deduplication_rules_from_env(SINGLE_TENANT_UUID),
        )
    )

    for name, step in steps:
        logger.info("Provisioning %s", name)
        try:
            step()
            logger.info("%s provisioned successfully", name)
        except Exception:
            if PROVISIONING_FATAL:
                raise
            logger.exception(
                "Failed to provision %s — continuing startup (set "
                "KEEP_PROVISIONING_FATAL=true to fail fast instead)",
                name,
            )


def init_services(auth_type: str, provision_dashboards_func=None, skip_ngrok=False):
    """
    Common initialization logic for Keep services.
    """
    logger.info("Keep server starting")

    migrate_db()

    # Load this early and use preloading
    ProvidersFactory.get_all_providers()
    # Load tenant configuration early
    TenantConfiguration()

    # Create single tenant if it doesn't exist
    if auth_type in [
        IdentityManagerTypes.DB.value,
        IdentityManagerTypes.NOAUTH.value,
        IdentityManagerTypes.OAUTH2PROXY.value,
        IdentityManagerTypes.ONELOGIN.value,
        "no_auth",  # backwards compatibility
        "single_tenant",  # backwards compatibility
    ]:
        excluded_from_default_user = [
            IdentityManagerTypes.OAUTH2PROXY.value,
            IdentityManagerTypes.ONELOGIN.value,
        ]
        # for oauth2proxy, we don't want to create the default user
        try_create_single_tenant(
            SINGLE_TENANT_UUID,
            create_default_user=(
                False if auth_type in excluded_from_default_user else True
            ),
        )

    provision_resources(provision_dashboards_func)

    if not skip_ngrok and os.environ.get("USE_NGROK", "false") == "true":
        try:
            from pyngrok import ngrok
            from pyngrok.conf import PyngrokConfig

            PORT = int(os.environ.get("PORT", 8080))
            ngrok_config = PyngrokConfig(
                auth_token=os.environ.get("NGROK_AUTH_TOKEN", None)
            )
            # If you want to use a custom domain, set the NGROK_DOMAIN & NGROK_AUTH_TOKEN environment variables
            # read https://ngrok.com/blog-post/free-static-domains-ngrok-users -> https://dashboard.ngrok.com/cloud-edge/domains
            ngrok_connection = ngrok.connect(
                PORT,
                pyngrok_config=ngrok_config,
                domain=os.environ.get("NGROK_DOMAIN", None),
            )
            public_url = ngrok_connection.public_url
            logger.info(f"ngrok tunnel: {public_url}")
            os.environ["KEEP_API_URL"] = public_url
        except ImportError:
            logger.warning("pyngrok not installed, skipping ngrok initialization")
        except Exception as e:
            logger.warning(f"Failed to initialize ngrok: {e}")

    logger.info("Keep server started")
