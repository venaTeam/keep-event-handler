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

PROVISION_RESOURCES = os.environ.get("PROVISION_RESOURCES", "true") == "true"
# Provisioning writes provider definitions and dedup rules from env vars into
# the DB before the consumer starts consuming. A malformed provider definition
# in a new image therefore CrashLooped EVERY consumer pod, over configuration
# that has nothing to do with consuming. Failures are now logged and stepped
# over; set this true in CI, where a bad provider file should fail loudly.
KEEP_PROVISIONING_FATAL = os.environ.get("KEEP_PROVISIONING_FATAL", "false") == "true"


def _provisioning_step(name: str, func, *args):
    """Run one provisioning step. Each is guarded independently so a failing
    step neither skips the others nor stops the consume loop."""
    try:
        func(*args)
        logger.info("Provisioning step '%s' completed", name)
    except Exception:
        if KEEP_PROVISIONING_FATAL:
            logger.exception(
                "Provisioning step '%s' failed and KEEP_PROVISIONING_FATAL is "
                "set — failing startup",
                name,
            )
            raise
        logger.exception(
            "Provisioning step '%s' failed; continuing without it. Alert "
            "processing is unaffected.",
            name,
        )


def provision_resources(provision_dashboards_func=None):
    if PROVISION_RESOURCES:
        logger.info("Provisioning providers, dashboards and deduplication rules")
        _provisioning_step(
            "providers", ProvidersService.provision_providers, SINGLE_TENANT_UUID
        )
        if provision_dashboards_func:
            _provisioning_step(
                "dashboards", provision_dashboards_func, SINGLE_TENANT_UUID
            )
        _provisioning_step(
            "deduplication_rules",
            provision_deduplication_rules_from_env,
            SINGLE_TENANT_UUID,
        )
    else:
        logger.info("Provisioning resources is disabled")


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
