import enum
import logging


logger = logging.getLogger(__name__)


class IdentityManagerTypes(enum.Enum):
    """
    Enum class representing different types of identity managers.
    """

    AUTH0 = "auth0"
    KEYCLOAK = "keycloak"
    OKTA = "okta"
    ONELOGIN = "onelogin"
    DB = "db"
    NOAUTH = "noauth"
    OAUTH2PROXY = "oauth2proxy"