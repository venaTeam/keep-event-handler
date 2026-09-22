import enum
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.dialects.mssql import DATETIME2 as MSSQL_DATETIME2
from sqlalchemy.dialects.mysql import DATETIME as MySQL_DATETIME
from sqlalchemy.engine.url import make_url
from sqlmodel import DateTime

from src.config.consts import RUNNING_IN_CLOUD_RUN, DB_CONNECTION_STRING

logger = logging.getLogger(__name__)

# We want to include the deleted_at field in the primary key,
# but we also want to allow it to be nullable. MySQL doesn't allow nullable fields in primary keys, so:
NULL_FOR_DELETED_AT = datetime(1000, 1, 1, 0, 0)


class DismissMode(enum.Enum):
    """How a dismissal ends. Shared by alerts (LastAlert) and incidents, which
    model dismissal identically.

    Mirrors keep-api-gateway's `src/models/db/helpers.py`. The two services read
    and write the same columns in the same database, so these values and the
    predicate below must agree exactly — a divergence shows up as one service
    considering an alert suppressed while the other does not.
    """

    # Only an explicit status change lifts it
    PERMANENT = "permanent"
    # Lifts on its own once `dismissed_until` passes
    DISMISS_UNTIL = "dismiss_until"


def is_dismiss_active(
    dismiss_mode: Optional[str],
    dismissed_until: Optional[datetime],
    now: Optional[datetime] = None,
) -> bool:
    """Whether a dismissal is in force right now.

    The one definition of "dismissed", for both alerts and incidents.
    Suppression is DERIVED from these two columns rather than stored as a status,
    so a time-boxed dismissal lapses on its own clock — nothing sweeps the tables,
    which means no reader may trust a stored status to tell it this.
    """
    if dismiss_mode == DismissMode.PERMANENT.value:
        return True

    if dismiss_mode == DismissMode.DISMISS_UNTIL.value:
        if dismissed_until is None:
            return False
        # The column is timezone-aware, but SQLite round-trips it naive; assume
        # UTC there so the comparison below cannot raise.
        deadline = dismissed_until
        if deadline.tzinfo is None:
            deadline = deadline.replace(tzinfo=timezone.utc)
        return deadline > (now or datetime.now(timezone.utc))

    return False


def suppressed_if_dismiss_active_sql(table: str) -> str:
    """SQL twin of `is_dismiss_active`: yields 'suppressed' while a dismissal is
    in force and NULL otherwise, so it can head a COALESCE chain and fall through
    when it is not.

    CURRENT_TIMESTAMP rather than NOW() because this string is emitted verbatim
    into whichever dialect is configured, and SQLite has no NOW().
    """
    return (
        "CASE"
        f" WHEN {table}.dismiss_mode = '{DismissMode.PERMANENT.value}'"
        " THEN 'suppressed'"
        f" WHEN {table}.dismiss_mode = '{DismissMode.DISMISS_UNTIL.value}'"
        f" AND {table}.dismissed_until > CURRENT_TIMESTAMP THEN 'suppressed'"
        " ELSE NULL END"
    )

# managed (mysql)
if RUNNING_IN_CLOUD_RUN or DB_CONNECTION_STRING == "impersonate":
    # Millisecond precision
    DATETIME_COLUMN_TYPE = MySQL_DATETIME(fsp=3)
# self hosted (mysql, sql server, sqlite / postgres)
else:
    try:
        url = make_url(DB_CONNECTION_STRING)
        dialect = url.get_dialect().name
        if dialect == "mssql":
            # Millisecond precision
            DATETIME_COLUMN_TYPE = MSSQL_DATETIME2(precision=3)
        elif dialect == "mysql":
            # Millisecond precision
            DATETIME_COLUMN_TYPE = MySQL_DATETIME(fsp=3)
        else:
            DATETIME_COLUMN_TYPE = DateTime
    except Exception:
        logger.warning(
            "Could not determine the database dialect, falling back to default datetime column type"
        )
        # give it a default
        DATETIME_COLUMN_TYPE = DateTime
