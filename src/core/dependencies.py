import logging

from fastapi import Request
from fastapi.datastructures import FormData

logger = logging.getLogger(__name__)


# Just a fake random tenant id
SINGLE_TENANT_UUID = "keep"
SINGLE_TENANT_EMAIL = "admin@keephq"


async def extract_generic_body(request: Request) -> dict | bytes | FormData:
    """
    Extracts the body of the request based on the content type.

    Args:
        request (Request): The request object.

    Returns:
        dict | bytes | FormData: The body of the request.
    """
    content_type = request.headers.get("Content-Type")
    if content_type == "application/x-www-form-urlencoded":
        return await request.form()
    elif isinstance(content_type, str) and content_type.startswith(
        "multipart/form-data"
    ):
        return await request.form()
    else:
        try:
            return await request.json()
        except Exception:
            if isinstance(content_type, str) and content_type.startswith(
                "application/json"
            ):
                logger.warning(
                    "Failed to parse body as json, returning raw body",
                    extra={"content_type": content_type},
                )
            else:
                logger.debug("Failed to parse body as json, returning raw body")
            return await request.body()