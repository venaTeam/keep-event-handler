import os
import logging
import requests
from config.consts import KEEP_API_URL
import os
import logging

from fastapi import Request
from fastapi.datastructures import FormData

logger = logging.getLogger(__name__)
# TODO: maybe change to const
SINGLE_TENANT_UUID = "keep"

# TODO: make sure i have the env variables




def notify_sse(tenant_id: str, event: str, data: dict | list) -> None:
    """Send SSE notification to API gateway."""
    try:
        api_url = KEEP_API_URL or "http://localhost:8080"
            
        url = f"{api_url}/sse/notify"
        payload = {
            "tenant_id": tenant_id,
            "event": event,
            "data": data
        }
        
        response = requests.post(url, json=payload, timeout=5)
        if not response.ok:
            logger.warning(f"Failed to send SSE notification. Status: {response.status_code}")
    except Exception as e:
        logger.warning(f"Error sending SSE notification: {str(e)}")


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
            logger.debug("Parsing body as json")
            body = await request.json()
            logger.debug("Parsed body as json")
            return body
        except Exception:
            logger.debug("Failed to parse body as json, returning raw body")
            return await request.body()
