import hashlib
import hmac
import logging

from fastapi import Header, HTTPException, Request

from app.config import settings

logger = logging.getLogger(__name__)


async def verify_webhook_secret(
    request: Request,
    x_signature: str | None = Header(default=None, alias="X-Keycloak-Signature"),
) -> None:
    """
    HMAC-SHA256 alapú webhook validalas.
    A vymalo/keycloak-webhook a WEBHOOK_HTTP_SHARED_SECRET-tel alair ja a payloadot,
    es X-Keycloak-Signature headerben kuldi.

    Ha nincs secret konfiguralva (fejlesztes), atengedi a kerest.
    """
    if not settings.webhook_secret:
        logger.warning("WEBHOOK_SECRET nincs beallitva — validalas kihagyva (csak fejlesztesben acceptable)")
        return

    if x_signature is None:
        logger.error("Hianyzo X-Keycloak-Signature header")
        raise HTTPException(status_code=401, detail="Hianyzo webhook signature")

    body = await request.body()
    expected = hmac.new(
        settings.webhook_secret.encode(),
        body,
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected, x_signature):
        logger.error("Ervenytelen webhook signature")
        raise HTTPException(status_code=403, detail="Ervenytelen webhook signature")
