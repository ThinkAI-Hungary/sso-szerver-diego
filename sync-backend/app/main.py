import logging
import sys
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse

from app.config import settings
from app.keycloak_client import KeycloakClient
from app.learnworlds_client import LearnWorldsClient
from app.models import KeycloakWebhookPayload
from app.security import verify_webhook_secret

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Singleton kliensek (az app elettartaman at ujrafelhasznalva)
# ---------------------------------------------------------------------------
kc_client = KeycloakClient()
lw_client = LearnWorldsClient()

# Esemenyek, amelyek szinkronizalast triggerenek
SYNC_EVENT_TYPES = {"LOGIN", "REGISTER", "UPDATE_PROFILE"}


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(
        "SSO sync backend indul | Keycloak: %s | LearnWorlds: %s",
        settings.keycloak_base_url,
        settings.learnworlds_school,
    )
    yield
    logger.info("SSO sync backend leall")


app = FastAPI(
    title="SSO Sync Backend",
    description="Keycloak -> LearnWorlds user attributum szinkronizalas",
    version="1.0.0",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Health check (Railway health probe)
# ---------------------------------------------------------------------------
@app.get("/health", tags=["system"])
async def health() -> dict:
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Webhook endpoint
# ---------------------------------------------------------------------------
@app.post(
    "/webhook/keycloak",
    status_code=status.HTTP_200_OK,
    tags=["webhook"],
    dependencies=[Depends(verify_webhook_secret)],
)
async def keycloak_webhook(request: Request, payload: KeycloakWebhookPayload) -> dict:
    """
    vymalo/keycloak-webhook altal kuldott Keycloak esemenyek fogadasa.
    Csak a SYNC_EVENT_TYPES esemenyek triggerelnek szinkronizalast.
    """
    event_type = payload.type
    logger.info("Keycloak esemeny erkezett: %s", event_type)

    # Csak a relevans esemenyek triggerenek szinkronizalast
    if event_type not in SYNC_EVENT_TYPES:
        logger.debug("Esemeny kihagyva (nem szinkronizalt tipus): %s", event_type)
        return {"status": "skipped", "reason": "event type not in sync list"}

    user_id = payload.userId
    if not user_id:
        logger.warning("Keycloak esemeny userId nelkul: %s", event_type)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="userId hianyzik a payloadbol",
        )

    # 1. Keycloak user attributumok lekerdezese
    try:
        attributes = await kc_client.get_user_attributes(user_id)
    except Exception as exc:
        logger.exception("Keycloak Admin API hiba (userId: %s): %s", user_id, exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Keycloak Admin API hiba",
        ) from exc

    if not attributes:
        logger.info("Nincsenek szinkronizalando attributumok (userId: %s)", user_id)
        return {"status": "skipped", "reason": "no mapped attributes found"}

    # Az email lekerdezese a Keycloak user adatabol (user ID alapjan kaptuk meg)
    # A LearnWorlds API email alapjan azonositja a usert
    try:
        user_info = await _get_keycloak_user_email(user_id)
    except Exception as exc:
        logger.exception("Keycloak user email lekerdezesi hiba: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Keycloak user email lekerdezesi hiba",
        ) from exc

    if not user_info:
        logger.error("Keycloak user email nem talalhato (userId: %s)", user_id)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Keycloak user email nem talalhato",
        )

    # 2. LearnWorlds user ID megkeresese email alapjan
    try:
        lw_user_id = await lw_client.get_user_id_by_email(user_info)
    except Exception as exc:
        logger.exception("LearnWorlds user kereses hiba (email: %s): %s", user_info, exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="LearnWorlds API hiba user keresesnel",
        ) from exc

    if not lw_user_id:
        logger.warning("LearnWorlds user nem letezik meg (email: %s) — kihagyva", user_info)
        return {"status": "skipped", "reason": "LearnWorlds user not found (may not have logged in yet)"}

    # 3. LearnWorlds Custom User Fields frissitese
    try:
        await lw_client.update_user_fields(lw_user_id, attributes)
    except Exception as exc:
        logger.exception("LearnWorlds update hiba (userId: %s): %s", lw_user_id, exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="LearnWorlds API hiba user frissitesnel",
        ) from exc

    logger.info(
        "Szinkronizalas sikeres | Keycloak user: %s | LW user: %s | Mezok: %s",
        user_id,
        lw_user_id,
        list(attributes.keys()),
    )
    return {
        "status": "synced",
        "keycloak_user_id": user_id,
        "learnworlds_user_id": lw_user_id,
        "synced_fields": list(attributes.keys()),
    }


async def _get_keycloak_user_email(user_id: str) -> str | None:
    """
    Keycloak Admin API-n keresztul lekeri a user email cimet.
    A keycloak_client.get_user_attributes() mar lekeri a user adatait,
    de az email kulon tarolodik a Keycloak user rekordban (nem attributumkent).
    """
    import httpx

    token = await kc_client._get_token()
    url = f"{settings.keycloak_base_url.rstrip('/')}/admin/realms/{settings.keycloak_realm}/users/{user_id}"

    async with httpx.AsyncClient() as client:
        resp = await client.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
        )

    if resp.status_code == 404:
        return None

    resp.raise_for_status()
    data = resp.json()
    return data.get("email")
