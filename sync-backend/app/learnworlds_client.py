import logging
from typing import Any

import httpx

from app.config import settings

logger = logging.getLogger(__name__)

LW_API_BASE = "https://api.learnworlds.com"
LW_API_VERSION = "2"


class LearnWorldsClient:
    """
    LearnWorlds REST API v2 client.
    Dokumentacio: https://developers.learnworlds.com/reference
    """

    def __init__(self) -> None:
        self._headers = {
            "Lw-Client": settings.learnworlds_school_id,
            "Authorization": f"Bearer {settings.learnworlds_api_key}",
            "Content-Type": "application/json",
        }

    async def get_user_id_by_email(self, email: str) -> str | None:
        """
        Email cim alapjan megkeresi a LearnWorlds user ID-t.
        Ha a user nem talalhato, None-t ad vissza.
        """
        url = f"{LW_API_BASE}/v{LW_API_VERSION}/users"
        params = {"email": email}

        async with httpx.AsyncClient() as client:
            resp = await client.get(url, headers=self._headers, params=params)

        if resp.status_code == 404:
            logger.warning("LearnWorlds: user nem talalhato (email: %s)", email)
            return None

        resp.raise_for_status()
        data = resp.json()
        users = data.get("data", [])
        if not users:
            logger.warning("LearnWorlds: ures valasz (email: %s)", email)
            return None

        user_id: str = users[0]["id"]
        logger.info("LearnWorlds user megtalaltva: %s -> %s", email, user_id)
        return user_id

    async def update_user_fields(self, user_id: str, fields: dict[str, Any]) -> bool:
        """
        Frissiti a LearnWorlds user Custom User Fields mezoit.
        A 'fields' dict kulcsai a LearnWorlds Field Label-jei (case-sensitive).
        Visszater True-val, ha sikeres.
        """
        if not fields:
            logger.info("Nincsenek frissitendo mezok, kihagyva.")
            return True

        url = f"{LW_API_BASE}/v{LW_API_VERSION}/users/{user_id}"
        payload = {"fields": fields}

        async with httpx.AsyncClient() as client:
            resp = await client.patch(url, headers=self._headers, json=payload)

        if resp.status_code == 429:
            logger.error("LearnWorlds rate limit eleres — kesobb kell ujra probalni")
            resp.raise_for_status()

        resp.raise_for_status()
        logger.info("LearnWorlds user %s frissitve: %s", user_id, list(fields.keys()))
        return True
