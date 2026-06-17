import logging
import time
from typing import Any

import httpx

from app.config import settings

logger = logging.getLogger(__name__)

# A Keycloak user attributumok, amelyeket szinkronizalunk LearnWorldsbe.
# Keycloak attribute nev -> LearnWorlds Custom User Field nev
# Ha a ket oldal nevei megegyeznek, a mapping egyszerusodik.
ATTRIBUTE_MAP: dict[str, str] = {
    "teljesnev": "teljesnev",
    "munkakor": "munkakor",
    "aruhaz": "aruhaz",
    "munkakezdet": "munkakezdet",
    "ujkollega": "ujkollega",
}


class KeycloakClient:
    """
    Keycloak Admin API client.
    - service account (client_credentials) alapu autentikacio
    - access token cache (automatikus lejarat kezeles)
    """

    def __init__(self) -> None:
        self._base_url = settings.keycloak_base_url.rstrip("/")
        self._realm = settings.keycloak_realm
        self._client_id = settings.keycloak_client_id
        self._client_secret = settings.keycloak_client_secret
        self._access_token: str | None = None
        self._token_expires_at: float = 0.0

    async def _get_token(self) -> str:
        """
        Client credentials grant alapjan keri le vagy frissiti a token-t.
        """
        if self._access_token and time.time() < self._token_expires_at - 30:
            return self._access_token

        token_url = f"{self._base_url}/realms/{self._realm}/protocol/openid-connect/token"
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                },
            )
            resp.raise_for_status()
            data = resp.json()

        self._access_token = data["access_token"]
        self._token_expires_at = time.time() + data.get("expires_in", 300)
        logger.debug("Keycloak access token megujitva")
        return self._access_token

    async def get_user_attributes(self, user_id: str) -> dict[str, Any]:
        """
        Leker egy Keycloak user-t ID alapjan, visszaadja a szinkronizalandó attributumokat.
        A Keycloak az attributumokat lista formaban adja vissza — mi az elso erteket hasznaljuk.

        Visszateresi ertek peldaja:
        {
            "teljesnev": "Kiss Janos",
            "munkakor": "Kasszas",
            "aruhaz": "Budapest-01",
            "munkakezdet": "2024-03-01",
            "ujkollega": "true"
        }
        """
        token = await self._get_token()
        url = f"{self._base_url}/admin/realms/{self._realm}/users/{user_id}"

        async with httpx.AsyncClient() as client:
            resp = await client.get(
                url,
                headers={"Authorization": f"Bearer {token}"},
            )
            resp.raise_for_status()
            user_data = resp.json()

        raw_attrs: dict[str, list[str]] = user_data.get("attributes") or {}
        result: dict[str, Any] = {}

        for kc_key, lw_key in ATTRIBUTE_MAP.items():
            values = raw_attrs.get(kc_key)
            if values:
                result[lw_key] = values[0]  # Keycloak listakat tarol, az elsot vesszuk

        logger.info("Keycloak user %s attributumok: %s", user_id, list(result.keys()))
        return result
