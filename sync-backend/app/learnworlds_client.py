import logging
from typing import Any

import httpx

from app.config import settings

logger = logging.getLogger(__name__)

LW_API_VERSION = "2"


def _api_base() -> str:
    """A school saját API base URL-je."""
    return f"https://{settings.learnworlds_school}/admin/api"


class LearnWorldsClient:
    """
    LearnWorlds REST API v2 client.
    Dokumentacio: https://developers.learnworlds.com/reference
    """

    def __init__(self) -> None:
        self._headers = {
            "Lw-Client": settings.learnworlds_client_id,
            "Authorization": f"Bearer {settings.learnworlds_api_key}",
            "Content-Type": "application/json",
        }

    async def get_user_id_by_email(self, email: str) -> str | None:
        """
        Email cim alapjan megkeresi a LearnWorlds user ID-t.
        Ha a user nem talalhato, None-t ad vissza.
        """
        url = f"{_api_base()}/v{LW_API_VERSION}/users"
        params = {"email": email}

        async with httpx.AsyncClient() as client:
            resp = await client.get(url, headers=self._headers, params=params)

        if resp.status_code == 404:
            logger.warning("LearnWorlds: user nem talalhato (email: %s)", email)
            return None

        if not resp.is_success:
            logger.error(
                "LearnWorlds API hiba: status=%s body=%s",
                resp.status_code, resp.text[:500]
            )
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

        url = f"{_api_base()}/v{LW_API_VERSION}/users/{user_id}"
        payload = {"fields": fields}

        async with httpx.AsyncClient() as client:
            resp = await client.patch(url, headers=self._headers, json=payload)

        if resp.status_code == 429:
            logger.error("LearnWorlds rate limit eleres — kesobb kell ujra probalni")
            resp.raise_for_status()

        resp.raise_for_status()
        logger.info("LearnWorlds user %s frissitve: %s", user_id, list(fields.keys()))
        return True

    async def _get_oauth2_token(self) -> str:
        """
        OAuth2 client_credentials grant segitsegevel kap egy admin access tokent.
        Ez szukseges a SSO link generáláshoz.
        """
        url = f"https://{settings.learnworlds_school}/admin/api/oauth2/access_token"
        data = {
            "client_id": settings.learnworlds_client_id,
            "client_secret": settings.learnworlds_client_secret,
            "grant_type": "client_credentials",
        }
        async with httpx.AsyncClient() as client:
            resp = await client.post(url, data=data)

        logger.info(
            "LearnWorlds OAuth2 token valasz: status=%s body=%s",
            resp.status_code, resp.text[:500]
        )
        resp.raise_for_status()
        data_json = resp.json()
        token_data = data_json.get("tokenData") or data_json
        if "access_token" not in token_data:
            logger.error("LearnWorlds OAuth2 valasz nem tartalmaz access_token-t: %s", data_json)
            raise ValueError(f"access_token hianyzik a valaszbol: {data_json}")
        token: str = token_data["access_token"]
        return token

    async def get_sso_link(self, user_id: str, redirect_url: str | None = None) -> str:
        """
        Egyszeri SSO belépési linket generál a megadott LearnWorlds user ID-hoz.
        Dokumentacio: POST /admin/api/sso (form-urlencoded, data=JSON)
        """
        token = await self._get_oauth2_token()
        url = f"https://{settings.learnworlds_school}/admin/api/sso"

        payload: dict = {"user_id": user_id}
        if redirect_url:
            payload["redirectUrl"] = redirect_url

        headers = {
            "Lw-Client": settings.learnworlds_client_id,
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        import json as jsonlib
        form_data = {"data": jsonlib.dumps(payload)}

        async with httpx.AsyncClient() as client:
            resp = await client.post(url, headers=headers, data=form_data)

        logger.info(
            "LearnWorlds SSO endpoint valasz: status=%s body=%s",
            resp.status_code, resp.text[:500],
        )
        resp.raise_for_status()

        if not resp.text.strip():
            raise ValueError("LearnWorlds SSO endpoint ures valaszt adott")

        data = resp.json()
        sso_link = data.get("url") or data.get("sso_link") or data.get("link")
        if not sso_link:
            logger.error("LearnWorlds SSO valasz nem tartalmaz URL-t: %s", data)
            raise ValueError(f"SSO link nem talalhato a valaszban: {data}")

        logger.info("SSO link generálva user %s-hez", user_id)
        return sso_link

