import logging
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

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

# In-memory store: email -> bejelentkezés időpontja (UTC)
_recent_lw_logins: dict[str, datetime] = {}
_LOGIN_TTL_MINUTES = 30


def _cleanup_logins() -> None:
    """Lejárt bejelentkezések törlése."""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=_LOGIN_TTL_MINUTES)
    expired = [e for e, t in _recent_lw_logins.items() if t < cutoff]
    for e in expired:
        del _recent_lw_logins[e]


def _get_recent_emails() -> list[str]:
    """Az elmúlt 30 percben bejelentkezett emailek listája."""
    _cleanup_logins()
    return list(_recent_lw_logins.keys())

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
# Magic link endpoint
# ---------------------------------------------------------------------------
@app.get("/magic-link", tags=["sso"])
async def magic_link(email: str, key: str | None = None) -> RedirectResponse:
    """
    Egyszeri SSO belépési linket generál a megadott email-hez, majd átirányít.
    A user automatikusan be lesz lépve a LearnWorlds webes felületén.

    Védelem: ha MAGIC_LINK_SECRET be van állítva, a 'key' paraméternek egyeznie kell.
    """
    # Kulcs ellenőrzés
    if settings.magic_link_secret and key != settings.magic_link_secret:
        logger.warning("Magic link: érvénytelen kulcs (email: %s)", email)
        raise HTTPException(status_code=403, detail="Érvénytelen kulcs")

    if not settings.learnworlds_client_id or not settings.learnworlds_client_secret:
        logger.error("Magic link: LEARNWORLDS_CLIENT_ID vagy LEARNWORLDS_CLIENT_SECRET nincs beállítva")
        raise HTTPException(status_code=503, detail="SSO nincs konfigurálva")

    # LearnWorlds user ID keresés email alapján
    try:
        lw_user_id = await lw_client.get_user_id_by_email(email)
    except Exception as exc:
        logger.exception("Magic link: LearnWorlds user keresés hiba (email: %s): %s", email, exc)
        raise HTTPException(status_code=502, detail="LearnWorlds API hiba") from exc

    if not lw_user_id:
        logger.warning("Magic link: user nem található (email: %s)", email)
        raise HTTPException(status_code=404, detail="Felhasználó nem található")

    # SSO link generálás
    try:
        sso_link = await lw_client.get_sso_link(lw_user_id)
    except Exception as exc:
        logger.exception("Magic link: SSO link generálás hiba (user: %s): %s", lw_user_id, exc)
        raise HTTPException(status_code=502, detail="SSO link generálás sikertelen") from exc

    logger.info("Magic link redirect: email=%s lw_user=%s", email, lw_user_id)
    return RedirectResponse(url=sso_link, status_code=302)


# ---------------------------------------------------------------------------
# LW Login oldal (mobilos app -> rendszer böngésző belépés)
# ---------------------------------------------------------------------------
_LW_LOGIN_HTML = """
<!DOCTYPE html>
<html lang="hu">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Diego Academy – Belépés</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Inter', sans-serif;
      min-height: 100vh;
      background: #f5f5f5;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
    }
    .card {
      background: #fff;
      border-radius: 16px;
      box-shadow: 0 8px 40px rgba(0,0,0,.12);
      padding: 40px 36px;
      width: 100%;
      max-width: 420px;
      text-align: center;
    }
    .logo {
      font-size: 28px;
      font-weight: 700;
      color: #e63946;
      letter-spacing: -1px;
      margin-bottom: 8px;
    }
    .logo span { color: #111; }
    .subtitle {
      color: #666;
      font-size: 14px;
      margin-bottom: 32px;
    }
    label {
      display: block;
      text-align: left;
      font-size: 13px;
      font-weight: 600;
      color: #333;
      margin-bottom: 6px;
    }
    input[type=email] {
      width: 100%;
      padding: 12px 16px;
      border: 1.5px solid #ddd;
      border-radius: 8px;
      font-size: 15px;
      font-family: inherit;
      outline: none;
      transition: border-color .2s;
      margin-bottom: 20px;
    }
    input[type=email]:focus { border-color: #e63946; }
    button {
      width: 100%;
      padding: 13px;
      background: #e63946;
      color: #fff;
      border: none;
      border-radius: 8px;
      font-size: 16px;
      font-weight: 600;
      font-family: inherit;
      cursor: pointer;
      transition: background .2s, transform .1s;
    }
    button:hover { background: #c1121f; }
    button:active { transform: scale(.98); }
    .error {
      background: #fff0f0;
      color: #c1121f;
      border: 1px solid #ffb3b3;
      border-radius: 8px;
      padding: 10px 14px;
      font-size: 13px;
      margin-bottom: 16px;
    }
    .note {
      font-size: 12px;
      color: #999;
      margin-top: 20px;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">DIEGO<span> ACADEMY</span></div>
    <p class="subtitle">Add meg az email cíedet a böngészős belépéshez</p>
    {error}
    <form method="POST" action="/lw-login">
      <label for="email">Email cím</label>
      <input type="email" id="email" name="email" placeholder="pelda@email.com"
             value="{prefill}" required autofocus>
      <button type="submit">Belépés</button>
    </form>
    <p class="note">Az email cíedet megjegyezzük a böngészőben – legközelebb automatikusan lépsz be.</p>
  </div>
</body>
</html>
"""

_LW_CONFIRM_HTML = """
<!DOCTYPE html>
<html lang="hu">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Diego Academy – Belépés megerősítése</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Inter', sans-serif;
      min-height: 100vh;
      background: #f5f5f5;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
    }
    .card {
      background: #fff;
      border-radius: 16px;
      box-shadow: 0 8px 40px rgba(0,0,0,.12);
      padding: 40px 36px;
      width: 100%;
      max-width: 420px;
      text-align: center;
    }
    .logo { font-size: 28px; font-weight: 700; color: #e63946; letter-spacing: -1px; margin-bottom: 8px; }
    .logo span { color: #111; }
    .subtitle { color: #666; font-size: 14px; margin-bottom: 32px; }
    .email-box {
      background: #f8f8f8;
      border: 1.5px solid #e0e0e0;
      border-radius: 10px;
      padding: 14px 18px;
      font-size: 16px;
      font-weight: 600;
      color: #111;
      margin-bottom: 24px;
      word-break: break-all;
    }
    button {
      width: 100%;
      padding: 13px;
      background: #e63946;
      color: #fff;
      border: none;
      border-radius: 8px;
      font-size: 16px;
      font-weight: 600;
      font-family: inherit;
      cursor: pointer;
      transition: background .2s, transform .1s;
      margin-bottom: 12px;
    }
    button:hover { background: #c1121f; }
    button:active { transform: scale(.98); }
    .other-link { font-size: 13px; color: #999; }
    .other-link a { color: #e63946; text-decoration: none; }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">DIEGO<span> ACADEMY</span></div>
    <p class="subtitle">Bejelentkezés böngészőben</p>
    <div class="email-box">{email}</div>
    <form method="POST" action="/lw-login/confirm">
      <input type="hidden" name="email" value="{email}">
      <button type="submit">Belépés ezzel a fiókkal</button>
    </form>
    <p class="other-link">Nem te vagy? <a href="/lw-login?force=1">Más email</a></p>
  </div>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# LW Webhook: user login event (automation-ból)
# ---------------------------------------------------------------------------
@app.post("/webhook/lw-login", tags=["sso"])
async def lw_login_webhook(request: Request) -> dict:
    """
    LearnWorlds automation webhook fogadása user bejelentkezéskor.
    A payload-ban lévő user.email-t eltárolja 30 percre.
    Az /lw-login oldal ezt használja az automatikus belépéshez.
    """
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Érvénytelen JSON payload")

    user = body.get("user", {})
    email = user.get("email", "").strip()

    if not email or "@" not in email:
        logger.warning("LW webhook: érvénytelen email a payload-ban: %s", body)
        raise HTTPException(status_code=400, detail="email hiányzik a payload-ból")

    _recent_lw_logins[email] = datetime.now(timezone.utc)
    logger.info("LW webhook: bejelentkezés rögzítve (email: %s)", email)
    return {"status": "ok", "email": email}


@app.get("/lw-login", tags=["sso"])
async def lw_login_page(request: Request) -> Response:
    """
    Böngészős belépési oldal.
    Ha az email cookie már be van állítva, automatikusan generál magic linket.
    Ha van friss LW bejelentkezés (webhook), megmutatja az email-t megerősítésre.
    Ha nincs, email beviteli formot jelenít meg.
    """
    lw_email = request.cookies.get("lw_email")
    force = request.query_params.get("force") == "1"

    if lw_email and not force:
        logger.info("LW Login: cookie-ból auto-redirect (email: %s)", lw_email)
        return RedirectResponse(
            url=f"/magic-link?email={lw_email}&key={settings.magic_link_secret}",
            status_code=302,
        )

    if not force:
        recent = _get_recent_emails()
        if recent:
            email_to_confirm = recent[0]
            html = _LW_CONFIRM_HTML.replace("{email}", email_to_confirm)
            logger.info("LW Login: friss belépés találva, megerősítés megmutatva (%s)", email_to_confirm)
            return HTMLResponse(content=html)

    html = _LW_LOGIN_HTML.replace("{error}", "").replace("{prefill}", "")
    return HTMLResponse(content=html)


@app.post("/lw-login", tags=["sso"])
async def lw_login_submit(request: Request) -> Response:
    """
    Email form submit: cookie-t állít be, majd magic linket generál.
    """
    form = await request.form()
    email = str(form.get("email", "")).strip()

    if not email or "@" not in email:
        error_html = '<div class="error">Kérjük, adjon meg érvényes email címet.</div>'
        html = _LW_LOGIN_HTML.replace("{error}", error_html).replace("{prefill}", email)
        return HTMLResponse(content=html, status_code=400)

    response = RedirectResponse(
        url=f"/magic-link?email={email}&key={settings.magic_link_secret}",
        status_code=302,
    )
    response.set_cookie(
        key="lw_email",
        value=email,
        max_age=365 * 24 * 60 * 60,  # 1 év
        httponly=True,
        secure=True,
        samesite="lax",
    )
    logger.info("LW Login: email cookie beállítva és magic link redirect (email: %s)", email)
    return response


@app.post("/lw-login/confirm", tags=["sso"])
async def lw_login_confirm(request: Request) -> Response:
    """
    Egy gombnyomásos megerősítés a friss webhook-alapu bejelentkezéshez.
    """
    form = await request.form()
    email = str(form.get("email", "")).strip()

    recent = _get_recent_emails()
    if email not in recent:
        error_html = '<div class="error">Ez az email nem szerepel a friss belépések között. Próbáld újra az appból.</div>'
        html = _LW_LOGIN_HTML.replace("{error}", error_html).replace("{prefill}", "")
        return HTMLResponse(content=html, status_code=403)

    response = RedirectResponse(
        url=f"/magic-link?email={email}&key={settings.magic_link_secret}",
        status_code=302,
    )
    response.set_cookie(
        key="lw_email",
        value=email,
        max_age=365 * 24 * 60 * 60,  # 1 év
        httponly=True,
        secure=True,
        samesite="lax",
    )
    logger.info("LW Login: megerősített belépés, cookie beállítva (email: %s)", email)
    return response


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
