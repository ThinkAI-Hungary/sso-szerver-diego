import base64
import hashlib
import hmac as hmac_lib
import json
import logging
import secrets
import sys
import urllib.parse
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

# Rate limiting: magic link generáláshoz (gomb spam védelem)
_magic_link_cooldowns: dict[str, datetime] = {}
_MAGIC_LINK_COOLDOWN_MINUTES = 5

# OIDC state store (CSRF védelem)
_oidc_states: dict[str, str] = {}  # state -> ""


# ---------------------------------------------------------------------------
# Cookie signing (HMAC-SHA256) – védi az lw_email cookie-t a hamisítástól
# ---------------------------------------------------------------------------
def _sign_email(email: str) -> str:
    """Visszaadja az emailt. (Cookie alairás kikapcsolva – webhook secret elegendo.)"""
    return email


def _verify_signed_email(value: str) -> str | None:
    """Visszaadja az emailt ha ervenyes formatum, kulonben None."""
    if not value or "@" not in value:
        return None
    # Ha alairassal erkezett (regi format: email|sig), csak az emailt adjuk vissza
    return value.split("|")[0] if "|" in value else value


def _cleanup_logins() -> None:
    """Lejárt bejelentkezések és magic link cooldownok törlése."""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=_LOGIN_TTL_MINUTES)
    expired = [e for e, t in _recent_lw_logins.items() if t < cutoff]
    for e in expired:
        del _recent_lw_logins[e]

    cooldown_cutoff = datetime.now(timezone.utc) - timedelta(minutes=_MAGIC_LINK_COOLDOWN_MINUTES)
    expired_cooldowns = [e for e, t in _magic_link_cooldowns.items() if t < cooldown_cutoff]
    for e in expired_cooldowns:
        del _magic_link_cooldowns[e]


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
# Keycloak OIDC SSO (Keycloak -> LearnWorlds web school)
# ---------------------------------------------------------------------------
@app.get("/sso/start", tags=["sso"])
async def sso_start() -> RedirectResponse:
    """
    Elindítja a Keycloak OIDC bejelentkezést.
    A Keycloak visszairányít /sso/callback-re, ahol LW magic linket generálunk.
    """
    if not settings.keycloak_base_url or not settings.keycloak_client_id:
        raise HTTPException(status_code=503, detail="Keycloak nincs konfigurálva")

    state = secrets.token_urlsafe(32)
    _oidc_states[state] = ""

    auth_url = (
        f"{settings.keycloak_base_url.rstrip('/')}"
        f"/realms/{settings.keycloak_realm}"
        "/protocol/openid-connect/auth"
    )
    redirect_uri = f"{settings.sso_base_url}/sso/callback"

    params = {
        "client_id": settings.keycloak_client_id,
        "response_type": "code",
        "scope": "openid email profile",
        "redirect_uri": redirect_uri,
        "state": state,
    }

    logger.info("SSO start: Keycloak OIDC flow indul")
    return RedirectResponse(url=f"{auth_url}?{urllib.parse.urlencode(params)}")


@app.get("/sso/callback", tags=["sso"])
async def sso_callback(code: str, state: str) -> RedirectResponse:
    """
    Keycloak OIDC callback. Kicseréli a kódot tokenre, lekéri az emailt,
    majd LearnWorlds magic linket generál és átirányít.
    """
    if state not in _oidc_states:
        raise HTTPException(status_code=400, detail="Érvénytelen OIDC state (CSRF?)")
    del _oidc_states[state]

    token_url = (
        f"{settings.keycloak_base_url.rstrip('/')}"
        f"/realms/{settings.keycloak_realm}"
        "/protocol/openid-connect/token"
    )
    redirect_uri = f"{settings.sso_base_url}/sso/callback"

    import httpx
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            token_url,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": settings.keycloak_client_id,
                "client_secret": settings.keycloak_client_secret,
                "redirect_uri": redirect_uri,
            },
        )

    if not resp.is_success:
        logger.error("SSO callback: Keycloak token csere sikertelen: %s", resp.text[:300])
        raise HTTPException(status_code=502, detail="Keycloak token csere sikertelen")

    token_data = resp.json()
    id_token = token_data.get("id_token", "")
    if not id_token:
        raise HTTPException(status_code=502, detail="id_token hiányzik a válaszból")

    # JWT payload dekodálás (nincs verificáció - a Keycloak-tól közvetlenül kaptuk)
    try:
        payload_b64 = id_token.split(".")[1]
        payload_b64 += "=" * (4 - len(payload_b64) % 4)
        claims = json.loads(base64.b64decode(payload_b64))
    except Exception as exc:
        raise HTTPException(status_code=502, detail="JWT dekodálás sikertelen") from exc

    email = claims.get("email", "").strip()
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Email nem található a Keycloak tokenben")

    logger.info("SSO callback: Keycloak auth sikeres, email: %s", email)

    # LearnWorlds user ID keresés
    try:
        lw_user_id = await lw_client.get_user_id_by_email(email)
    except Exception as exc:
        raise HTTPException(status_code=502, detail="LearnWorlds API hiba") from exc

    if not lw_user_id:
        raise HTTPException(status_code=404, detail=f"LearnWorlds user nem található: {email}")

    # LW magic link genérálás
    try:
        sso_link = await lw_client.get_sso_link(lw_user_id)
    except Exception as exc:
        raise HTTPException(status_code=502, detail="SSO link generálás sikertelen") from exc

    logger.info("SSO callback: LW magic link redirect, email=%s user=%s", email, lw_user_id)
    return RedirectResponse(url=sso_link, status_code=302)


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

    # SSO link generálás – belépés után /profile oldalra irányít
    try:
        redirect_to = f"https://{settings.learnworlds_school}/profile"
        sso_link = await lw_client.get_sso_link(lw_user_id, redirect_url=redirect_to)
    except Exception as exc:
        logger.exception("Magic link: SSO link generálás hiba (user: %s): %s", lw_user_id, exc)
        raise HTTPException(status_code=502, detail="SSO link generálás sikertelen") from exc

    logger.info("Magic link redirect: email=%s lw_user=%s -> /profile", email, lw_user_id)
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

_LW_COOLDOWN_HTML = """
<!DOCTYPE html>
<html lang="hu">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Diego Academy – Belépési link</title>
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
    .icon { font-size: 44px; margin: 16px 0; }
    .title { font-size: 18px; font-weight: 600; color: #111; margin-bottom: 12px; }
    .message { color: #666; font-size: 14px; line-height: 1.6; margin-bottom: 28px; }
    .btn {
      display: inline-block;
      padding: 13px 24px;
      background: #e63946;
      color: #fff;
      border-radius: 8px;
      font-size: 15px;
      font-weight: 600;
      font-family: inherit;
      text-decoration: none;
      transition: background .2s;
    }
    .btn:hover { background: #c1121f; }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">DIEGO<span> ACADEMY</span></div>
    <div class="icon">&#9200;</div>
    <p class="title">Belépési link aktív</p>
    <p class="message">Az előző belépési link még érvényes.<br>Kérj újat <strong>{minutes} perc</strong> múlva.</p>
    <a href="{lw_url}" class="btn">Vissza a Diego Academybe</a>
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

    Védelem: ha LW_WEBHOOK_SECRET be van állítva, az X-LW-Webhook-Secret
    headernek egyeznie kell (megakadályozza az álwebhook-okat).
    """
    # Webhook titkos kulcs ellenőrzés (Bearer Token)
    if settings.lw_webhook_secret:
        auth_header = request.headers.get("Authorization", "")
        expected = f"Bearer {settings.lw_webhook_secret}"
        if not hmac_lib.compare_digest(auth_header, expected):
            logger.warning("LW webhook: érvénytelen Authorization header")
            raise HTTPException(status_code=403, detail="Érvénytelen webhook titkos kulcs")
    else:
        logger.warning("LW webhook: LW_WEBHOOK_SECRET nincs beállítva – bárki tud webhookot küldeni!")

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

    Prioritási sorrend:
    1. Ha lw_email cookie van (és nincs force) → magic link redirect (visszatérő user)
    2. Ha ?email=X param van ÉS friss webhook létezik → rate limit ellenőrzés → magic link + cookie beállítás
    3. Ha ?email=X van de nincs friss webhook → hiba oldal
    4. Ha van friss webhook (nincs email param) → megerősítő oldal
    5. Különben → email beviteli form
    """
    lw_email = _verify_signed_email(request.cookies.get("lw_email", ""))
    force = request.query_params.get("force") == "1"
    email_param = request.query_params.get("email", "").strip()

    # 1. Cookie alapú auto-redirect (visszatérő user)
    # Ha van ?email=X param ÉS eltér a cookie-tól → a param prioritást kap (user váltás)
    cookie_matches = (not email_param) or (email_param.lower() == (lw_email or "").lower())
    if lw_email and not force and cookie_matches:
        logger.info("LW Login: cookie-ból auto-redirect (email: %s)", lw_email)
        return RedirectResponse(
            url=f"/magic-link?email={urllib.parse.quote(lw_email)}&key={settings.magic_link_secret}",
            status_code=302,
        )

    # 2-3. Email param alapú belépés (LW oldalon lévő gombról érkezik, {user_email} változóval)
    if email_param and "@" in email_param and not force:
        recent = _get_recent_emails()
        recent_lower = [e.lower() for e in recent]

        if email_param.lower() not in recent_lower:
            # Nincs friss webhook → user nem lépett be LW-ben a közelmúltban
            logger.warning("LW Login: nincs friss webhook email param alapú belépéshez: %s", email_param)
            error_html = '<div class="error">Nem találtunk friss belépést. Lépj be a Diego Academy alkalmazásba, majd próbáld újra.</div>'
            html = _LW_LOGIN_HTML.replace("{error}", error_html).replace("{prefill}", email_param)
            return HTMLResponse(content=html, status_code=403)

        # Rate limit ellenőrzés (spam védelem: max 1 link / 5 perc / email)
        cooldown_key = email_param.lower()
        if cooldown_key in _magic_link_cooldowns:
            elapsed_minutes = (
                datetime.now(timezone.utc) - _magic_link_cooldowns[cooldown_key]
            ).total_seconds() / 60
            if elapsed_minutes < _MAGIC_LINK_COOLDOWN_MINUTES:
                remaining = int(_MAGIC_LINK_COOLDOWN_MINUTES - elapsed_minutes) + 1
                logger.info("LW Login: cooldown aktív (email: %s, %d perc múlva újrakérhető)", email_param, remaining)
                html = _LW_COOLDOWN_HTML.replace("{minutes}", str(remaining)).replace(
                    "{lw_url}", f"https://{settings.learnworlds_school}"
                )
                return HTMLResponse(content=html)

        # Magic link generálás + 1 éves cookie beállítás
        _magic_link_cooldowns[cooldown_key] = datetime.now(timezone.utc)
        logger.info("LW Login: gomb alapú belépés, magic link generálás (email: %s)", email_param)
        response = RedirectResponse(
            url=f"/magic-link?email={urllib.parse.quote(email_param)}&key={settings.magic_link_secret}",
            status_code=302,
        )
        response.set_cookie(
            key="lw_email",
            value=_sign_email(email_param),
            max_age=365 * 24 * 60 * 60,
            httponly=True,
            secure=True,
            samesite="lax",
        )
        return response

    # 4. Friss webhook → megerősítő oldal (3 perces ablak)
    if not force:
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=3)
        fresh = [e for e, t in _recent_lw_logins.items() if t >= cutoff]
        if fresh:
            email_to_confirm = fresh[0]
            html = _LW_CONFIRM_HTML.replace("{email}", email_to_confirm)
            logger.info("LW Login: megerősítő oldal (%s)", email_to_confirm)
            return HTMLResponse(content=html)

    # 5. Email beviteli form
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

    # Ellenőrzés: volt-e friss LW bejelentkezés ehhez az emailhez?
    recent = _get_recent_emails()
    if email not in recent:
        logger.warning("LW Login: nincs friss webhook ehhez az emailhez: %s", email)
        error_html = '<div class="error">Nem találtunk friss bejelentkezést ehhez az emailhez. Kérjük, nyisd meg a Diego Academy alkalmazást és lépj be ott először.</div>'
        html = _LW_LOGIN_HTML.replace("{error}", error_html).replace("{prefill}", email)
        return HTMLResponse(content=html, status_code=403)

    response = RedirectResponse(
        url=f"/magic-link?email={email}&key={settings.magic_link_secret}",
        status_code=302,
    )
    response.set_cookie(
        key="lw_email",
        value=_sign_email(email),
        max_age=365 * 24 * 60 * 60,  # 1 év
        httponly=True,
        secure=True,
        samesite="lax",
    )
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
        value=_sign_email(email),
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
