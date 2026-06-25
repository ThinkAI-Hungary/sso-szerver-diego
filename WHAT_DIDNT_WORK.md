# Diego Academy SSO – Mi nem ment és miért

**Készítés dátuma:** 2026-06-25
**Alapja:** learnworlds_keycloak_sso_osszefoglalo.md + 2026-06-25 session logok

---

## 1. Keycloak OIDC SSO (natív LW integráció)

### Mi volt a cél
User belép LW schoolba → LW megnyitja a Keycloak login oldalt → user hitelesít → LW visszairányít és létrehozza/frissíti a profilt automatikusan.

### Amit próbáltunk

#### 1.1 Régi Keycloak (sso.insta.hu) → LW OIDC
- **Konfiguráció:** Docker Compose, Ubuntu, Nginx reverse proxy, HTTPS/Let's Encrypt
- **Ütközött probléma:** `ERR_TOO_MANY_REDIRECTS` a callback fázisban
  - A Keycloak rosszul érzékelte a külső protokollt/hostot a proxy mögül
  - Kritikus headerek: `X-Forwarded-Proto`, `X-Forwarded-Host` – nem volt jól beállítva
- **Eredmény:** Nem sikerült az OIDC flow végigmenni

#### 1.2 Invalid scope probléma
- **Hiba:** `Invalid scopes: openid roles offline_access organization web-origins ...`
- **Ok:** Keycloak sok extra scope-ot küldött a token request-ben
- **Következmény:** Ha a token exchange nem sikerül → nincs ID token → LW mapping sem fut
- **Fix:** Csak `openid email profile` scope-ot szabad küldeni
- **Állapot:** A Railway-es Keycloakra ez még nincs élesben tesztelve

#### 1.3 Attribute mapping nem működött
- **Cél:** Keycloak custom attribútumok (teljesnev, munkakor, aruhaz, munkakezdet, ujkollega) → LW Custom User Fields
- **Amit LW support mondott (végső fejlesztői válasz):**
  - LW csak az id_token-t olvassa (nem a UserInfo endpointot, nem az access tokent)
  - A claim-nek top-level kell lennie az ID tokenben (nem `attributes.X` formában)
  - A claim neve pontosan, case-sensitive-en egyezzen az LW Attribute Mapping mezővel
  - Date/DateTime típusú LW field nem működik mapping-gel → Text mezőt kell használni
- **Ütközött probléma:** A Keycloak mapperek `attributes.X` nested formában adták ki a claimeket, nem top-level-en
- **Állapot:** Soha nem futott le sikeres end-to-end attribute mapping teszt élesben

#### 1.4 LW SSO oldal "disabled" volt
- A tesztelés során a support jelezte hogy az OpenID solution le van tiltva LW oldalon
- Ez blokolta a teljes OIDC flow-t amíg visszakapcsolták

#### 1.5 Railway Keycloak (sso-szerver-diego-keycloak-production.up.railway.app)
- Új deployment Railwayen, friss PostgreSQL DB-vel
- A régi sso.insta.hu konfig ide nincs átmásolva
- A LW-ben a redirect URI és client konfig nincs frissítve az új URL-re
- **Állapot:** End-to-end SSO teszt ezen a szerveren nem volt

---

## 2. Magic Link (backend SSO workaround)

### Ami MŰKÖDIK

#### 2.1 LW API email filter
```
GET /admin/api/v2/users?email=user@example.com → 200 OK
```
Az előző session logjaiban megerősítve: az LW API támogatja az email szűrést.
Egy API call elég a user ID-hoz, nem kell lapozni. (A jelenlegi kódbázisban lapozásos megoldás van – visszarakandó.)

#### 2.2 LW SSO link generálás
```
POST /admin/api/sso → 200 OK
{"user_id": "6a37...", "url": "https://academyhu.diego.hu/login?code=...", "success": true}
```
A magic link generálás megbízhatóan működik. Az URL egyszeri belépési link.

#### 2.3 /magic-link backend endpoint
A Railway backend `/magic-link?email=X&key=Y` endpointja generál és visszaad LW magic linket → redirect.
Böngészőben működik.

#### 2.4 LW Automation → webhook → backend
LW Automation "User signs in" trigger → POST /webhook/lw-login → backend eltárolja az emailt 30 percre.
Az automation és webhook mechanizmus működik.

### Ami NEM MŰKÖDÖTT

#### 2.5 Magic link mobilos app-ban
- **Probléma:** A LW mobilos app WebView-t használ
- **WebView vs rendszer böngésző:** A WebView és a rendszer böngésző (Chrome/Safari) nem osztja meg a session cookie-kat
- **Következmény:** Ha a magic link a WebView-ban nyílik meg, a user be van lépve a WebView-ban, de a rendszer böngészőben NEM
- **Ez az alapvető mobilos flow blokkológja**

#### 2.6 /megnyitas LW oldal gombja
- Volt egy LW oldal (academyhu.diego.hu/megnyitas) egy gombbal
- **Probléma 1:** Az oldal draft módban volt a tesztelés idején (Error oldalt adott)
- **Probléma 2:** A LW-s gomb elemnek nem volt URL/JS konfigurálva – csak vizuális elem volt
- **Próbáltuk:** A gomb HTML-jét megnézni, de a gombhoz csak link URL-t lehet rendelni az LW page builderben, JS-t nem közvetlenül a gomb-widget-re
- **Nem tudtuk megvalósítani:** A gomb kattintáskor automatikusan kitölti az emailt és a rendszer böngészőben nyit

#### 2.7 LW Custom Code / JS
- A user megnézte a LW Custom Code docs-ot (custom HTML blokk lehetséges)
- Még nem volt idő megvalósítani hogy a LW oldal JS-ből kiolvasva a window.LW.user.email (vagy hasonló) változót automatikusan a magic link URL-t nyissa rendszer böngészőben
- **Kockázat:** Nem ismert pontosan a LW JS globális objektum neve (verzió-függő)

---

## 3. Profil szinkronizáció (Keycloak → LW)

### Állapot
- **Kód:** Megírva, deployolva
- **Nem tesztelve:** A Keycloak valóban küld-e webhookot login után, és a backend feldolgozza-e
- **Függőség:** A vymalo/keycloak-webhook plugin telepítve van Railway Keycloakra, de az WEBHOOK_HTTP_BASE_URL beállítás nem biztos hogy helyes

---

## 4. Mobilos App → Rendszer böngésző flow

### Alapprobléma
A LW mobile app WebView-ja szigetelt – nem kommunikál a rendszer böngészővel.

### Megközelítések amiket megvizsgáltunk

| Megközelítés | Státusz | Probléma |
|---|---|---|
| Magic link WebView-ban nyílik | Nem jó | Session nem kerül át a rendszer böngészőbe |
| LW oldal gombja → rendszer böngésző | Részlegesen próbált | Draft mód, gombhoz nincs JS |
| Email küldés minden loginra | Elvetett | 500 login = 500 email |
| LW Automation → email magic linkkel | Elvetett | Spam, nincs user-kontroll |
| LW oldal gomb → backend /lw-login?email=X | Jelenlegi terv | LW JS context nem tesztelve |

---

## 5. Jelenlegi megközelítés (2026-06-25 implementált)

### Backend változtatások
- Rate limiting: max 1 magic link / 5 perc / email (spam védelem)
- `/lw-login?email=X` param kezelés: ha friss webhook és rate limit ok → magic link + cookie
- Cooldown oldal: ha 5 percen belül kér újat → "Kérj újat X perc múlva"
- 1 éves cookie: visszatérő usernél nincs szükség webhook-ra

### Mi még hiányzik

1. **LW oldal gomb JS** – window.LW.user.email (vagy ekvivalens) kiolvasása és rendszer böngészőben megnyitás
2. **LW API email filter visszarakása** a kódba (az előző sessionben működött, de a jelenlegi kódbázisban lapozásos megoldás van)
3. **LW Automation konfig** – az automation csak webhookot küldjön (emailt NE), a gomb az egyetlen trigger
4. **Keycloak OIDC scope fix** – ha/amikor a natív SSO-t is szeretnénk: csak `openid email profile`
5. **Keycloak redirect URI frissítés** – a LW-ben az OIDC konfig még a régi URL-t tartalmazza

---

## 6. Ismert technikai korlátok

- **LW password API:** Nincs ilyen. A usernek magának kell beállítani az LW jelszót.
- **LW Automation incoming webhook:** LW Automation csak küld webhookot, NEM fogad. Csak LW événtekre triggerelhet.
- **In-memory store:** A Railway backend újrainduláskor elveszíti a _recent_lw_logins és _magic_link_cooldowns dicteket.
- **LW Custom User Fields date típus:** Nem működik IdP mapping-gel. Text mező kell.
- **LW mobil WebView:** Teljesen izolált session a rendszer böngészőtől – ez a mobilos SSO alapproblémája.

---

## 7. Következő kipróbálandó lépések (prioritás sorrendben)

1. **LW oldal JS konzolban:** Bejelentkezve a LW school-ba, F12 konzolban megvizsgálni:
   `window.LW`, `window.LW.visitor`, `window.LW.user` stb. – mi van rajta, mi az email property neve
2. **LW Custom HTML blokk tesztelése:** Egy LW oldalon Custom HTML blokkot elhelyezni JS-sel
3. **Keycloak scope teszt:** Csak `openid email profile` scope-pal teszt login futtatása
4. **Keycloak webhook teszt:** Railway logban megnézni – érkezik-e webhook login után?
5. **LW email filter visszarakása a kódba:** `/v2/users?email=X` – 1 API call, nem lapozás

---

## 8. LW API email filter (2026-06-25 este)

### Mi nem ment
- `GET /admin/api/v2/users?email=X` → 200 OK de **üres lista** minden emailre
- `GET /admin/api/v2/users?email=X&items_per_page=10` → ugyanígy üres
- **Következtetés:** Az LW API email filter paraméter megbízhatatlan – jogosultsági vagy API verziós probléma

### Megoldás
- Visszaállás lapozásos megkeresésre (`page=1..N, items_per_page=50`) – ez biztosan működik

---

## 9. LW page builder változók button URL-ben (2026-06-25 este)

### Mi nem ment
- `{{user.email}}` beírva a gomb link URL mezőjébe → LW NEM helyettesíti be
- A szerver logban ez látszott: `GET /lw-login?email=%7B%7Buser.email%7D%7D` (literálisan jött át)
- Az automation webhook body-ban (`{"email": "{{user.email}}"}`) IGEN működik, page builderben NEM

### Megoldás
- `localStorage.getItem('lw_email')` – LW maga tárolja el a bejelentkezett user emailjét localStorage-ban
- Custom HTML blokk JS-sel olvassa ki és rakja bele a gomb URL-jébe

---

## 10. LW `window.LW` JavaScript objektum (2026-06-25 este)

### Mi nem ment
- `window.LW` → undefined (nem ez a neve)
- `window.LW.user.email` → undefined
- `window.LW.visitor.email` → undefined
- `/api/v2/users/me` saját tokennel → `{"errors": [...], "success": false}`

### Ami működik
- `localStorage.getItem('lw_email')` → visszaadja a bejelentkezett user emailjét (pl. `diego.learning.2025@gmail.com`)
- `getUserToken()` → Bearer tokent ad vissza (de nem JWT, email nem dekódolható belőle)

---

## 11. Admin fiók nem jelenik meg `/v2/users`-ban

### Megfigyelés
- `diego.learning.2025@gmail.com` az admin fiók → az LW API `/v2/users` listán NEM szerepel
- Normál learner fióknál a lapozásos megkeresés MŰKÖDIK
- **Tanulság:** A magic link flow csak learner fiókokra fog működni, admin fiókra nem

---

## 12. Jelenlegi működő állapot (2026-06-25 este)

### Ami KÉSZ és MŰKÖDIK
- Lapozásos user lookup learner fiókokra
- `/webhook/lw-login` webhook fogadás → email tárolás 30 percre
- Rate limiting: 5 perc cooldown per email
- `/lw-login?email=X` confirm oldal + magic link generálás
- Magic link → `/profile` redirect (nem főoldal)
- 1 éves cookie visszatérő usernél

### Ami MÉG HIÁNYZIK az éles deployhoz
- LW Custom HTML gomb a `/megnyitas` oldalon (kész a kód, berakandó LW-be)
- LW Automation konfig: "User signs in" → webhook (nem email)
- Teszt valódi mobilról

---

## 13. Security update szívás (2026-06-25 éjjel, commit c9e216b óta)

### Mi volt a probléma
- `c9e216b` commit ("security: HMAC-signed lw_email cookie + LW webhook secret verification")
  ETTőL KEZDVE SZÍVUNK
- **HMAC cookie aláírás** → régi cookie-k érvénytelenek lesznek, minden user ki lett lépve
- **Webhook secret** (Bearer Token) → LW Automation nem küldte a headert → 403 → webhook nem ment át → confirm oldal soha nem töltött ki
- **Confirm oldal eltávolítása** (`bfc7ec8`) → a `{{user.email}}`-es flow teljesen megszakadt

### Mi volt az eredeti jó állapot
- `add63d3` commit ("feat: webhook-alapu auto-login, confirm oldal, LW automation support")
- Egyszerű flow: webhook → _recent_lw_logins → confirm oldal (1 kattintás) → magic link → /profile

### Mit javítottunk (de még nem teljesen kész)
- Cookie aláírás visszavonva (nem szükséges a backend-only domainhez)
- Webhook secret marad: **Bearer Token** az LW Automationban kell
- Confirm oldal visszarakva, majd **auto-redirect**-re cserélve (nincs kattintás)
- page_size 50 → 200 (admin account is megtalálható lett)
- Email param prioritás: ha URL email eltér a cookie-tól → URL nyer
- Automation **disabled volt** – be kellett kapcsolni
- `test@example.com` email a webhookba: az LW Automation "Test" gombja küldi, nem igazi login

### Jelenlegi állapot (commit 98ab89d)
- Auto-redirect webhook alapján (3 perces TTL) – NINCS kész, nem redirect-el
- LW Automationban Bearer Token van beállítva
- LW oldal: Custom HTML blokk van, de a `{{user.email}}`-es automation redirect is fut
- Railway env: LW_WEBHOOK_SECRET nincs beállítva (warning logban de nem blokkolja)

### Ami még hiányzik
- Az auto-redirect valódi tesztelése (Railway deploy után)
- Ha nem megy: visszaállás `add63d3` commitra és onnan indulni
- LW_WEBHOOK_SECRET beállítása Railway-en (jelenleg üres)
