# Keycloak Railway deployment - hibakeresés

## A cél

Keycloak 25.0.0 + vymalo webhook provider futtatása Railway-en, custom Docker image-ből.

## Jelenlegi Dockerfile állapot

- Multi-stage build: Alpine letölti a webhook JAR-okat, Keycloak image veszi át
- Webhook JAR-ok: `keycloak-webhook-provider-core` + `keycloak-webhook-provider-http` v0.10.0-rc.1
- `kc.sh build` a Dockerfile-ban (optimized image)
- `start --optimized` runtime-ban (nem épít újra)
- Build-time ENV-ek: `KC_TRANSACTION_XA_ENABLED=false`, `KC_HEALTH_ENABLED=true`, `KC_HTTP_MANAGEMENT_HEALTH_ENABLED=false`

## Eddig próbált dolgok és tanulságok

### 1. Webhook JAR inkompatibilitás
- **Hiba:** `ERROR: com.vymalo.keycloak.webhook.AbstractWebhookEventListenerFactory`
- **Ok:** Csak a HTTP JAR volt letöltve, de a core JAR is szükséges (két külön modul)
- **Fix:** Mindkét JAR letöltése: `keycloak-webhook-provider-core` + `keycloak-webhook-provider-http`

### 2. "The executable `start` could not be found"
- **Hiba:** Railway `startCommand = "start"` volt a railway.toml-ban
- **Ok:** Railway önállóan próbálta futtatni a "start" szót mint executable-t, a Dockerfile ENTRYPOINT-ot figyelmen kívül hagyva
- **Fix:** startCommand eltávolítása, Dockerfile CMD-re bízni

### 3. OOM (Out of Memory) - `Killed`
- **Hiba:** `kc.sh: line 169: Killed` - Java process megölve
- **Ok:** `start` (és `start-dev`) runtime-ban is futtat egy `kc.sh build` fázist (`-Dkc.config.build-and-exit=true`), ami OOM-ot okoz Railway free tier memóriakorlátján (512MB)
- **Fix:** `start --optimized` flag - kihagyja a runtime build fázist; a build a Dockerfile-ban történik

### 4. ARJUNA object store hiba
- **Hiba:** `ARJUNA012391: Could not initialize object store 'null' of type ShadowNoFileLockStore`
- **Ok:** Narayana transaction manager file-alapú object store-t próbál írni, az útvonal null (nem konfigurált)
- **Próbált fix #1:** `KC_TRANSACTION_XA_ENABLED=false` runtime változóként - NEM hatásos `--optimized` módban, mert a build-time konfig be van égetve
- **Fix:** `KC_TRANSACTION_XA_ENABLED=false` ENV a Dockerfile-ban (build-time), + `mkdir -p` a startCommand-ban + `QUARKUS_TRANSACTION_MANAGER_OBJECT_STORE_DIRECTORY` beállítva

### 5. Health check timeout - "service unavailable"
- **Hiba:** `1/1 replicas never became healthy!` - `/health/ready` nem válaszol
- **Ok #1:** `healthcheckTimeout = 30` túl rövid, Keycloak lassabban indul
- **Ok #2:** Keycloak 25-ben a `/health/ready` endpoint a 9000-es management porton van, NEM a 8080-as főporton. Railway a főportot ellenőrzi.
- **Próbált fix:** `KC_HTTP_MANAGEMENT_HEALTH_ENABLED=false` - letiltja a management portot, de NEM mozgatja a health endpointot a 8080-ra
- **Jelenlegi megközelítés:** healthcheckPath eltávolítva, Railway TCP-szintű port ellenőrzést végez

### 6. start-dev mód OOM
- **Próbált:** `start-dev` mód hogy elkerüljük a Postgres igényt
- **Hiba:** `start-dev` is futtat runtime build lépést, ugyanolyan OOM mint a `start`
- **Tanulság:** Az egyetlen módja az OOM elkerülésének: `kc.sh build` a Dockerfile-ban + `start --optimized`

## Jelenlegi állapot

- Dockerfile: optimized image, JAR-ok benne, health ENV-ek beégetve
- railway.toml: startCommand mkdir + `start --optimized`, healthcheck eltávolítva
- Railway Variables: KC_BOOTSTRAP_ADMIN_*, KC_HOSTNAME, KC_HTTP_ENABLED, KC_PROXY_HEADERS, KC_HEALTH_ENABLED, KC_HTTP_MANAGEMENT_HEALTH_ENABLED=false, KC_TRANSACTION_XA_ENABLED=false, QUARKUS_*

## Nyitott kérdések

- A `/health/ready` Keycloak 25-ben valóban csak a 9000-es porton van? Hogyan lehet azt Railway-en elérni?
- `KC_LEGACY_OBSERVABILITY_INTERFACE=true` esetleg áthozza a 8080-ra?
- Kell-e Postgres a stabil működéshez, vagy H2 + volume megoldja?

### 7. Health check port probléma - "/health" 9000-es porton
- **Hiba:** `1/1 replicas never became healthy!` - Keycloak fut, de health check fail
- **Ok:** Keycloak 25-ben a `/health/ready` endpoint a **9000-es management porton** van, NEM a 8080-as főporton. Railway a főportot (8080) ellenőrzi HTTP-vel.
- **Próbált fix:** `KC_HTTP_MANAGEMENT_HEALTH_ENABLED=false` - letiltja a management portot, de NEM mozgatja a health endpointot a 8080-ra
- **Jelenlegi megközelítés:** Railway dashboard-on health check path törölve, TCP port check marad

### 8. /opt/keycloak/data permission denied
- **Hiba:** `mkdir: cannot create directory '/opt/keycloak/data/tx-object-store': Permission denied`
- **Ok:** A volume van csatolva, de a Keycloak user nem tud írni az `/opt/keycloak/data` könyvtárba
- **Fix:** `/tmp/keycloak-tx-object-store` használata a startCommand-ban

### 9. Silent OOM crash az Infinispan indulasa utan
- **Hiba:** Log megszakad az Infinispan sor utan, nincs error -- kernel OOM kill (SIGKILL)
- **Ok:** `-XX:MaxRAMPercentage=70` + `-XX:MaxMetaspaceSize=256m` --> Railway memoriakeretet meghaladja
- **Fix:** `JAVA_OPTS_APPEND` Dockerfile-ban beallitva:
  ```
  -Xms64m -Xmx384m -XX:MaxMetaspaceSize=128m -XX:+UseSerialGC -XX:MinHeapFreeRatio=10 -XX:MaxHeapFreeRatio=20
  ```
  - Heap: max 384MB (alapertelmezett ~700MB helyett)
  - Metaspace: max 128MB (alapertelmezett 256MB helyett)
  - SerialGC: kisebb GC overhead, mint G1GC
  - HeapFreeRatio: agressziv heap visszaadas az OS-nek
  - Teljes becsult JVM memoria: ~592MB (384 + 128 + ~80 native)

## Jelenlegi allapot

- Dockerfile: optimized image, JAR-ok benne, `KC_HEALTH_ENABLED=true`, `KC_HTTP_MANAGEMENT_HEALTH_ENABLED=false`, `JAVA_OPTS_APPEND` beeegetve
- railway.toml: startCommand `mkdir /tmp/...` + `start --optimized`, nincs healthcheckPath
- Railway dashboard: health check path torolve
- Railway Variables: KC_BOOTSTRAP_ADMIN_*, KC_HOSTNAME, KC_HTTP_ENABLED, KC_PROXY_HEADERS, KC_HEALTH_ENABLED, KC_HTTP_MANAGEMENT_HEALTH_ENABLED=false, KC_TRANSACTION_XA_ENABLED=false, QUARKUS_*
- **Kovetkezo lepes:** Deploy es tesztelni, hogy az OOM fix megoldja-e az indulast

