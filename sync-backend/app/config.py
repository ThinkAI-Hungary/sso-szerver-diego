from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    # Keycloak Admin API
    keycloak_base_url: str  # pl. https://your-keycloak.up.railway.app
    keycloak_realm: str = "diego"
    keycloak_client_id: str  # dedikalt service account client ID
    keycloak_client_secret: str

    # LearnWorlds API (egyszerű API kulcs - meglévő műveletek)
    learnworlds_api_key: str
    learnworlds_school: str  # pl. academyhu.diego.hu

    # LearnWorlds OAuth2 (SSO link generáláshoz szükséges)
    learnworlds_client_id: str = ""
    learnworlds_client_secret: str = ""

    # Magic link végpont védelme
    magic_link_secret: str = ""  # üres = nincs védelem (csak fejlesztésben)

    # Webhook biztonsag
    webhook_secret: str = ""  # ugyanaz, mint KC WEBHOOK_HTTP_SHARED_SECRET

    # Port (Railway automatikusan beallitja)
    port: int = 8000


settings = Settings()
