from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    # Keycloak Admin API
    keycloak_url: str  # pl. https://your-keycloak.up.railway.app
    keycloak_realm: str = "master"
    keycloak_client_id: str  # dedikalt service account client ID
    keycloak_client_secret: str

    # LearnWorlds API
    learnworlds_api_key: str
    learnworlds_school_id: str  # pl. academyhu.diego.hu

    # Webhook biztonsag
    webhook_secret: str  # ugyanaz, mint KC WEBHOOK_HTTP_SHARED_SECRET

    # Port (Railway automatikusan beallitja)
    port: int = 8000


settings = Settings()
