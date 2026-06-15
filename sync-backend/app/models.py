from pydantic import BaseModel


class KeycloakEventDetails(BaseModel):
    """Keycloak event payload reszletei (LOGIN, REGISTER, stb.)"""

    # Keycloak user ID (sub)
    userId: str | None = None
    # Client ID, amelyen at a login tortent
    clientId: str | None = None
    # IP cim
    ipAddress: str | None = None
    # Email (csak regisztracional szokott szerepelni)
    email: str | None = None


class KeycloakWebhookPayload(BaseModel):
    """
    vymalo/keycloak-webhook altal kuldott HTTP POST body.
    Teljes esemeny struktúra: https://github.com/vymalo/keycloak-webhook
    """

    # Esemeny tipusa: LOGIN, REGISTER, UPDATE_PROFILE, stb.
    type: str
    # Realm neve
    realmId: str | None = None
    # Keycloak user ID
    userId: str | None = None
    # Reszletek (opcionalisan tartalmazza az email-t, clientId-t stb.)
    details: KeycloakEventDetails | None = None
    # Esemeny idopontja (epoch ms)
    time: int | None = None
