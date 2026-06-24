import os
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    host: str = "0.0.0.0"
    port: int = 8000
    secret_key: str
    auth_mode: str = "oidc"
    oidc_client_id: str | None = None
    oidc_client_secret: str | None = None
    oidc_discovery_url: str | None = None
    totp_secrets_file: str = "/opt/amnezia-auth/totp_secrets.json"
    vpn_interface: str = "awg0"
    inactivity_timeout_seconds: int = 900
    max_session_seconds: int = 28800

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
