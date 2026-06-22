import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    host: str = "0.0.0.0"
    port: int = 8000
    secret_key: str
    oidc_client_id: str
    oidc_client_secret: str
    oidc_discovery_url: str
    vpn_interface: str = "awg0"
    inactivity_timeout_seconds: int = 900
    max_session_seconds: int = 28800
    allowed_subnets: str = "0.0.0.0/0"

    @property
    def allowed_subnets_list(self) -> list[str]:
        return [s.strip() for s in self.allowed_subnets.split(",")] if self.allowed_subnets else []

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()
