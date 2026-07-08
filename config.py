import os
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    host: str = "0.0.0.0"
    port: int = 8000
    secret_key: str
    daemon_api_key_path: str = "/run/amnezia-daemon/api.key"
    use_reverse_proxy: bool = False
    auth_mode: str = "oidc"
    oidc_client_id: str | None = None
    oidc_client_secret: str | None = None
    oidc_discovery_url: str | None = None
    totp_secrets_file: str = "/opt/amnezia-auth/totp_secrets.json"
    handshakes_db_path: str = "/opt/amnezia-auth/handshakes.db"
    sessions_db_path: str = "/opt/amnezia-auth/sessions.db"
    totp_issuer_name: str = "AmneziaWG Portal"
    totp_account_name_template: str = "VPN ({peer_name} - {peer_ip})"
    vpn_interface: str = "awg0"
    inactivity_timeout_seconds: int = 900
    max_session_seconds: int = 28800
    handshake_silence_threshold_seconds: int = 3600
    enable_audit_logging: bool = True

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
