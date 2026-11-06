"""Environment-only settings for the Kestrel control plane."""
from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False, env_prefix="KESTREL_")
    app_name: str = "Kestrel"
    environment: str = "production"
    database_url: str = "sqlite:////var/lib/kestrel/kestrel.db"
    media_path: str = "/var/lib/kestrel/media"
    # Parent for the per-call libvirt key directory. Empty = the system temp dir, which
    # both systemd units make private to the service with PrivateTmp=true.
    runtime_dir: str = ""
    max_upload_mb: int = Field(default=8192, ge=1, le=65536)
    session_hours: int = Field(default=12, ge=1, le=720)
    session_cookie: str = "kestrel_session"
    secret_key: SecretStr
    encryption_key: SecretStr
    trusted_host: str = "vps.mydomain.xyz"
    secure_cookies: bool = True
    login_ip_limit: int = Field(default=10, ge=1, le=100)
    login_account_limit: int = Field(default=8, ge=1, le=100)
    login_lock_minutes: int = Field(default=15, ge=1, le=1440)
    worker_interval_seconds: int = Field(default=2, ge=1, le=60)
    worker_concurrency: int = Field(default=8, ge=1, le=64)
    metrics_interval_seconds: int = Field(default=10, ge=5, le=300)
    metrics_retention_days: int = Field(default=7, ge=1, le=365)

settings = Settings()
