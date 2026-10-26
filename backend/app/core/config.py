"""Application Configuration Module

Loads and validates all settings from environment variables or .env file.
"""
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "BugBountyHunterBot"
    APP_ENV: str = "development"
    DEBUG: bool = True
    SECRET_KEY: str = "default-dev-secret-change-in-production-min-32-chars-long"
    API_V1_PREFIX: str = "/api/v1"

    # Database
    DATABASE_URL: str = "sqlite:///./bug_bounty_bot.db"

    # SMTP Configuration
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USERNAME: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    ALERT_FROM_EMAIL: str = "scanner-alerts@example.com"
    ALERT_TO_EMAIL: str = "security-researcher@example.com"
    SMTP_USE_TLS: bool = True
    EMAIL_NOTIFICATIONS_ENABLED: bool = False

    # Scanner Controls & Limits
    MAX_CONCURRENT_SCANS: int = 3
    DEFAULT_RATE_LIMIT_RPS: float = 2.0
    SCAN_TIMEOUT_SECONDS: int = 30
    GLOBAL_EMERGENCY_STOP: bool = False

    # Security & SSRF Safeguards
    BLOCK_PRIVATE_NETWORKS: bool = True
    BLOCK_CLOUD_METADATA: bool = True
    DEFAULT_ALLOWLIST_MODE: str = "STRICT"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()
