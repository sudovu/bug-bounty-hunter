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

    # Automated Periodic Scanning & Seeding
    AUTO_SCAN_ENABLED: bool = True
    AUTO_SCAN_INTERVAL_MINUTES: int = 60
    AUTO_SEED_DEFAULT_PROGRAM: bool = True
    AUTO_SCAN_TARGET_FILTER: str = "ewnet.com.np"  # Restrict automated scheduler strictly to ewnet.com.np targets

    # Reporting & Audit Identity
    DEFAULT_REPORT_AUTHOR: str = "Bhuwan Gautam (IT Officer, Everest Wireless Network Pvt. Ltd.)"

    # Security & SSRF Safeguards
    BLOCK_PRIVATE_NETWORKS: bool = True
    BLOCK_CLOUD_METADATA: bool = True
    DEFAULT_ALLOWLIST_MODE: str = "STRICT"

    @property
    def effective_alert_from_email(self) -> str:
        # If user explicitly set ALERT_FROM_EMAIL and it's not the dummy example, use it
        if self.ALERT_FROM_EMAIL and self.ALERT_FROM_EMAIL != "scanner-alerts@example.com":
            return self.ALERT_FROM_EMAIL
        # Otherwise default to SMTP_USERNAME (e.g. Gmail strictly requires From to match username)
        if self.SMTP_USERNAME and "@" in self.SMTP_USERNAME:
            return self.SMTP_USERNAME
        return self.ALERT_FROM_EMAIL

    @property
    def effective_alert_to_email(self) -> str:
        if self.ALERT_TO_EMAIL and self.ALERT_TO_EMAIL != "security-researcher@example.com":
            return self.ALERT_TO_EMAIL
        # If not set, default to SMTP_USERNAME (send alerts to the configured user)
        if self.SMTP_USERNAME and "@" in self.SMTP_USERNAME:
            return self.SMTP_USERNAME
        return self.ALERT_TO_EMAIL

    @property
    def is_email_enabled(self) -> bool:
        if self.EMAIL_NOTIFICATIONS_ENABLED:
            return True
        # Auto-enable if SMTP host and username are provided
        return bool(self.SMTP_HOST and self.SMTP_USERNAME)

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()
