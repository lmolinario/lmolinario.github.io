from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Digital Risk Scanner"
    app_env: str = "development"
    app_debug: bool = False

    database_url: str
    redis_url: str

    scan_cache_hours: int = 24
    scan_rate_limit_per_hour: int = 60
    admin_api_key: str = ""

    stripe_secret_key: str = ""
    stripe_publishable_key: str = ""
    stripe_webhook_secret: str = ""
    stripe_report_price_eur_cents: int = 2900

    app_base_url: str = "http://localhost:8000"
    public_frontend_url: str = "https://lmolinario.github.io/tools/domain-risk-scan/"
    reports_storage_dir: str = "storage/reports"

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=False,
        extra="ignore",
    )


settings = Settings()