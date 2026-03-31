from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Digital Risk Scanner"
    app_env: str = "development"
    app_debug: bool = True

    database_url: str
    redis_url: str

    scan_cache_hours: int = 24

    stripe_secret_key: str = ""
    stripe_publishable_key: str = ""
    stripe_webhook_secret: str = ""
    stripe_report_price_eur_cents: int = 2900

    app_base_url: str = "http://localhost:8000"
    reports_storage_dir: str = "storage/reports"

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=False,
        extra="ignore",
    )


settings = Settings()