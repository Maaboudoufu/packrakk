from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: str = Field(
        default="postgresql+psycopg://appuser:change_me@10.0.20.2:5432/appdb",
        alias="DATABASE_URL",
    )
    storage_dir: Path = Field(default=Path("./storage"), alias="PACKRAKK_STORAGE_DIR")
    scanner_timeout_seconds: int = Field(
        default=600, alias="PACKRAKK_SCANNER_TIMEOUT_SECONDS"
    )
    cors_origins: str = Field(
        default="http://localhost:5173,http://localhost:3000",
        alias="BACKEND_CORS_ORIGINS",
    )

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def scans_storage_dir(self) -> Path:
        return self.storage_dir / "scans"


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.scans_storage_dir.mkdir(parents=True, exist_ok=True)
    return settings
