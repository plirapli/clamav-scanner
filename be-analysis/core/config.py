from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    APP_NAME: str = "BE Analysis"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = False
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DATABASE_URL: str = "sqlite:///be_analysis.db"
    OPENAI_API_KEY: str = ""
    OPENAI_BASE_URL: str = "https://openrouter.ai/api/v1"
    OPENAI_MODEL: str = "openai/gpt-4o-mini"
    MONGO_URI: str = "mongodb://localhost:27017"
    MONGO_DATABASE: str = "scanner_service"
    MONGO_COLLECTION: str = "scan_logs"


@lru_cache
def get_settings() -> Settings:
    return Settings()