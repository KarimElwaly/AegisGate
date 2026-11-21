from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # General
    AEGIS_ENV: Literal["dev", "staging", "prod", "test"] = "dev"
    AEGIS_HOST: str = "0.0.0.0"
    AEGIS_PORT: int = 8088
    AEGIS_LOG_LEVEL: str = "INFO"

    # Security
    AEGIS_SECRET_KEY: str = "default-dev-secret-key-32-bytes-minimum-length-012345"
    AEGIS_JWT_ALGORITHM: str = "HS256"
    AEGIS_JWT_EXPIRY_MINUTES: int = 1440

    # Persistence
    DATABASE_URL: str = "sqlite+aiosqlite:///./aegisgate.db"
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_KEY_PREFIX: str = "aegisgate:"
    USE_IN_MEMORY_REDIS: bool = False

    # Pipeline Performance Timeouts (ms)
    DEFAULT_SCANNER_TIMEOUT_MS: int = 500
    MAX_EVALUATION_TIMEOUT_MS: int = 3000

    # Vault
    PII_VAULT_TTL_SECONDS: int = 3600

    # Observability
    OTEL_ENABLED: bool = False
    OTEL_EXPORTER_OTLP_ENDPOINT: str = "http://localhost:4317"
    PROMETHEUS_METRICS_ENABLED: bool = True

    # OIDC Configuration
    OIDC_ENABLED: bool = False
    OIDC_ISSUER: str = ""
    OIDC_CLIENT_ID: str = ""
    OIDC_JWKS_URI: str = ""
    OIDC_ROLE_CLAIM: str = "groups"

    # Local ML & Judge
    LOCAL_ONNX_MODEL_DIR: str = "./models"
    LLM_JUDGE_BASE_URL: str = "http://localhost:11434/v1"
    LLM_JUDGE_API_KEY: str = "ollama"
    LLM_JUDGE_MODEL: str = "llama3.2"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()

