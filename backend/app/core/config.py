"""Application settings loaded from environment variables / .env file."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Environment-driven configuration for the CYBERGUARD backend."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    SUPABASE_URL: str
    SUPABASE_ANON_KEY: str
    SUPABASE_SERVICE_ROLE_KEY: str
    API_V1_PREFIX: str = "/api/v1"
    CORS_ORIGINS: str = "http://localhost:5173,http://localhost:3000"

    DATABASE_URL: str = "sqlite+aiosqlite:///./cyberguard.db"

    OPENROUTER_API_KEY: str = ""
    OPENROUTER_API_KEYS: str = ""
    OPENROUTER_MAX_KEYS: int = 10
    OPENROUTER_KEY_COOLDOWN_SECONDS: int = 60
    OPENROUTER_HEALTH_CHECK_INTERVAL_SECONDS: int = 30
    OPENROUTER_MODEL: str = "liquid/lfm-2.5-2.6b:free"
    OPENROUTER_FALLBACK_MODELS: str = "liquid/lfm-2.5-2.6b:free,google/gemma-4-26b-a4b-it:free,nvidia/nemotron-3.5-lightning:free,nex-agi/nex-n2.5-mini:free"

    ML_ENABLED: bool = True
    ML_MODELS_DIR: str = "ml/models"

    APP_TITLE: str = "CYBERGUARD API"
    APP_VERSION: str = "0.2.0"

    @property
    def async_database_url(self) -> str:
        """Ensure standard postgresql:// URLs are translated to asyncpg."""
        url = self.DATABASE_URL.strip() if self.DATABASE_URL else "sqlite+aiosqlite:///./cyberguard.db"
        if url.startswith("postgres://"):
            return url.replace("postgres://", "postgresql+asyncpg://", 1)
        if url.startswith("postgresql://") and not url.startswith("postgresql+asyncpg://"):
            return url.replace("postgresql://", "postgresql+asyncpg://", 1)
        return url

    @property
    def fallback_models_list(self) -> list[str]:
        return [m.strip() for m in self.OPENROUTER_FALLBACK_MODELS.split(",") if m.strip()]

    @property
    def openrouter_keys_list(self) -> list[str]:
        """Collect and deduplicate OpenRouter API keys up to OPENROUTER_MAX_KEYS."""
        import os

        keys: list[str] = []
        # 1. Comma/newline-separated list
        if self.OPENROUTER_API_KEYS:
            for k in self.OPENROUTER_API_KEYS.replace("\n", ",").split(","):
                cleaned = k.strip()
                if cleaned and cleaned not in keys:
                    keys.append(cleaned)

        # 2. Check environment variables OPENROUTER_API_KEY_1 .. OPENROUTER_API_KEY_N
        for i in range(1, self.OPENROUTER_MAX_KEYS + 1):
            env_val = os.environ.get(f"OPENROUTER_API_KEY_{i}", "").strip()
            if env_val and env_val not in keys:
                keys.append(env_val)

        # 3. Fallback to single primary key
        if self.OPENROUTER_API_KEY:
            cleaned = self.OPENROUTER_API_KEY.strip()
            if cleaned and cleaned not in keys:
                keys.append(cleaned)

        return keys[: max(1, self.OPENROUTER_MAX_KEYS)]

    @property
    def cors_origins_list(self) -> list[str]:
        """Parse the comma-separated CORS_ORIGINS variable into a list."""
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    """Return the cached singleton Settings instance."""
    return Settings()
