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
    # Service-role DSN used by Alembic migrations (bypasses RLS).
    # Falls back to DATABASE_URL when empty.
    MIGRATION_DATABASE_URL: str = ""

    # Organization accounts are frozen ("coming soon") until the Orgs Phase.
    ORG_ENABLED: bool = False

    # Real-time pipeline infrastructure (RT-1 / RT-3)
    REDIS_URL: str = "redis://localhost:6379"
    ARQ_QUEUE_NAME: str = "cyberguard_email"
    ARQ_MAX_JOBS: int = 10
    ARQ_JOB_TIMEOUT: int = 300
    WORKER_CONCURRENCY: int = 4
    GOOGLE_PUBSUB_VERIFICATION_TOKEN: str = ""  # set via env; webhook validates this
    GMAIL_PUBSUB_TOPIC: str = "projects/<your-project>/topics/cyberguard-gmail"
    GMAIL_PUBSUB_AUDIENCE: str | None = None  # optional JWT audience

    # Retry and backoff tuning (RT-10)
    RETRY_BASE_DELAY_S: int = 5
    RETRY_MAX_RETRIES: int = 5
    RETRY_JITTER_ENABLED: bool = True


    # --- Email connectors (Phase 1-2): Gmail only; own Google OAuth client ---
    GOOGLE_GMAIL_CLIENT_ID: str = ""
    GOOGLE_GMAIL_CLIENT_SECRET: str = ""
    GOOGLE_GMAIL_REDIRECT_URI: str = "http://localhost:8000/api/v1/connectors/gmail/callback"
    # Where the Gmail OAuth callback redirects the browser afterwards.
    FRONTEND_CONNECTORS_URL: str = "http://localhost:5173/email-connectors"
    # Fernet key encrypting provider tokens at rest. Generate with:
    #   uv run python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    CONNECTOR_TOKEN_KEY: str = ""
    CONNECTOR_OAUTH_STATE_TTL_SECONDS: int = 600
    GMAIL_CONNECTOR_ENABLED: bool = True

    # --- Event email notifications (Phase 7) ---
    # Empty SMTP host = DB-logged delivery backend (hackathon-demo safe):
    # the email is rendered and persisted to notification_logs.
    # When set, SMTP delivery is attempted best-effort and falls back to
    # DB logging on any failure so the demo never crashes.
    NOTIFICATION_SMTP_HOST: str = ""
    NOTIFICATION_SMTP_PORT: int = 587
    NOTIFICATION_FROM_ADDRESS: str = "cyberguard-alerts@localhost"
    NOTIFICATION_SMTP_USERNAME: str = ""
    NOTIFICATION_SMTP_PASSWORD: str = ""

    # Multi-Provider Orchestration (Groq, Gemini, OpenRouter)
    LLM_PROVIDERS: str = "groq,gemini,openrouter"
    LLM_COOLDOWN_SECONDS: int = 60
    LLM_HEALTH_CHECK_INTERVAL_SECONDS: int = 30

    # OpenRouter
    OPENROUTER_API_KEY: str = ""
    OPENROUTER_API_KEYS: str = ""
    OPENROUTER_MAX_KEYS: int = 10
    OPENROUTER_KEY_COOLDOWN_SECONDS: int = 60
    OPENROUTER_HEALTH_CHECK_INTERVAL_SECONDS: int = 30
    OPENROUTER_MODEL: str = "liquid/lfm-2.5-2.6b:free"
    OPENROUTER_FALLBACK_MODELS: str = "liquid/lfm-2.5-2.6b:free,google/gemma-4-26b-a4b-it:free,nvidia/nemotron-3.5-lightning:free,nex-agi/nex-n2.5-mini:free"

    # Groq (Ultra-low latency inference: Llama 3.3 70B, Llama 3.1 8B, Mixtral)
    GROQ_API_KEY: str = ""
    GROQ_API_KEYS: str = ""
    GROQ_MAX_KEYS: int = 10
    GROQ_KEY_COOLDOWN_SECONDS: int = 60
    GROQ_HEALTH_CHECK_INTERVAL_SECONDS: int = 30
    GROQ_MODEL: str = "llama-3.3-70b-versatile"
    GROQ_FALLBACK_MODELS: str = "llama-3.3-70b-versatile,llama-3.1-8b-instant"

    # Gemini (Google GenAI: Gemini 2.0 Flash, Gemini 1.5 Flash)
    GEMINI_API_KEY: str = ""
    GEMINI_API_KEYS: str = ""
    GEMINI_MAX_KEYS: int = 10
    GEMINI_KEY_COOLDOWN_SECONDS: int = 60
    GEMINI_HEALTH_CHECK_INTERVAL_SECONDS: int = 30
    GEMINI_MODEL: str = "gemini-2.0-flash"
    GEMINI_FALLBACK_MODELS: str = "gemini-2.0-flash,gemini-1.5-flash"

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
    def groq_keys_list(self) -> list[str]:
        """Collect and deduplicate Groq API keys up to GROQ_MAX_KEYS."""
        import os

        keys: list[str] = []
        if self.GROQ_API_KEYS:
            for k in self.GROQ_API_KEYS.replace("\n", ",").split(","):
                cleaned = k.strip()
                if cleaned and cleaned not in keys:
                    keys.append(cleaned)

        for i in range(1, max(1, self.GROQ_MAX_KEYS) + 1):
            env_val = os.environ.get(f"GROQ_API_KEY_{i}", "").strip()
            if env_val and env_val not in keys:
                keys.append(env_val)

        if self.GROQ_API_KEY:
            cleaned = self.GROQ_API_KEY.strip()
            if cleaned and cleaned not in keys:
                keys.append(cleaned)

        return keys[: max(1, self.GROQ_MAX_KEYS)]

    @property
    def gemini_keys_list(self) -> list[str]:
        """Collect and deduplicate Gemini API keys up to GEMINI_MAX_KEYS."""
        import os

        keys: list[str] = []
        if self.GEMINI_API_KEYS:
            for k in self.GEMINI_API_KEYS.replace("\n", ",").split(","):
                cleaned = k.strip()
                if cleaned and cleaned not in keys:
                    keys.append(cleaned)

        for i in range(1, max(1, self.GEMINI_MAX_KEYS) + 1):
            env_val = os.environ.get(f"GEMINI_API_KEY_{i}", "").strip()
            if env_val and env_val not in keys:
                keys.append(env_val)

        if self.GEMINI_API_KEY:
            cleaned = self.GEMINI_API_KEY.strip()
            if cleaned and cleaned not in keys:
                keys.append(cleaned)

        # Fallback to standard GOOGLE_API_KEY if present
        google_env = os.environ.get("GOOGLE_API_KEY", "").strip()
        if google_env and google_env not in keys:
            keys.append(google_env)

        return keys[: max(1, self.GEMINI_MAX_KEYS)]

    @property
    def groq_fallback_models_list(self) -> list[str]:
        return [m.strip() for m in self.GROQ_FALLBACK_MODELS.split(",") if m.strip()]

    @property
    def gemini_fallback_models_list(self) -> list[str]:
        return [m.strip() for m in self.GEMINI_FALLBACK_MODELS.split(",") if m.strip()]

    @property
    def llm_providers_list(self) -> list[str]:
        return [p.strip().lower() for p in self.LLM_PROVIDERS.split(",") if p.strip()]

    @property
    def cors_origins_list(self) -> list[str]:
        """Parse the comma-separated CORS_ORIGINS variable into a list."""
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    """Return the cached singleton Settings instance."""
    return Settings()
