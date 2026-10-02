"""Configuration for the CyberGuard demo server — pydantic-settings.

Every value comes from the environment — no hardcoded URLs, keys or paths.
`Settings` is a pydantic-settings `BaseSettings` model: with no explicit
mapping, values are read from the process environment layered over a local
`.env` file (looked up in the working directory, then the project root;
real environment variables win, and empty environment values are ignored so
they can't shadow a `.env` entry). `load_settings(env)` accepts an explicit
mapping instead (used by tests).

Each variable has a primary name and, where the demo server historically
shipped one, a legacy `CYBERGUARD_*` alias (see `.env.example`); the
primary name wins when both are set. Missing/contradictory required values
raise ConfigError with a clear message at startup — never lazily
mid-shipment. The API key is held as a `SecretStr` (redacted in
`repr()`), never logged, never written to the response store, and
`describe()` returns a log-safe view of the settings.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import AliasChoices, Field, SecretStr, model_validator
from pydantic_core import ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict

# Project root (demo-server-project/), resolved from this file's location so
# .env / campaigns / scenarios lookups work from any working directory.
PROJECT_ROOT = Path(__file__).resolve().parents[2]

REDACTED = "***REDACTED***"


class ConfigError(RuntimeError):
    """Raised when configuration is missing or contradictory."""


# Primary env names paired with their legacy CYBERGUARD_* aliases.
_PAIRS: dict[str, tuple[str, ...]] = {
    "GATEWAY_URL": ("GATEWAY_URL", "CYBERGUARD_GATEWAY_URL"),
    "PROJECT_SLUG": ("PROJECT_SLUG", "CYBERGUARD_PROJECT_SLUG"),
    "MASTER_API_KEY": ("MASTER_API_KEY", "CYBERGUARD_MASTER_KEY"),
    "KEY_FILE": ("KEY_FILE", "CYBERGUARD_KEY_FILE"),
}

# Reverse map: every accepted env name -> the primary name.
_ENV_TO_PRIMARY: dict[str, str] = {
    env: primary for primary, names in _PAIRS.items() for env in names
}


class Settings(BaseSettings):
    """Every configurable value of the demo server, from env/.env only.

    See `.env.example` for a documented copy of every variable.
    """

    model_config = SettingsConfigDict(
        # Later files win, so the working directory's .env beats the
        # project root's (same rule as the historical loader).
        env_file=(PROJECT_ROOT / ".env", ".env"),
        env_ignore_empty=True,
        extra="ignore",
        populate_by_name=True,
    )

    # --- Required: project identity + gateway key ---
    project_slug: str = Field(
        default="",
        validation_alias=AliasChoices("PROJECT_SLUG", "CYBERGUARD_PROJECT_SLUG"),
        description="CyberGuard project slug to ship as",
    )
    master_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("MASTER_API_KEY", "CYBERGUARD_MASTER_KEY"),
        description="gateway master key (inline)",
    )
    key_file: str | None = Field(
        default=None,
        validation_alias=AliasChoices("KEY_FILE", "CYBERGUARD_KEY_FILE"),
        description="file holding the gateway key",
    )

    # --- Gateway connection ---
    gateway_url: str = Field(
        default="http://localhost:8000/api/v1",
        validation_alias=AliasChoices("GATEWAY_URL", "CYBERGUARD_GATEWAY_URL"),
        description="backend API base URL; ships to {gateway_url}/p/{slug}/gateway",
    )
    ship_timeout_s: int = Field(default=10, validation_alias="SHIP_TIMEOUT_S")
    ship_max_retries: int = Field(default=3, validation_alias="SHIP_MAX_RETRIES")

    # --- Traffic generator defaults ---
    default_rate: float = Field(default=10.0, validation_alias="DEFAULT_RATE")
    default_duration: float = Field(default=60.0, validation_alias="DEFAULT_DURATION")

    # --- Campaigns ---
    default_timescale: float = Field(default=1.0, validation_alias="DEFAULT_TIMESCALE")
    campaigns_dir: str = Field(default="./campaigns", validation_alias="CAMPAIGNS_DIR")
    reports_dir: str = Field(
        default="./data/campaign_reports", validation_alias="REPORTS_DIR"
    )

    # --- Local service / storage ---
    demo_port: int = Field(default=8020, validation_alias="DEMO_PORT")
    store_path: str = Field(default="data/responses.db", validation_alias="STORE_PATH")

    @model_validator(mode="after")
    def _validate(self) -> Settings:
        if not self.project_slug.strip():
            raise ConfigError(
                "PROJECT_SLUG is required (slug of the CyberGuard project to "
                "ship as; legacy alias CYBERGUARD_PROJECT_SLUG also accepted) "
                "— set it in the environment or .env"
            )

        direct_key = (
            self.master_api_key.get_secret_value() if self.master_api_key else ""
        )
        if direct_key and self.key_file:
            raise ConfigError(
                "Set only one of MASTER_API_KEY or KEY_FILE, not both "
                "(legacy aliases CYBERGUARD_MASTER_KEY / CYBERGUARD_KEY_FILE "
                "count as the same variable)"
            )
        if not direct_key and not self.key_file:
            raise ConfigError(
                "A gateway key is required: set MASTER_API_KEY (inline) or "
                "KEY_FILE (path to a file holding the key), in the "
                "environment or .env (legacy aliases CYBERGUARD_MASTER_KEY / "
                "CYBERGUARD_KEY_FILE also accepted)"
            )
        if self.key_file:
            key_path = Path(self.key_file).expanduser()
            if not key_path.is_file():
                raise ConfigError(f"KEY_FILE does not exist: {key_path}")
            try:
                key_text = key_path.read_text(encoding="utf-8").strip()
            except OSError as exc:
                raise ConfigError(f"KEY_FILE unreadable: {exc}") from exc
            if not key_text:
                raise ConfigError(f"KEY_FILE is empty: {key_path}")
            self.master_api_key = SecretStr(key_text)
        return self

    @property
    def master_key(self) -> str:
        """The gateway key as a plain string (for the Authorization header)."""
        return self.master_api_key.get_secret_value() if self.master_api_key else ""

    @property
    def gateway_endpoint(self) -> str:
        """Full gateway URL this client ships to: {url}/p/{slug}/gateway."""
        return f"{self.gateway_url.rstrip('/')}/p/{self.project_slug}/gateway"

    def describe(self) -> dict[str, object]:
        """Log-safe view of the settings (key redacted)."""
        return {
            "gateway_url": self.gateway_url,
            "project_slug": self.project_slug,
            "gateway_endpoint": self.gateway_endpoint,
            "master_key": REDACTED,
            "ship_timeout_s": self.ship_timeout_s,
            "ship_max_retries": self.ship_max_retries,
            "demo_port": self.demo_port,
            "store_path": self.store_path,
            "default_rate": self.default_rate,
            "default_duration": self.default_duration,
            "default_timescale": self.default_timescale,
            "campaigns_dir": self.campaigns_dir,
            "reports_dir": self.reports_dir,
        }


# Historical names kept as aliases so existing imports keep working.
Config = Settings


def _normalize_env_dict(env: dict[str, str]) -> dict[str, str]:
    """Collapse an explicit env mapping to primary env names.

    Primary names beat legacy CYBERGUARD_* aliases; empty values are
    ignored so they can't shadow a real value.
    """
    best: dict[str, str] = {}
    for name, value in env.items():
        primary = _ENV_TO_PRIMARY.get(name, name)
        if not value.strip():
            continue
        if primary not in best or name == primary:
            best[primary] = value
    return best


def _friendly_config_error(exc: ValidationError) -> ConfigError:
    """Translate a pydantic ValidationError into clear env-var guidance."""
    parts: list[str] = []
    for error in exc.errors():
        loc = error["loc"][0] if error["loc"] else ""
        env_name = str(loc).upper()
        etype = error["type"]
        if etype == "missing":
            parts.append(f"{env_name} is required")
        elif etype in ("float_parsing", "float_type"):
            parts.append(f"{env_name} must be a number")
        elif etype in ("int_parsing", "int_type"):
            parts.append(f"{env_name} must be an integer")
        else:
            parts.append(f"{env_name}: {error['msg']}")
    return ConfigError("; ".join(parts) or "invalid configuration")


def load_settings(env: dict[str, str] | None = None) -> Settings:
    """Build a Settings from environment variables, failing fast.

    With no explicit `env` mapping, values come from the process environment
    layered over a local `.env` file (cwd, then project root); variables
    already set in the environment take precedence over `.env`, and empty
    environment values are ignored so they can't shadow a `.env` entry.

    Required (primary name; legacy CYBERGUARD_* alias accepted):
      PROJECT_SLUG                project slug to ship as
      MASTER_API_KEY or KEY_FILE  gateway key (exactly one)
    Optional (default):
      GATEWAY_URL        (http://localhost:8000/api/v1)
      DEFAULT_RATE       (10 — generate events per minute)
      DEFAULT_DURATION   (60 — generate run length, minutes)
      DEFAULT_TIMESCALE  (1.0 — campaign run stage-delay multiplier)
      CAMPAIGNS_DIR      (./campaigns)
      REPORTS_DIR        (./data/campaign_reports)
      SHIP_TIMEOUT_S     (10)
      SHIP_MAX_RETRIES   (3)
      DEMO_PORT          (8020)
      STORE_PATH         (data/responses.db)
    """
    try:
        if env is None:
            return Settings()
        return Settings(**_normalize_env_dict(env))
    except ValidationError as exc:
        raise _friendly_config_error(exc) from None


# Historical name kept as an alias so existing imports keep working.
load_config = load_settings
