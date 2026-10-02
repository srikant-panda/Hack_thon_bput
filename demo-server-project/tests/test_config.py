"""Config fail-fast tests (S2)."""

import pytest

from demo_server.config import ConfigError, Settings, load_config

BASE = {
    "CYBERGUARD_PROJECT_SLUG": "demo",
    "CYBERGUARD_MASTER_KEY": "ds_demo_secret_value_123",
}

SETTING_VARS = [
    "PROJECT_SLUG",
    "MASTER_API_KEY",
    "KEY_FILE",
    "GATEWAY_URL",
    "DEFAULT_RATE",
    "DEFAULT_DURATION",
    "CAMPAIGNS_DIR",
    "REPORTS_DIR",
    "CYBERGUARD_PROJECT_SLUG",
    "CYBERGUARD_MASTER_KEY",
    "CYBERGUARD_KEY_FILE",
    "CYBERGUARD_GATEWAY_URL",
    "SHIP_TIMEOUT_S",
    "SHIP_MAX_RETRIES",
    "DEMO_PORT",
    "STORE_PATH",
]


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch, tmp_path):
    """Isolate os.environ for the env=None paths and keep cwd out of the repo
    so a developer's real .env can never leak into these tests.

    chdir alone is not enough: Settings.env_file also includes the absolute
    project-root .env, so point it at the tmp dir instead (tests that write
    a cwd .env still work — same file, resolved from tmp_path)."""
    for var in SETTING_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        Settings,
        "model_config",
        {**Settings.model_config, "env_file": (tmp_path / ".env",)},
    )


def test_defaults_applied():
    cfg = load_config(dict(BASE))
    assert cfg.gateway_url == "http://localhost:8000/api/v1"
    assert cfg.ship_timeout_s == 10
    assert cfg.ship_max_retries == 3
    assert cfg.demo_port == 8020
    assert cfg.store_path == "data/responses.db"
    assert cfg.gateway_endpoint == "http://localhost:8000/api/v1/p/demo/gateway"


def test_missing_slug_fails_fast():
    env = {k: v for k, v in BASE.items() if k != "CYBERGUARD_PROJECT_SLUG"}
    with pytest.raises(ConfigError, match="CYBERGUARD_PROJECT_SLUG"):
        load_config(env)


def test_missing_key_fails_fast():
    env = {k: v for k, v in BASE.items() if k != "CYBERGUARD_MASTER_KEY"}
    with pytest.raises(ConfigError, match="gateway key is required"):
        load_config(env)


def test_both_key_sources_fails_fast():
    env = dict(BASE, CYBERGUARD_KEY_FILE="/tmp/key.txt")
    with pytest.raises(ConfigError, match="only one"):
        load_config(env)


def test_key_file_read(tmp_path):
    kf = tmp_path / "gateway.key"
    kf.write_text("ds_demo_from_file\n")
    env = {"CYBERGUARD_PROJECT_SLUG": "demo", "CYBERGUARD_KEY_FILE": str(kf)}
    cfg = load_config(env)
    assert cfg.master_key == "ds_demo_from_file"


def test_key_file_missing_fails_fast():
    env = {"CYBERGUARD_PROJECT_SLUG": "demo", "CYBERGUARD_KEY_FILE": "/nonexistent/key"}
    with pytest.raises(ConfigError, match="does not exist"):
        load_config(env)


def test_key_file_empty_fails_fast(tmp_path):
    kf = tmp_path / "empty.key"
    kf.write_text("   \n")
    env = {"CYBERGUARD_PROJECT_SLUG": "demo", "CYBERGUARD_KEY_FILE": str(kf)}
    with pytest.raises(ConfigError, match="empty"):
        load_config(env)


@pytest.mark.parametrize(
    "var,value",
    [
        ("SHIP_TIMEOUT_S", "abc"),
        ("SHIP_MAX_RETRIES", "1.5"),
        ("DEMO_PORT", "eighty-twenty"),
    ],
)
def test_bad_int_vars_fail_fast(var, value):
    with pytest.raises(ConfigError, match=var):
        load_config(dict(BASE, **{var: value}))


def test_key_never_in_repr_or_describe():
    cfg = load_config(dict(BASE))
    assert "ds_demo_secret_value_123" not in repr(cfg)
    assert "ds_demo_secret_value_123" not in str(cfg)
    assert "ds_demo_secret_value_123" not in str(cfg.describe())
    assert cfg.describe()["master_key"] == "***REDACTED***"


def test_dotenv_file_is_loaded(tmp_path):
    (tmp_path / ".env").write_text(
        "# comment\n"
        "CYBERGUARD_PROJECT_SLUG=dotenv-slug\n"
        "export CYBERGUARD_MASTER_KEY='ds_demo_from_dotenv'\n"
        "DEMO_PORT=8099\n"
        "BROKEN LINE WITHOUT EQUALS\n"
        "\n"
    )
    cfg = load_config()
    assert cfg.project_slug == "dotenv-slug"
    assert cfg.master_key == "ds_demo_from_dotenv"
    assert cfg.demo_port == 8099


def test_environment_wins_over_dotenv(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text(
        "CYBERGUARD_PROJECT_SLUG=dotenv-slug\n"
        "CYBERGUARD_MASTER_KEY=ds_demo_from_dotenv\n"
    )
    monkeypatch.setenv("CYBERGUARD_PROJECT_SLUG", "env-slug")
    cfg = load_config()
    assert cfg.project_slug == "env-slug"
    assert cfg.master_key == "ds_demo_from_dotenv"


def test_empty_env_var_does_not_shadow_dotenv(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text(
        "CYBERGUARD_PROJECT_SLUG=dotenv-slug\n"
        "CYBERGUARD_MASTER_KEY=ds_demo_from_dotenv\n"
    )
    monkeypatch.setenv("CYBERGUARD_MASTER_KEY", "")
    cfg = load_config()
    assert cfg.master_key == "ds_demo_from_dotenv"


def test_missing_everything_mentions_env_or_dotenv():
    with pytest.raises(ConfigError, match=r"CYBERGUARD_PROJECT_SLUG.*\.env"):
        load_config()


def test_no_dotenv_still_fails_fast():
    with pytest.raises(ConfigError):
        load_config()


def test_primary_names_accepted():
    """Primary (non-legacy) env names load like the CYBERGUARD_* aliases."""
    cfg = load_config(
        {
            "PROJECT_SLUG": "primary-proj",
            "MASTER_API_KEY": "ds_demo_primary_key",
            "GATEWAY_URL": "https://gw.example.com/api/v1",
        }
    )
    assert cfg.project_slug == "primary-proj"
    assert cfg.master_key == "ds_demo_primary_key"
    assert cfg.gateway_url == "https://gw.example.com/api/v1"


def test_primary_name_wins_over_legacy_alias():
    cfg = load_config(
        {
            "PROJECT_SLUG": "primary-proj",
            "CYBERGUARD_PROJECT_SLUG": "legacy-proj",
            "MASTER_API_KEY": "ds_demo_key_123",
        }
    )
    assert cfg.project_slug == "primary-proj"


def test_new_setting_defaults():
    cfg = load_config(dict(BASE))
    assert cfg.default_rate == 10.0
    assert cfg.default_duration == 60.0
    assert cfg.campaigns_dir == "./campaigns"
    assert cfg.reports_dir == "./data/campaign_reports"


def test_new_settings_parsed_from_env():
    cfg = load_config(
        {
            **BASE,
            "DEFAULT_RATE": "25.5",
            "DEFAULT_DURATION": "30",
            "CAMPAIGNS_DIR": "/tmp/camps",
            "REPORTS_DIR": "/tmp/reps",
        }
    )
    assert cfg.default_rate == 25.5
    assert cfg.default_duration == 30.0
    assert cfg.campaigns_dir == "/tmp/camps"
    assert cfg.reports_dir == "/tmp/reps"


def test_invalid_default_rate_fails_fast():
    with pytest.raises(ConfigError, match="DEFAULT_RATE must be a number"):
        load_config({**BASE, "DEFAULT_RATE": "fast"})


def test_describe_includes_new_settings():
    cfg = load_config(dict(BASE))
    d = cfg.describe()
    assert d["default_rate"] == 10.0
    assert d["campaigns_dir"] == "./campaigns"
    assert d["reports_dir"] == "./data/campaign_reports"
