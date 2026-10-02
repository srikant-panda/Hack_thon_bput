"""Tests for JSON campaign loading, validation, and settings-driven defaults."""

import json

import httpx
import pytest

import demo_server.cli as cli_mod
import demo_server.traffic as traffic_mod
from demo_server.campaign_runner import (
    PROJECT_CAMPAIGNS_DIR,
    CampaignError,
    get_campaign,
    load_campaign_file,
    load_campaigns,
    resolve_campaigns_dir,
)
from demo_server.cli import main
from demo_server.config import load_config
from demo_server.shipper import GatewayShipper
from demo_server.store import ResponseStore

SECRET = "ds_demo_json_campaign_test_key"
ENV = {"CYBERGUARD_PROJECT_SLUG": "json-proj", "CYBERGUARD_MASTER_KEY": SECRET}

VALID = {
    "name": "mini_camp",
    "description": "smallest valid campaign",
    "default_attacker_ip": "198.51.100.1",
    "stages": [
        {
            "name": "stage1",
            "action": "analyze_network",
            "expected_severity": "high",
            "delay_s": 0.1,
            "payload": {"flows": [{"dest_ip": "{attacker_ip}", "port": 4444}]},
        }
    ],
}


def write_campaign(tmp_path, data, filename=None):
    path = tmp_path / (filename or f"{data.get('name', 'unnamed')}.json")
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("CAMPAIGNS_DIR", raising=False)


def test_builtin_campaigns_all_valid(tmp_path):
    """Every shipped campaign JSON parses, validates, and builds payloads."""
    campaigns = load_campaigns()
    assert set(campaigns) == {
        "cred_stuffing",
        "exfil_spike",
        "c2_beacon_wave",
        "apt_mixed",
    }
    for camp in campaigns.values():
        assert camp.source_file is not None
        assert len(camp.stages) >= 3
        assert camp.default_attacker_ip
        for stage in camp.stages:
            payload = stage.build_payload(None)  # default IP must substitute everywhere
            flat = json.dumps(payload)
            assert "{attacker_ip}" not in flat


def test_apt_mixed_spans_both_analyzers():
    """apt_mixed is the multi-stage APT lifecycle across ato + network."""
    camp = get_campaign("apt_mixed")
    actions = {s.action for s in camp.stages}
    assert actions == {"analyze_ato", "analyze_network"}
    assert len(camp.stages) >= 5


def test_attacker_ip_override_substitutes(tmp_path):
    camp = get_campaign("c2_beacon_wave")
    payload = camp.stages[0].build_payload("203.0.113.55")
    assert payload["flows"][0]["dest_ip"] == "203.0.113.55"
    default_payload = camp.stages[0].build_payload(None)
    assert default_payload["flows"][0]["dest_ip"] == "198.51.100.23"


def test_missing_attacker_ip_without_default_errors(tmp_path):
    data = {**VALID, "default_attacker_ip": None}
    camp = load_campaign_file(write_campaign(tmp_path, data))
    with pytest.raises(CampaignError, match="no attacker IP was given"):
        camp.stages[0].build_payload(None)


def test_invalid_json_raises(tmp_path):
    path = tmp_path / "broken_camp.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(CampaignError, match="not valid JSON"):
        load_campaign_file(path)


@pytest.mark.parametrize(
    "mutation, match",
    [
        (lambda d: d.pop("name"), "name must be a non-empty string"),
        (lambda d: d.update(stages=[]), "stages must be a non-empty list"),
        (lambda d: d["stages"][0].update(action="analyze_hax"), "not a gateway action"),
        (
            lambda d: d["stages"][0].update(expected_severity="apocalyptic"),
            "expected_severity",
        ),
        (lambda d: d["stages"][0].update(delay_s=-1), "delay_s must be a number >= 0"),
        (
            lambda d: d["stages"][0].update(payload=[]),
            "payload must be a non-empty object",
        ),
        (lambda d: d["stages"].append(dict(d["stages"][0])), "duplicate stage name"),
    ],
)
def test_schema_validation_failures(tmp_path, mutation, match):
    data = json.loads(json.dumps(VALID))
    mutation(data)
    path = write_campaign(tmp_path, data)
    with pytest.raises(CampaignError, match=match):
        load_campaign_file(path)


def test_name_filename_mismatch_rejected(tmp_path):
    with pytest.raises(CampaignError, match="does not match filename"):
        load_campaign_file(write_campaign(tmp_path, VALID, filename="other_name.json"))


def test_missing_campaigns_dir_errors(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(CampaignError, match="campaigns directory not found"):
        load_campaigns(tmp_path / "nonexistent")


def test_resolve_campaigns_dir_prefers_cwd_then_project_root(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # No ./campaigns in cwd -> project root fallback (which has the 4 built-ins)
    assert resolve_campaigns_dir() == PROJECT_CAMPAIGNS_DIR
    (tmp_path / "campaigns").mkdir()
    assert resolve_campaigns_dir() == tmp_path / "campaigns"


# --- Settings-driven generate defaults (DEFAULT_RATE / DEFAULT_DURATION) ---


@pytest.fixture()
def mock_env(monkeypatch, tmp_path):
    """Patch build_components + generate so `generate` runs instantly and
    captures its rate/duration kwargs."""
    config = load_config({**ENV, "STORE_PATH": str(tmp_path / "responses.db")})
    store = ResponseStore(tmp_path / "responses.db")

    def handler(request):
        return httpx.Response(200, json={"event_id": "e1", "severity": "low"})

    shipper = GatewayShipper(
        config,
        store,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        sleeper=lambda _s: None,
    )
    monkeypatch.setattr(
        cli_mod, "build_components", lambda env=None: (config, store, shipper)
    )

    captured = {}

    def fake_generate(shipper, book, mix, **kwargs):
        captured.update(kwargs)
        s = traffic_mod.TrafficSummary()
        s.events_shipped = 0
        s.elapsed_s = 0.0
        return s

    monkeypatch.setattr(traffic_mod, "generate", fake_generate)
    return captured


def test_generate_defaults_from_settings(mock_env):
    assert main(["generate"]) == 0
    assert mock_env["rate_per_min"] == 10.0  # DEFAULT_RATE default
    assert mock_env["duration_min"] == 60.0  # DEFAULT_DURATION default


def test_generate_flags_override_settings(mock_env):
    config = load_config({**ENV, "DEFAULT_RATE": "25", "DEFAULT_DURATION": "30"})
    assert config.default_rate == 25.0 and config.default_duration == 30.0

    assert main(["generate", "--rate", "50", "--duration", "30"]) == 0
    assert mock_env["rate_per_min"] == 50.0
    assert mock_env["duration_min"] == 30.0


# --- Settings-driven campaign timescale (DEFAULT_TIMESCALE) ---


def test_default_timescale_default_and_parsing():
    cfg = load_config(ENV)
    assert cfg.default_timescale == 1.0
    cfg = load_config({**ENV, "DEFAULT_TIMESCALE": "0.25"})
    assert cfg.default_timescale == 0.25
    with pytest.raises(Exception, match="DEFAULT_TIMESCALE must be a number"):
        load_config({**ENV, "DEFAULT_TIMESCALE": "fast"})


def test_campaign_run_uses_default_timescale_from_settings(monkeypatch, tmp_path):
    """`campaign run --timescale` omitted -> Settings.default_timescale."""
    config = load_config(
        {
            **ENV,
            "STORE_PATH": str(tmp_path / "responses.db"),
            "REPORTS_DIR": str(tmp_path / "reports"),
            "DEFAULT_TIMESCALE": "0.5",
        }
    )
    store = ResponseStore(tmp_path / "responses.db")

    def handler(request):
        return httpx.Response(200, json={"event_id": "e_ts", "severity": "critical"})

    shipper = GatewayShipper(
        config,
        store,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        sleeper=lambda _s: None,
    )
    monkeypatch.setattr(
        cli_mod, "build_components", lambda env=None: (config, store, shipper)
    )

    captured = {}

    def fake_run_campaign(shipper, camp, **kwargs):
        captured.update(kwargs)
        from demo_server.campaign_runner import CampaignSummary

        return CampaignSummary(
            campaign_name=camp.name,
            attacker_ip=None,
            timescale=kwargs["timescale"],
            total_stages=1,
            succeeded=0,
            failed=0,
            auto_blocked_count=0,
            elapsed_s=0.0,
        )

    monkeypatch.setattr(cli_mod, "run_campaign", fake_run_campaign)
    code = main(["campaign", "run", "--name", "c2_beacon_wave"])
    assert code == 0
    assert captured["timescale"] == 0.5
