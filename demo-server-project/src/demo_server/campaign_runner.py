"""Simulated client-traffic campaign runner and reporting (SIM-1, JSON-driven).

Campaign definitions live as validated JSON files in the configured
campaigns directory (`CAMPAIGNS_DIR`, default `./campaigns`, falling back
to the project root). Each file describes one simulated traffic sequence;
`{attacker_ip}` placeholders inside stage payloads are substituted at build
time with the `--attacker-ip` override or the campaign's
`default_attacker_ip`.

Execution runs each stage in order with timescale-scaled delays against
the CyberGuard gateway and reports stage-by-stage severity matches and
closed-loop auto-enforcement verdicts. Completed runs are persisted as
JSON reports in `REPORTS_DIR`.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .config import PROJECT_ROOT
from .shipper import GatewayShipper

# Fallback location for campaign JSON when ./campaigns doesn't exist in cwd.
PROJECT_CAMPAIGNS_DIR = PROJECT_ROOT / "campaigns"

# The only gateway actions a campaign stage may target, and the severity
# scale the gateway's analyzers emit (validated at load time).
ALLOWED_ACTIONS = frozenset(
    {"analyze_network", "analyze_ato", "analyze_email", "analyze_url", "analyze_media"}
)
ALLOWED_SEVERITIES = frozenset({"low", "medium", "high", "critical"})

# Placeholder replaced with the simulated source IP in stage payloads.
ATTACKER_IP_TOKEN = "{attacker_ip}"


class CampaignError(RuntimeError):
    """Raised when a campaign definition is missing or fails validation."""


@dataclass
class CampaignStage:
    name: str
    action: str
    expected_severity: str
    delay_s: float
    payload_builder: Callable[[str | None], dict[str, Any]]
    description: str = ""

    def build_payload(self, attacker_ip: str | None = None) -> dict[str, Any]:
        return self.payload_builder(attacker_ip)


@dataclass
class StageResult:
    stage_name: str
    action: str
    attempts: int
    status: str
    severity: str
    expected_severity: str
    verdict: str
    risk_score: int | None
    blocked_matched: bool
    latency_ms: int | None
    error: str | None
    ok: bool


@dataclass
class CampaignSummary:
    campaign_name: str
    attacker_ip: str | None
    timescale: float
    total_stages: int
    succeeded: int
    failed: int
    auto_blocked_count: int
    elapsed_s: float
    results: list[StageResult] = field(default_factory=list)

    @property
    def all_matched_expected_severity(self) -> bool:
        return all(
            r.severity.lower() == r.expected_severity.lower()
            for r in self.results
            if r.ok
        )

    @property
    def all_auto_blocked(self) -> bool:
        return len(self.results) > 0 and all(
            r.verdict == "blocked_permanently" and r.blocked_matched
            for r in self.results
            if r.ok
        )


@dataclass
class Campaign:
    name: str
    description: str
    stages: list[CampaignStage]
    default_attacker_ip: str | None = None
    source_file: str | None = None


# --- Loading and validation ---


def resolve_campaigns_dir(explicit: str | Path | None = None) -> Path:
    """Resolve the campaigns directory.

    Order: an explicit argument (used by the CLI with `Settings.campaigns_dir`)
    wins; otherwise the `CAMPAIGNS_DIR` environment variable; otherwise
    `./campaigns` in the working directory; finally the project root's
    `campaigns/` (so the CLI works from any cwd). The default value
    "./campaigns" is treated like the unset case — cwd first, project root
    as fallback.
    """
    if explicit and Path(explicit) != Path("./campaigns"):
        return Path(explicit)
    env_dir = os.environ.get("CAMPAIGNS_DIR", "").strip()
    if env_dir:
        return Path(env_dir)
    cwd_candidate = Path.cwd() / "campaigns"
    if cwd_candidate.is_dir():
        return cwd_candidate
    return PROJECT_CAMPAIGNS_DIR


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CampaignError(message)


def _require_nonempty_str(value: Any, what: str, source: str) -> str:
    _require(
        isinstance(value, str) and value.strip(),
        f"{source}: {what} must be a non-empty string",
    )
    return value.strip()


def _payload_builder(
    payload: dict[str, Any], default_ip: str | None, stage_name: str, campaign_name: str
) -> Callable[[str | None], dict[str, Any]]:
    """Build a payload builder that substitutes {attacker_ip} tokens."""

    def build(attacker_ip: str | None = None) -> dict[str, Any]:
        ip = attacker_ip or default_ip
        _require(
            ip,
            f"campaign '{campaign_name}' stage '{stage_name}' uses {ATTACKER_IP_TOKEN} "
            "but no attacker IP was given (--attacker-ip) and the campaign "
            "has no default_attacker_ip",
        )

        def walk(node: Any) -> Any:
            if isinstance(node, str):
                return node.replace(ATTACKER_IP_TOKEN, ip)
            if isinstance(node, list):
                return [walk(item) for item in node]
            if isinstance(node, dict):
                return {key: walk(item) for key, item in node.items()}
            return node

        return walk(payload)

    return build


def load_campaign_file(path: Path) -> Campaign:
    """Parse and validate one campaign JSON file into a Campaign."""
    source = f"campaign file {path}"
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise CampaignError(f"{source} is unreadable: {exc}") from exc
    except ValueError as exc:
        raise CampaignError(f"{source} is not valid JSON: {exc}") from exc

    _require(isinstance(raw, dict), f"{source}: top level must be a JSON object")
    name = _require_nonempty_str(raw.get("name"), "name", source)
    _require(
        path.stem == name,
        f"{source}: campaign name '{name}' does not match filename '{path.stem}.json'",
    )
    description = raw.get("description", "")
    _require(isinstance(description, str), f"{source}: description must be a string")
    default_ip = raw.get("default_attacker_ip")
    if default_ip is not None:
        default_ip = _require_nonempty_str(default_ip, "default_attacker_ip", source)

    stages_raw = raw.get("stages")
    _require(
        isinstance(stages_raw, list) and stages_raw,
        f"{source}: stages must be a non-empty list",
    )

    stages: list[CampaignStage] = []
    seen: set[str] = set()
    for entry in stages_raw:
        _require(isinstance(entry, dict), f"{source}: each stage must be an object")
        stage_name = _require_nonempty_str(entry.get("name"), "stage name", source)
        _require(
            stage_name not in seen,
            f"{source}: duplicate stage name '{stage_name}'",
        )
        seen.add(stage_name)
        where = f"{source} stage '{stage_name}'"

        action = _require_nonempty_str(entry.get("action"), "action", where)
        _require(
            action in ALLOWED_ACTIONS,
            f"{where}: action '{action}' is not a gateway action "
            f"(allowed: {', '.join(sorted(ALLOWED_ACTIONS))})",
        )
        expected = _require_nonempty_str(
            entry.get("expected_severity"), "expected_severity", where
        )
        _require(
            expected.lower() in ALLOWED_SEVERITIES,
            f"{where}: expected_severity '{expected}' is not one of "
            f"{', '.join(sorted(ALLOWED_SEVERITIES))}",
        )
        delay = entry.get("delay_s", 0.0)
        _require(
            isinstance(delay, (int, float))
            and not isinstance(delay, bool)
            and delay >= 0,
            f"{where}: delay_s must be a number >= 0",
        )
        stage_description = entry.get("description", "")
        _require(
            isinstance(stage_description, str), f"{where}: description must be a string"
        )
        payload = entry.get("payload")
        _require(
            isinstance(payload, dict) and payload,
            f"{where}: payload must be a non-empty object",
        )

        stages.append(
            CampaignStage(
                name=stage_name,
                action=action,
                expected_severity=expected.lower(),
                delay_s=float(delay),
                payload_builder=_payload_builder(payload, default_ip, stage_name, name),
                description=stage_description,
            )
        )

    return Campaign(
        name=name,
        description=description,
        stages=stages,
        default_attacker_ip=default_ip,
        source_file=str(path),
    )


def load_campaigns(directory: str | Path | None = None) -> dict[str, Campaign]:
    """Load and validate every *.json campaign in the campaigns directory.

    The directory is resolved via `resolve_campaigns_dir`. A missing
    directory is a configuration error naming the path checked.
    """
    dir_path = resolve_campaigns_dir(directory)
    if not dir_path.is_dir():
        raise CampaignError(
            f"campaigns directory not found: {dir_path} — set CAMPAIGNS_DIR "
            "or place campaign JSON files there"
        )
    campaigns: dict[str, Campaign] = {}
    for path in sorted(dir_path.glob("*.json")):
        camp = load_campaign_file(path)
        campaigns[camp.name] = camp
    if not campaigns:
        raise CampaignError(f"no campaign JSON files (*.json) found in {dir_path}")
    return campaigns


def get_campaign(name: str, directory: str | Path | None = None) -> Campaign:
    """Return one campaign by name, raising CampaignError for unknown names."""
    campaigns = load_campaigns(directory)
    if name not in campaigns:
        valid = ", ".join(sorted(campaigns.keys()))
        raise CampaignError(f"Unknown campaign '{name}'. Available: {valid}")
    return campaigns[name]


# --- Execution ---


def run_campaign(
    shipper: GatewayShipper,
    campaign: Campaign,
    timescale: float = 1.0,
    attacker_ip: str | None = None,
    sleeper: Callable[[float], None] = time.sleep,
) -> CampaignSummary:
    """Execute each stage of a campaign with scaled delays and return summary."""
    t0 = time.monotonic()
    results: list[StageResult] = []
    auto_blocked_count = 0

    for i, stage in enumerate(campaign.stages):
        if i > 0 and stage.delay_s > 0:
            delay = stage.delay_s * timescale
            if delay > 0:
                sleeper(delay)

        t_stage = time.monotonic()
        payload = stage.build_payload(attacker_ip)
        print(
            f"Forwarding client event to CyberGuard API... "
            f"stage '{stage.name}' (action={stage.action})"
        )
        ship_res = shipper.ship(stage.action, payload)
        stage_lat_ms = int((time.monotonic() - t_stage) * 1000)

        severity = ""
        verdict = ""
        risk_score = None
        blocked_matched = False

        if isinstance(ship_res.response, dict):
            severity = str(ship_res.response.get("severity", ""))
            verdict = str(ship_res.response.get("verdict", ""))
            risk_score = ship_res.response.get("risk_score")
            blocked_matched = bool(
                ship_res.response.get("blocked_indicator_matched", False)
            )
            if blocked_matched or verdict == "blocked_permanently":
                auto_blocked_count += 1
                print(
                    "CyberGuard API returned verdict: BLOCK. "
                    "Client app will deny access."
                )

        res = StageResult(
            stage_name=stage.name,
            action=stage.action,
            attempts=ship_res.attempts,
            status=ship_res.status or "transport_error",
            severity=severity,
            expected_severity=stage.expected_severity,
            verdict=verdict,
            risk_score=risk_score,
            blocked_matched=blocked_matched,
            latency_ms=stage_lat_ms,
            error=ship_res.error,
            ok=ship_res.ok,
        )
        results.append(res)

    elapsed = time.monotonic() - t0
    succeeded = sum(1 for r in results if r.ok)
    failed = sum(1 for r in results if not r.ok)

    return CampaignSummary(
        campaign_name=campaign.name,
        attacker_ip=attacker_ip,
        timescale=timescale,
        total_stages=len(campaign.stages),
        succeeded=succeeded,
        failed=failed,
        auto_blocked_count=auto_blocked_count,
        elapsed_s=elapsed,
        results=results,
    )


# --- Reporting ---


def serialize_summary(summary: CampaignSummary) -> dict[str, Any]:
    """JSON-safe dict of a summary (for the persisted report file)."""
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "campaign_name": summary.campaign_name,
        "attacker_ip": summary.attacker_ip,
        "timescale": summary.timescale,
        "total_stages": summary.total_stages,
        "succeeded": summary.succeeded,
        "failed": summary.failed,
        "auto_blocked_count": summary.auto_blocked_count,
        "elapsed_s": round(summary.elapsed_s, 3),
        "all_matched_expected_severity": summary.all_matched_expected_severity,
        "all_auto_blocked": summary.all_auto_blocked,
        "results": [
            {
                "stage_name": r.stage_name,
                "action": r.action,
                "attempts": r.attempts,
                "status": r.status,
                "severity": r.severity,
                "expected_severity": r.expected_severity,
                "verdict": r.verdict,
                "risk_score": r.risk_score,
                "blocked_matched": r.blocked_matched,
                "latency_ms": r.latency_ms,
                "error": r.error,
                "ok": r.ok,
            }
            for r in summary.results
        ],
    }


def write_campaign_report(summary: CampaignSummary, reports_dir: str | Path) -> Path:
    """Persist a run summary as JSON under the reports directory.

    The directory is created on demand; the filename is timestamped so
    repeated runs never overwrite each other.
    """
    dir_path = Path(reports_dir)
    dir_path.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    path = dir_path / f"{summary.campaign_name}_{stamp}.json"
    path.write_text(json.dumps(serialize_summary(summary), indent=2), encoding="utf-8")
    return path


def format_campaign_table(summary: CampaignSummary) -> str:
    headers = [
        "STAGE",
        "ACTION",
        "STATUS",
        "SEVERITY",
        "EXP_SEV",
        "VERDICT",
        "BLOCKED_MATCH",
        "LAT_MS",
    ]
    rows = []
    for r in summary.results:
        rows.append(
            [
                r.stage_name,
                r.action,
                str(r.status),
                r.severity or "—",
                r.expected_severity,
                r.verdict or "—",
                "TRUE" if r.blocked_matched else "false",
                str(r.latency_ms) if r.latency_ms is not None else "—",
            ]
        )

    widths = [
        max(len(h), *(len(row[i]) for row in rows)) if rows else len(h)
        for i, h in enumerate(headers)
    ]
    lines = []
    header_line = "  ".join(h.ljust(w) for h, w in zip(headers, widths))
    lines.append(header_line)
    lines.append("-" * len(header_line))
    for row in rows:
        lines.append("  ".join(c.ljust(w) for c, w in zip(row, widths)))

    lines.append("")
    lines.append(f"Campaign      : {summary.campaign_name}")
    if summary.attacker_ip:
        lines.append(f"Simulated IP  : {summary.attacker_ip}")
    lines.append(f"Timescale     : {summary.timescale}")
    lines.append(
        f"Stages Forwarded: {summary.total_stages} (Succeeded: {summary.succeeded}, Failed: {summary.failed})"
    )
    lines.append(f"Auto-Blocked  : {summary.auto_blocked_count}/{summary.total_stages}")
    lines.append(f"Elapsed Time  : {summary.elapsed_s:.2f}s")
    sev_match = (
        "ALL MATCHED" if summary.all_matched_expected_severity else "MISMATCH DETECTED"
    )
    lines.append(f"Severity Match: {sev_match}")
    if summary.all_auto_blocked:
        lines.append(
            "CLOSED-LOOP PROOF: CyberGuard API returned verdict: BLOCK. "
            "Client app will deny access."
        )

    return "\n".join(lines)
