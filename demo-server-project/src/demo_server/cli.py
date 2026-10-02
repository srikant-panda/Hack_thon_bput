"""Typer command-line interface: demo-server / python -m demo_server.

Command wiring only — configuration lives in :mod:`demo_server.config`,
HTTP shipping in :mod:`demo_server.shipper`, traffic in
:mod:`demo_server.traffic`, campaigns in :mod:`demo_server.campaign_runner`,
payload-file parsing in :mod:`demo_server.payloads`. Every configurable
value comes from `Settings` (environment / .env); nothing is hardcoded.

`main(argv)` runs the Typer app in non-standalone click mode so it returns
the command's exit code instead of raising SystemExit (tests call it
directly and assert on the code; the console script wrapper exits with it).
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Annotated, Any

import click
import typer

from .campaign_runner import (
    CampaignError,
    format_campaign_table,
    get_campaign,
    load_campaigns,
    run_campaign,
    write_campaign_report,
)
from .config import ConfigError, Settings, load_settings
from .payloads import load_payload_file
from .shipper import GatewayShipper, ShipResult
from .store import ResponseStore

app = typer.Typer(
    help="Client App Simulator for CyberGuard Security API.",
    no_args_is_help=True,
)
campaign_app = typer.Typer(
    help="Simulate client app traffic: run multi-stage campaigns and report gateway verdicts.",
    no_args_is_help=True,
)
app.add_typer(campaign_app, name="campaign")


def build_components(
    env: dict[str, str] | None = None,
) -> tuple[Settings, ResponseStore, GatewayShipper]:
    """Wire settings + store + shipper (tests monkeypatch this to inject a
    mock-transport shipper; production uses defaults)."""
    config = load_settings(env)
    store = ResponseStore(config.store_path)
    shipper = GatewayShipper(config, store)
    return config, store, shipper


def _print_table(headers: list[str], rows: list[list[str]]) -> None:
    widths = [
        max(len(h), *(len(row[i]) for row in rows)) if rows else len(h)
        for i, h in enumerate(headers)
    ]
    header_line = "  ".join(h.ljust(w) for h, w in zip(headers, widths))
    print(header_line)
    print("-" * len(header_line))
    for row in rows:
        print("  ".join(c.ljust(w) for c, w in zip(row, widths)))


def _print_ship_table(results: list[ShipResult]) -> None:
    headers = ["ACTION", "ATTEMPTS", "STATUS", "SEVERITY", "VERDICT/RISK", "ERROR"]
    rows: list[list[str]] = []
    for r in results:
        severity = risk = ""
        if isinstance(r.response, dict):
            severity = str(r.response.get("severity", ""))
            risk = (
                f"{r.response.get('verdict', '')} / {r.response.get('risk_score', '')}"
            )
        rows.append(
            [
                r.action,
                str(r.attempts),
                r.status or "transport_error",
                severity,
                risk,
                (r.error or "")[:60],
            ]
        )
    _print_table(headers, rows)


@app.command("ship-once")
def ship_once(
    file: Annotated[str, typer.Option(help="path to payloads JSON")],
) -> int:
    """Ship each payload from a JSON file once."""
    entries = load_payload_file(file)
    _config, _store, shipper = build_components()
    results = []
    exit_code = 0
    for entry in entries:
        result = shipper.ship(entry["action"], entry.get("data"))
        results.append(result)
        if not result.ok:
            exit_code = 1
    shipper.close()
    _print_ship_table(results)
    return exit_code


@app.command("responses")
def responses(
    limit: Annotated[int, typer.Option(help="max rows to show")] = 20,
    action: Annotated[str | None, typer.Option(help="filter by action")] = None,
    min_status: Annotated[
        int | None, typer.Option("--min-status", help="minimum HTTP status")
    ] = None,
) -> int:
    """List stored gateway attempts."""
    config = load_settings()
    store = ResponseStore(config.store_path)
    rows = store.query(limit=limit, action=action, min_status=min_status)
    headers = [
        "ID",
        "TS",
        "ACTION",
        "STATUS",
        "LAT_MS",
        "RESPONSE (truncated)",
        "ERROR",
    ]
    rows_out = []
    for r in rows:
        rows_out.append(
            [
                str(r["id"]),
                str(r["ts"]),
                str(r["action"]),
                str(r["status"]),
                str(r["latency_ms"] if r["latency_ms"] is not None else ""),
                (r["response_json"] or "")[:80],
                (r["error"] or "")[:60],
            ]
        )
    _print_table(headers, rows_out)
    return 0


@app.command("counts")
def counts() -> int:
    """Attempt counts by status."""
    config = load_settings()
    store = ResponseStore(config.store_path)
    counts_by_status = store.counts()
    print(f"total attempts: {counts_by_status.get('total', 0)}")
    for status, n in sorted(counts_by_status.items()):
        if status != "total":
            print(f"  status {status}: {n}")
    return 0


@app.command("serve")
def serve(
    port: Annotated[int | None, typer.Option(help="override DEMO_PORT")] = None,
) -> int:
    """Run the demo server (health, traffic control, metrics, replay)."""
    import uvicorn

    from .service import create_app

    config = load_settings()
    fast_app = create_app(config)
    uvicorn.run(
        fast_app, host="127.0.0.1", port=port or config.demo_port, log_level="info"
    )
    return 0


@app.command("generate")
def generate(
    rate: Annotated[
        float | None,
        typer.Option(help="payloads per minute (default: DEFAULT_RATE, currently 10)"),
    ] = None,
    duration: Annotated[
        float | None,
        typer.Option(help="minutes to run (default: DEFAULT_DURATION, currently 60)"),
    ] = None,
    mix: Annotated[
        str, typer.Option(help="percent split, e.g. net=30,ato=20,benign=50")
    ] = "net=15,ato=15,benign=70",
    jitter: Annotated[float, typer.Option(help="interval jitter 0..1")] = 0.2,
) -> int:
    """Run continuous traffic (SIGINT stops gracefully).

    Rate/duration fall back to `Settings.default_rate` /
    `Settings.default_duration` (DEFAULT_RATE / DEFAULT_DURATION) when the
    flags are omitted.
    """
    import signal
    import threading

    from .scenarios import ScenarioBook, ScenarioError, parse_mix
    from .traffic import generate as run_traffic

    try:
        mix_map = parse_mix(mix)
    except ScenarioError as exc:
        print(f"mix error: {exc}", file=sys.stderr)
        return 2

    config, _store, shipper = build_components()
    rate_value = rate if rate is not None else config.default_rate
    duration_value = duration if duration is not None else config.default_duration
    book = ScenarioBook()
    stop_event = threading.Event()

    def _sigint(signum: int, _frame: Any) -> None:
        print("\nSIGINT received — finishing current send, stopping schedule...")
        stop_event.set()

    prev_handler = signal.signal(signal.SIGINT, _sigint)
    try:
        summary = run_traffic(
            shipper,
            book,
            mix_map,
            rate_per_min=rate_value,
            duration_min=duration_value,
            jitter=jitter,
            stop_event=stop_event,
        )
    finally:
        signal.signal(signal.SIGINT, prev_handler)
        shipper.close()

    print(f"\nevents shipped : {summary.events_shipped}")
    print(f"succeeded      : {summary.succeeded}")
    print(f"failed         : {summary.failed}")
    print(f"success rate   : {summary.success_rate:.2%}")
    print(f"stopped early  : {summary.stopped_early}")
    print(f"elapsed s      : {summary.elapsed_s:.1f}")
    print(f"by category    : {summary.by_category}")
    return 0 if summary.failed == 0 else 1


@app.command("replay")
def replay(
    from_ts: Annotated[str, typer.Option("--from", help="window start (ISO, UTC)")],
    to_ts: Annotated[str, typer.Option("--to", help="window end (ISO, UTC)")],
    max_rows: Annotated[
        int, typer.Option("--max-rows", help="max rows to re-ship")
    ] = 1000,
) -> int:
    """Re-ship stored successful calls in a time window."""
    from .replay import ReplayError
    from .replay import replay as run_replay

    _config, store, shipper = build_components()
    try:
        stats = run_replay(shipper, store, from_ts, to_ts, max_rows=max_rows)
    except ReplayError as exc:
        print(f"replay error: {exc}", file=sys.stderr)
        return 2
    finally:
        shipper.close()

    print(f"window         : {stats['window']['from']} -> {stats['window']['to']}")
    print(f"replayed       : {stats['replayed']}")
    print(f"succeeded      : {stats['succeeded']}")
    print(f"success rate   : {stats['success_rate']:.2%}")
    print(f"sample old ids : {stats['old_event_ids'][:3]}")
    print(f"sample new ids : {stats['new_event_ids'][:3]}")
    return 0 if stats["replayed"] == stats["succeeded"] else 1


@campaign_app.command("run")
def campaign_run(
    name: Annotated[
        str,
        typer.Option(
            "--name",
            help="campaign name: cred_stuffing, exfil_spike, c2_beacon_wave, apt_mixed",
        ),
    ],
    timescale: Annotated[
        float | None,
        typer.Option(
            "--timescale",
            help="delay timescale (default: DEFAULT_TIMESCALE, currently 1.0)",
        ),
    ] = None,
    attacker_ip: Annotated[
        str | None,
        typer.Option("--attacker-ip", help="simulated source IP override"),
    ] = None,
) -> int:
    """Simulate client app traffic forwarding user events to the gateway.

    Stages progress with delays and verdict assertions validate the API's
    responses. A JSON summary of the run is persisted under
    `Settings.reports_dir` (REPORTS_DIR) so demo evidence survives the
    terminal session.
    """
    config, _store, shipper = build_components()
    try:
        camp = get_campaign(name, directory=config.campaigns_dir)
    except CampaignError as exc:
        print(f"campaign error: {exc}", file=sys.stderr)
        return 2

    timescale_value = timescale if timescale is not None else config.default_timescale
    try:
        summary = run_campaign(
            shipper,
            camp,
            timescale=timescale_value,
            attacker_ip=attacker_ip,
        )
    finally:
        shipper.close()

    report_path = write_campaign_report(summary, config.reports_dir)
    print(format_campaign_table(summary))
    print(f"Report saved   : {report_path}")
    return 0 if summary.failed == 0 else 1


@campaign_app.command("report")
def campaign_report(
    limit: Annotated[int, typer.Option(help="limit results")] = 20,
) -> int:
    """Display gateway calls and closed-loop auto-enforcement report."""
    config, store, shipper = build_components()
    try:
        rows = store.query(limit=limit)
    finally:
        shipper.close()

    print(
        f"Response store report ({len(rows)} recent calls from {config.store_path}):\n"
    )

    headers = [
        "ID",
        "TS",
        "ACTION",
        "STATUS",
        "SEVERITY",
        "VERDICT",
        "BLOCKED_MATCH",
        "LAT_MS",
    ]
    rows_out = []
    for r in rows:
        resp = {}
        if r.get("response_json"):
            try:
                resp = json.loads(r["response_json"])
            except ValueError:
                pass
        severity = resp.get("severity", "") if isinstance(resp, dict) else ""
        verdict = resp.get("verdict", "") if isinstance(resp, dict) else ""
        matched = (
            "TRUE"
            if isinstance(resp, dict) and resp.get("blocked_indicator_matched")
            else "false"
        )
        rows_out.append(
            [
                str(r["id"]),
                str(r["ts"]),
                str(r["action"]),
                str(r["status"]),
                severity,
                verdict,
                matched,
                str(r["latency_ms"] if r["latency_ms"] is not None else ""),
            ]
        )
    _print_table(headers, rows_out)
    return 0


@campaign_app.command("list")
def campaign_list() -> int:
    """List all available simulated traffic campaigns and stages.

    Works without a configured key — it only reads the campaigns directory.
    """
    try:
        campaigns = load_campaigns()
    except CampaignError as exc:
        print(f"campaign error: {exc}", file=sys.stderr)
        return 2

    print("Available Simulated Traffic Campaigns:\n")
    for name, camp in sorted(campaigns.items()):
        print(f"  • {name}: {camp.description}")
        print(f"    Stages ({len(camp.stages)}):")
        for s in camp.stages:
            print(
                f"      - {s.name}: action={s.action}, expected_severity={s.expected_severity}, delay={s.delay_s}s"
            )
        print()
    return 0


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s"
    )

    command = typer.main.get_command(app)
    try:
        # Non-standalone mode returns the command's return value instead of
        # raising SystemExit; the console script wrapper exits with it.
        return int(
            command.main(args=argv, prog_name="demo-server", standalone_mode=False) or 0
        )
    except click.exceptions.Exit as exc:  # --help / no-args help
        return int(exc.exit_code)
    except click.UsageError as exc:  # bad usage: print usage + return 2
        exc.show()
        return 2
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
