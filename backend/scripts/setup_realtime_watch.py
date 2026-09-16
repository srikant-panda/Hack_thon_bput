#!/usr/bin/env python3
"""Real-Time Gmail Watch & Pub/Sub Setup Helper.

Diagnoses, configures, and tests the real-time Gmail push notification
pipeline (Issue 2 resolution).

Usage:
    # Check status and instructions:
    uv run python scripts/setup_realtime_watch.py

    # Start public Cloudflare tunnel to receive Google push notifications:
    uv run python scripts/setup_realtime_watch.py --start-tunnel

    # Trigger live watch() registration with Google API for connected accounts:
    uv run python scripts/setup_realtime_watch.py --watch

    # Send a simulated Pub/Sub push notification to test pipeline end-to-end:
    uv run python scripts/setup_realtime_watch.py --simulate
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import subprocess
import sys
import time
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

import httpx
from sqlalchemy import select

from app.core.config import get_settings
from app.db.admin import _get_admin_session_maker
from app.db.models import EmailConnectorAccount, GmailAccount
from app.services.gmail.watch_service import renew_watches


def _check_tunnel() -> str | None:
    """Check if cloudflared or ngrok is running and return the public URL if found."""
    # Check /tmp/cloudflared_tunnel.log
    log_file = Path("/tmp/cloudflared_tunnel.log")
    if log_file.exists():
        content = log_file.read_text(errors="ignore")
        import re
        matches = re.findall(r"https://[-a-zA-Z0-9@:%._+~#=]*\.trycloudflare\.com", content)
        if matches:
            return matches[-1]

    # Check local ngrok API
    try:
        r = httpx.get("http://127.0.0.1:4040/api/tunnels", timeout=1.0)
        if r.status_code == 200:
            data = r.json()
            for t in data.get("tunnels", []):
                if t.get("public_url", "").startswith("https://"):
                    return t["public_url"]
    except Exception:
        pass

    return None


def start_tunnel() -> str:
    """Start cloudflared tunnel in background."""
    print("🚀 Starting Cloudflare public HTTPS tunnel for http://127.0.0.1:8000...")
    log_path = "/tmp/cloudflared_tunnel.log"
    # Clean previous log
    if os.path.exists(log_path):
        os.remove(log_path)

    cmd = [
        "cloudflared",
        "tunnel",
        "--url",
        "http://127.0.0.1:8000",
        "--protocol",
        "http2",
        "--no-autoupdate",
    ]
    with open(log_path, "w") as out:
        subprocess.Popen(cmd, stdout=out, stderr=out, start_new_session=True)

    print("⏳ Waiting for Cloudflare tunnel URL to establish...")
    import re
    for _ in range(15):
        time.sleep(1)
        if os.path.exists(log_path):
            with open(log_path, "r") as f:
                content = f.read()
                matches = re.findall(r"https://[-a-zA-Z0-9@:%._+~#=]*\.trycloudflare\.com", content)
                if matches:
                    url = matches[-1]
                    print(f"✔ Public Tunnel Established: {url}")
                    print(f"👉 Webhook Endpoint: {url}/api/v1/webhooks/gmail\n")
                    return url

    print("❌ Failed to retrieve tunnel URL within 15 seconds. Check /tmp/cloudflared_tunnel.log")
    sys.exit(1)


async def show_status() -> None:
    settings = get_settings()
    print("=" * 65)
    print("🛰️  CYBERGUARD REAL-TIME GMAIL PIPELINE STATUS")
    print("=" * 65)

    # 1. Config check
    topic = settings.GMAIL_PUBSUB_TOPIC
    is_placeholder = "<" in topic or "your-project" in topic
    print(f"Pub/Sub Topic configured : {topic}")
    if is_placeholder:
        print("  ⚠️  WARNING: GMAIL_PUBSUB_TOPIC still has placeholder text.")
        print("     Set GMAIL_PUBSUB_TOPIC=projects/<gcp-project-id>/topics/cyberguard-gmail in backend/.env")
    else:
        print("  ✔ Valid format")

    # 2. Public tunnel check
    tunnel_url = _check_tunnel()
    if tunnel_url:
        print(f"Active Public Tunnel     : {tunnel_url}")
        print(f"GCP Push Endpoint URL    : {tunnel_url}/api/v1/webhooks/gmail")
    else:
        print("Active Public Tunnel     : None detected")
        print("  💡 Run with --start-tunnel to create a public HTTPS endpoint instantly.")

    # 3. Database Accounts
    async with _get_admin_session_maker()() as s:
        connectors = (await s.execute(select(EmailConnectorAccount))).scalars().all()
        gmail_accs = (await s.execute(select(GmailAccount))).scalars().all()

        print("\nConnected Email Accounts:")
        if not connectors and not gmail_accs:
            print("  (No accounts connected yet. Connect in UI at http://localhost:5173/email-connectors)")
        else:
            for c in connectors:
                print(f"  [email_connector_accounts] {c.provider_email} ({c.status})")
            for g in gmail_accs:
                print(
                    f"  [gmail_accounts]          {g.email} | status={g.sync_status} | "
                    f"historyId={g.last_history_id or 'none'} | "
                    f"watch_expires={g.watch_expiration or 'none'}"
                )

    print("=" * 65)


async def run_watch() -> None:
    print("\n🔄 Calling Google Gmail watch() API for connected mailboxes...")
    async with _get_admin_session_maker()() as s:
        res = await renew_watches(s)
        print(f"Result: {res['renewed']} renewed, {res['errors']} errors, {res['skipped']} skipped.")


async def run_simulate(email: str | None = None) -> None:
    async with _get_admin_session_maker()() as s:
        if not email:
            acc = (await s.execute(select(GmailAccount).limit(1))).scalar_one_or_none()
            if not acc:
                conn = (await s.execute(select(EmailConnectorAccount).limit(1))).scalar_one_or_none()
                email = conn.provider_email if conn else "coder6861python@gmail.com"
            else:
                email = acc.email

    print(f"\n📨 Sending simulated Google Cloud Pub/Sub push notification for: {email}")
    data_payload = json.dumps({"emailAddress": email, "historyId": "9999999"}).encode()
    b64_data = base64.b64encode(data_payload).decode()

    webhook_payload = {
        "subscription": "projects/test-project/subscriptions/cyberguard-gmail-sub",
        "message": {
            "data": b64_data,
            "messageId": f"sim-{int(time.time())}",
            "publishTime": "2026-09-16T12:00:00Z",
        },
    }

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                "http://127.0.0.1:8000/api/v1/webhooks/gmail",
                json=webhook_payload,
                timeout=5.0,
            )
            print(f"Response Status: {resp.status_code}")
            print(f"Response Body  : {resp.text}")
            if resp.status_code == 200:
                print("✔ Webhook accepted! Check Terminal Tab 2 (gmail-worker) and Tab 3 (email-worker) to see it process.")
        except Exception as exc:
            print(f"❌ Failed to reach local backend webhook: {exc}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Real-Time Gmail Pub/Sub Setup Helper")
    parser.add_argument("--start-tunnel", action="store_true", help="Start Cloudflare tunnel in background")
    parser.add_argument("--watch", action="store_true", help="Trigger watch renewal with Google API")
    parser.add_argument("--simulate", action="store_true", help="Send a simulated Pub/Sub webhook push")
    args = parser.parse_args()

    if args.start_tunnel:
        start_tunnel()
    elif args.watch:
        asyncio.run(run_watch())
    elif args.simulate:
        asyncio.run(run_simulate())
    else:
        asyncio.run(show_status())


if __name__ == "__main__":
    main()
