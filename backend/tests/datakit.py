"""Evaluation data kit: online fetch with mandatory cached/synthetic fallback.

`fetch_or_cache` downloads a dataset once into tests/data/cache/ (gitignored),
records provenance (source URL, HTTP status, rows, sha256, fetch date), and
always provides a deterministic synthetic fallback so the harness runs fully
offline at the venue.
"""

import csv
import hashlib
import io
import json
import math
import random
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent / "data"
CACHE_DIR = DATA_DIR / "cache"
PROVENANCE_PATH = DATA_DIR / "PROVENANCE.md"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

_report_hook = None  # set by conftest to record provenance


def set_report_hook(hook):
    global _report_hook
    _report_hook = hook


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _record(name: str, mode: str, rows: int, sha: str | None, url: str | None):
    entry = {
        "name": name,
        "mode": mode,  # online | cache | synthetic
        "rows": rows,
        "sha256": sha,
        "url": url,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }
    if _report_hook:
        _report_hook(**entry)
    # Append/refresh the human-readable provenance log.
    lines = PROVENANCE_PATH.read_text(encoding="utf-8").splitlines() if PROVENANCE_PATH.exists() else [
        "# Dataset provenance",
        "",
        "| Name | Mode | Rows | SHA256 | Source URL | Date |",
        "|---|---|---|---|---|---|",
    ]
    header = 3
    # Deduplicate: one provenance line per (name, mode).
    if not any(f"| {name} | {mode} |" in l for l in lines[header:]):
        lines.insert(
            header,
            f"| {name} | {mode} | {rows} | {(sha or '—')[:16]}… | {url or 'synthetic'} | {entry['fetched_at'][:19]} |",
        )
    PROVENANCE_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return entry


def fetch_or_cache(name: str, urls: list[str], loader, synthetic, *, force: bool = False, offline: bool = False):
    """Return (rows, mode). Tries cache, then each URL, then synthetic.

    `loader(raw_bytes) -> rows` parses a successful download; `synthetic(n)`
    builds the deterministic fallback. Every fetch is cached on disk and
    provenance-tracked.
    """
    cache_file = CACHE_DIR / f"{name}.json"

    # 1. Cache (unless --fetch forces a re-download).
    if cache_file.exists() and not force:
        rows = json.loads(cache_file.read_text(encoding="utf-8"))
        _record(name, "cache", len(rows), None, urls[0] if urls else None)
        return rows, "cache"

    # 2. Online fetch.
    if not offline:
        for url in urls:
            try:
                request = urllib.request.Request(url, headers={"User-Agent": "cyberguard-eval-harness/1.0"})
                with urllib.request.urlopen(request, timeout=20) as response:
                    if response.status != 200:
                        continue
                    raw = response.read()
                rows = loader(raw)
                if not rows:
                    continue
                cache_file.write_text(json.dumps(rows), encoding="utf-8")
                _record(name, "online", len(rows), _sha256_bytes(raw), url)
                return rows, "online"
            except Exception:  # noqa: BLE001 - any fetch failure falls through
                continue

    # 3. Synthetic fallback (mandatory — the suite always runs).
    rows = synthetic()
    _record(name, "synthetic", len(rows), None, None)
    return rows, "synthetic"


# ---------------------------------------------------------------------------
# Online dataset loaders
# ---------------------------------------------------------------------------

def _load_sms_tsv(raw: bytes) -> list[dict]:
    """SMS Spam Collection TSV (label, message)."""
    rows = []
    reader = csv.reader(io.StringIO(raw.decode("utf-8", errors="replace")), delimiter="\t")
    for line in reader:
        if len(line) >= 2:
            rows.append({"label": line[0].strip(), "text": line[1].strip()})
    return rows


def _load_url_list(raw: bytes) -> list[dict]:
    """Plain-text URL list (e.g. OpenPhish feed) — all rows are phishing."""
    rows = []
    for line in raw.decode("utf-8", errors="replace").splitlines():
        url = line.strip()
        if url.startswith("http"):
            rows.append({"label": "phishing", "url": url})
    return rows


def _load_whitelist_sample(raw: bytes, n: int, seed: int = 7) -> list[dict]:
    """Sample benign URLs from the committed top-1m whitelist."""
    rng = random.Random(seed)
    lines = [l.strip() for l in raw.decode("utf-8", errors="replace").splitlines() if l.strip()]
    picked = rng.sample(lines, min(n, len(lines)))
    return [{"label": "benign", "url": f"https://{domain}" if not domain.startswith("http") else domain}
            for domain in picked]


# ---------------------------------------------------------------------------
# Synthetic generators (seeded, deterministic)
# ---------------------------------------------------------------------------

PHISH_DOMAINS = ["paypa1-secure.tk", "amaz0n-verify.ml", "appleid-support.cf", "microsoft-login.gq",
                 "netflix-billing.tk", "coinbase-wallets.ml", "steamcommunuty.ru", "dropbox-signin.cf"]
BENIGN_DOMAINS = ["paypal.com", "amazon.com", "apple.com", "microsoft.com", "github.com",
                  "google.com", "dropbox.com", "wikipedia.org"]
URGENT_WORDS = ["urgent", "immediately", "verify", "suspend", "alert", "final notice", "action required"]
CRED_PHRASES = ["confirm your password", "validate your billing information", "verify your account"]
BENIGN_TEXTS = [
    "Meeting moved to 3pm tomorrow, see you there.",
    "Lunch on Friday? The new ramen place opened downtown.",
    "Project update attached, let me know your thoughts.",
    "Thanks for the quick turnaround on the report.",
    "Reminder: team standup at 9:30 in the second floor room.",
]


def synthetic_emails(n: int = 1000, seed: int = 11) -> list[dict]:
    """(payload={sender, subject, body}, expected_label, expected_band_hint)."""
    rng = random.Random(seed)
    rows = []
    half = n // 2
    for i in range(n):
        phishing = i < half
        if phishing:
            domain = rng.choice(PHISH_DOMAINS)
            brand = rng.choice(["paypal", "amazon", "apple", "microsoft", "netflix"])
            sender = f"security@{domain}"
            subject = f"{rng.choice(URGENT_WORDS).title()}: verify your {brand} account now"
            body = (
                f"Dear customer, your {brand} account will be suspended within 24 hours. "
                f"Please {rng.choice(CRED_PHRASES)} immediately at "
                f"http://{rng.choice(['192.168.', '10.0.', '172.16.'])}{rng.randint(1, 254)}.{rng.randint(1, 254)}"
                f"/{rng.choice(['verify-login', 'secure-update', 'account-fix'])}.php"
            )
        else:
            sender = f"{rng.choice(['alice', 'bob', 'carol'])}@{rng.choice(BENIGN_DOMAINS)}"
            subject = rng.choice(["Team update", "Meeting notes", "Quick question", "Lunch plans"])
            body = rng.choice(BENIGN_TEXTS)
        rows.append({
            "payload": {"sender": sender, "subject": subject, "body": body},
            "expected_label": "phishing" if phishing else "benign",
            "expected_band_hint": "high" if phishing else "safe",
        })
    return rows


def synthetic_urls(n: int = 2000, seed: int = 13, whitelist_path: Path | None = None) -> list[dict]:
    """Malicious URL patterns + benign domains (sampled from the committed
    top-1m whitelist when available)."""
    rng = random.Random(seed)
    benign_pool: list[str] = []
    wp = whitelist_path or (Path(__file__).resolve().parents[1] / "ml" / "data" / "url_whitelist" / "top1m.txt")
    if wp.exists():
        lines = [l.strip() for l in wp.read_text(errors="replace").splitlines() if l.strip()]
        rng2 = random.Random(seed + 1)
        benign_pool = rng2.sample(lines, min(n, len(lines)))

    rows = []
    half = n // 2
    for i in range(n):
        phishing = i < half
        if phishing:
            style = rng.choice(["ip", "entropy", "brand", "exec"])
            if style == "ip":
                url = f"http://{rng.randint(1,254)}.{rng.randint(1,254)}.{rng.randint(1,254)}.{rng.randint(1,254)}/{rng.choice(['login','verify','secure'])}-{rng.randint(1000,9999)}.php"
            elif style == "entropy":
                token = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(28))
                url = f"http://{token}.com/{token[:12]}/verify.php"
            elif style == "brand":
                url = f"http://{rng.choice(['paypal','apple','netflix'])}-{''.join(rng.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(6))}.{rng.choice(['tk','ml','cf','gq'])}/signin"
            else:
                url = f"http://cdn-{rng.randint(100,999)}.example.ru/downloads/{rng.choice(['invoice','setup','update'])}.exe"
            rows.append({"payload": url, "expected_label": "phishing", "expected_band_hint": "high"})
        else:
            if benign_pool and i % 2 == 0:
                url = benign_pool[i % len(benign_pool)]
            else:
                url = f"https://www.{rng.choice(BENIGN_DOMAINS)}/{rng.choice(['about','help','docs','blog'])}/{i}"
            rows.append({"payload": url, "expected_label": "benign", "expected_band_hint": "safe"})
    return rows


def synthetic_images(n: int = 400, seed: int = 17, tmp_dir: Path | None = None) -> list[dict]:
    """PIL-generated images: benign gradient/noise photos vs manipulated
    (splice patch, copy-move block, heavy recompression). Returns file paths
    + expected labels; media forensics runs on real files."""
    from PIL import Image, ImageDraw, ImageFilter

    out_dir = Path(tmp_dir or (DATA_DIR / "cache" / "images"))
    out_dir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)
    rows = []
    half = n // 2
    for i in range(n):
        phishing = i < half  # "phishing" == manipulated
        path = out_dir / f"img_{i:04d}.png"
        if not path.exists():
            base = Image.new("RGB", (256, 256))
            draw = ImageDraw.Draw(base)
            for y in range(256):
                draw.line([(0, y), (256, y)], fill=(y, 128, 255 - y))
            if phishing:
                style = rng.choice(["splice", "copymove", "recompress"])
                patch = Image.new("RGB", (64, 64), (200, 30, 30))
                draw2 = ImageDraw.Draw(patch)
                draw2.rectangle([10, 10, 50, 50], fill=(30, 200, 30))
                base.paste(patch, (rng.randint(0, 180), rng.randint(0, 180)))
                if style == "copymove":
                    region = base.crop((0, 0, 64, 64))
                    base.paste(region, (150, 150))
                if style == "recompress":
                    buffer = path.with_suffix(".jpg.tmp")
                    base.save(buffer, "JPEG", quality=35)
                    base = Image.open(buffer)
                    buffer.unlink(missing_ok=True)
                base = base.filter(ImageFilter.GaussianBlur(0.4))
            else:
                base = base.filter(ImageFilter.GaussianBlur(rng.uniform(0.5, 1.5)))
            base.save(path, "PNG")
        rows.append({
            "payload": {"path": str(path), "file_name": path.name, "content_type": "image/png"},
            "expected_label": "phishing" if phishing else "benign",
            "expected_band_hint": "high" if phishing else "safe",
        })
    return rows


def synthetic_audio(n: int = 400, seed: int = 19, tmp_dir: Path | None = None) -> list[dict]:
    """WAV files: benign tones/noise vs spoof-like synthesized speech-formants
    (phase discontinuities). Returns file paths + expected labels."""
    import struct
    import wave

    out_dir = Path(tmp_dir or (DATA_DIR / "cache" / "audio"))
    out_dir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)
    sample_rate = 8000
    duration = 1.0
    rows = []
    half = n // 2
    for i in range(n):
        spoofed = i < half
        path = out_dir / f"audio_{i:04d}.wav"
        if not path.exists():
            frames = []
            if spoofed:
                # Spoof-like: concatenated formant bursts with hard phase cuts.
                pos = 0.0
                while pos < duration:
                    freq = rng.uniform(300, 900)
                    seg = 0.02
                    for t in range(int(seg * sample_rate)):
                        value = 12000 * math.sin(2 * math.pi * freq * t / sample_rate)
                        frames.append(value)
                    pos += seg
            else:
                # Natural-ish: smooth sine + slow noise envelope.
                base_freq = rng.uniform(150, 350)
                for t in range(int(duration * sample_rate)):
                    envelope = 0.6 + 0.4 * math.sin(2 * math.pi * 0.7 * t / sample_rate)
                    value = int(9000 * envelope * math.sin(2 * math.pi * base_freq * t / sample_rate))
                    frames.append(value)
            with wave.open(str(path), "w") as wav:
                wav.setnchannels(1)
                wav.setsampwidth(2)
                wav.setframerate(sample_rate)
                wav.writeframes(b"".join(struct.pack("<h", max(-32768, min(32767, int(v)))) for v in frames))
        rows.append({
            "payload": {"path": str(path), "file_name": path.name, "content_type": "audio/wav"},
            "expected_label": "phishing" if spoofed else "benign",
            "expected_band_hint": "high" if spoofed else "safe",
        })
    return rows


def synthetic_auth_events(n: int = 2000, seed: int = 23) -> list[dict]:
    """Auth-log event batches: benign sessions vs injected attacks
    (brute-force bursts, password spray, impossible travel, new-device
    success-after-failures). Each row is one USER'S session (list of events)
    with the attack injected into the tail half."""
    rng = random.Random(seed)
    rows = []
    users = [f"user{i:04d}" for i in range(max(1, n // 4))]
    base_time = datetime(2026, 9, 1, 9, 0, 0, tzinfo=timezone.utc)
    for i in range(n):
        user = rng.choice(users)
        phishing = i >= n // 2
        events = []
        if not phishing:
            # Normal history: a few successes from the usual device/location.
            for k in range(rng.randint(2, 5)):
                events.append({
                    "user": user, "ip": "203.0.113.10", "location": "Berlin",
                    "device": "win-11", "status": "success",
                    "timestamp": (base_time + timedelta(hours=k)).isoformat(),
                })
        else:
            attack = rng.choice(["bruteforce", "spray", "travel", "newdevice"])
            if attack == "bruteforce":
                for k in range(rng.randint(6, 12)):
                    events.append({"user": user, "ip": "198.51.100.7", "location": "Lagos",
                                   "device": "linux", "status": "failed",
                                   "timestamp": (base_time + timedelta(seconds=20 * k)).isoformat()})
                events.append({"user": user, "ip": "198.51.100.7", "location": "Lagos",
                               "device": "linux", "status": "success",
                               "timestamp": (base_time + timedelta(minutes=5)).isoformat()})
            elif attack == "spray":
                # Password spray as seen per-victim: repeated failures for one
                # victim from the attacker IP (the engine groups by user).
                victim = rng.choice(users)
                for k in range(rng.randint(4, 9)):
                    events.append({"user": victim, "ip": "198.51.100.9", "location": "Lagos",
                                   "device": "linux", "status": "failed",
                                   "timestamp": (base_time + timedelta(seconds=30 * k)).isoformat()})
            elif attack == "travel":
                events.append({"user": user, "ip": "203.0.113.10", "location": "Berlin",
                               "device": "win-11", "status": "success",
                               "timestamp": base_time.isoformat()})
                events.append({"user": user, "ip": "198.51.100.7", "location": "Lagos",
                               "device": "win-11", "status": "success",
                               "timestamp": (base_time + timedelta(minutes=30)).isoformat()})
            else:  # newdevice
                events.append({"user": user, "ip": "203.0.113.10", "location": "Berlin",
                               "device": "win-11", "status": "success",
                               "timestamp": base_time.isoformat()})
                for k in range(1, 3):
                    events.append({"user": user, "ip": "203.0.113.99", "location": "Berlin",
                                   "device": "unknown-mac", "status": "failed",
                                   "timestamp": (base_time + timedelta(minutes=10 + k)).isoformat()})
                events.append({"user": user, "ip": "203.0.113.99", "location": "Berlin",
                               "device": "unknown-mac", "status": "success",
                               "timestamp": (base_time + timedelta(minutes=13)).isoformat()})
        rows.append({
            "payload": events,
            "expected_label": "phishing" if phishing else "benign",
            "expected_band_hint": "high" if phishing else "safe",
        })
    return rows


def synthetic_network_flows(n: int = 2000, seed: int = 29) -> list[dict]:
    """Flow batches: benign web traffic vs beaconing/exfil/bad-port attacks."""
    rng = random.Random(seed)
    rows = []
    half = n // 2
    base_time = datetime(2026, 9, 1, 9, 0, 0, tzinfo=timezone.utc)
    for i in range(n):
        phishing = i < half
        flows = []
        if not phishing:
            for k in range(rng.randint(3, 8)):
                flows.append({
                    "source_ip": "10.0.0.15", "dest_ip": rng.choice(["93.184.216.34", "142.250.72.14"]),
                    "port": rng.choice([443, 80]), "bytes_out": rng.randint(1_000, 500_000),
                    "protocol": "TCP",
                    "timestamp": (base_time + timedelta(seconds=60 * k)).isoformat(),
                })
        else:
            attack = rng.choice(["beacon", "exfil", "badport"])
            if attack == "beacon":
                for k in range(rng.randint(10, 20)):
                    flows.append({"source_ip": "10.0.0.66", "dest_ip": "185.220.101.9", "port": 443,
                                  "bytes_out": rng.randint(300, 900), "protocol": "TCP",
                                  "timestamp": (base_time + timedelta(seconds=60 * k)).isoformat()})
            elif attack == "exfil":
                flows.append({"source_ip": "10.0.0.77", "dest_ip": "45.33.32.156", "port": 443,
                              "bytes_out": rng.randint(500_000_000, 2_000_000_000), "protocol": "TCP",
                              "timestamp": base_time.isoformat()})
            else:
                flows.append({"source_ip": "10.0.0.88", "dest_ip": "45.33.32.156",
                              "port": rng.choice([4444, 1337, 6667]), "bytes_out": rng.randint(10_000, 100_000),
                              "protocol": "TCP", "timestamp": base_time.isoformat()})
        rows.append({
            "payload": flows,
            "expected_label": "phishing" if phishing else "benign",
            "expected_band_hint": "high" if phishing else "safe",
        })
    return rows


def synthetic_impersonation(n: int = 600, seed: int = 31) -> list[dict]:
    """(message, claimed_identity) pairs: authority/pressure/secrecy vs benign."""
    rng = random.Random(seed)
    rows = []
    half = n // 2
    identities = ["the IT helpdesk", "the CFO", "HR department", "the CEO"]
    for i in range(n):
        phishing = i < half
        if phishing:
            identity = rng.choice(identities)
            text = rng.choice([
                f"This is {identity}. I need you to buy 5 gift cards immediately and send me the codes.",
                f"{identity.title()} here — transfer the invoice payment today and keep this confidential.",
                f"This is {identity}. Email me the employee payroll list right away, do not tell anyone.",
                f"Urgent: {identity} requires your password to finish maintenance. Reply now.",
            ])
        else:
            identity = "a colleague"
            text = rng.choice([
                "Could you review my pull request when you have a minute?",
                "The quarterly numbers are in the shared drive, nothing urgent.",
                "Standup is moved to Thursday this week.",
            ])
        rows.append({
            "payload": {"message": text, "claimed_identity": identity},
            "expected_label": "phishing" if phishing else "benign",
            "expected_band_hint": "high" if phishing else "safe",
        })
    return rows
