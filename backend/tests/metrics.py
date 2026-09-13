"""Shared metrics helpers for the evaluation harness."""

import numpy as np
from sklearn.metrics import precision_recall_fscore_support, roc_auc_score
from scipy.stats import mannwhitneyu


def compute_metrics_adaptive(rows: list[dict], score_key: str = "score") -> dict:
    """Metrics with an adaptive positive threshold (midpoint of the class
    means) — for engines whose max attainable score is below 50 (e.g. ATO).
    Reports the threshold used."""
    y_true = np.array([1 if r["expected_label"] == "phishing" else 0 for r in rows])
    scores = np.array([float(r[score_key]) for r in rows])
    mal_mean = scores[y_true == 1].mean() if (y_true == 1).any() else 50.0
    ben_mean = scores[y_true == 0].mean() if (y_true == 0).any() else 50.0
    threshold = (mal_mean + ben_mean) / 2
    m = compute_metrics(rows, score_key)
    y_pred = (scores >= threshold).astype(int)
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average="binary", zero_division=0
    )
    m.update({"threshold": float(threshold), "precision": float(precision),
              "recall": float(recall), "f1": float(f1)})
    return m


def compute_metrics(rows: list[dict], score_key: str = "score") -> dict:
    """rows: [{expected_label: 'phishing'|'benign', score: 0..100, ...}].

    Returns precision/recall/F1/AUC (score >= 50 == predicted positive),
    per-class score means, band gap (malicious mean - benign mean), and a
    Mann-Whitney U p-value for the score separation.
    """
    y_true = np.array([1 if r["expected_label"] == "phishing" else 0 for r in rows])
    scores = np.array([float(r[score_key]) for r in rows])
    y_pred = (scores >= 50).astype(int)

    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average="binary", zero_division=0
    )
    try:
        auc = roc_auc_score(y_true, scores)
    except ValueError:
        auc = float("nan")

    mal = scores[y_true == 1]
    ben = scores[y_true == 0]
    mal_mean = float(mal.mean()) if len(mal) else float("nan")
    ben_mean = float(ben.mean()) if len(ben) else float("nan")
    band_gap = mal_mean - ben_mean if len(mal) and len(ben) else float("nan")
    try:
        _, mw_p = mannwhitneyu(mal, ben, alternative="greater")
        mw_p = float(mw_p)
    except ValueError:
        mw_p = float("nan")

    return {
        "cases": len(rows),
        "positives": int(y_true.sum()),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "auc": float(auc),
        "mal_mean": mal_mean,
        "ben_mean": ben_mean,
        "band_gap": float(band_gap),
        "mw_p": mw_p,
    }


def score_from_indicators(indicators: list[dict]) -> int:
    """Deterministic heuristic score from indicator severities (mirrors
    scoring_service weights) — used by direct-engine evals."""
    weights = {"critical": 25, "high": 15, "medium": 5}
    return min(sum(weights.get(str(i.get("severity", "")).lower(), 0) for i in indicators), 100)


def verbose_fail(kind: str, row: dict, score, indicators: list[dict], limit: int = 3) -> str:
    """Verbose failure payload: snippet + score + indicator names."""
    snippet = json_short(row, limit)
    names = [f"{i.get('type')}:{i.get('severity')}" for i in indicators][:6]
    return f"{kind} payload={snippet} score={score} indicators={names}"


def json_short(row: dict, limit: int = 3) -> str:
    payload = row.get("payload")
    if isinstance(payload, str):
        text = payload
    else:
        text = str(payload)
    return text[:160] + ("…" if len(text) > 160 else "")
