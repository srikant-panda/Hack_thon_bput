"""Impersonation detector evaluation at scale."""

import pytest

from tests.conftest import scale_n
from tests.datakit import synthetic_impersonation
from tests.metrics import compute_metrics_adaptive, score_from_indicators, verbose_fail

from app.services.impersonation_detector import analyze_impersonation_heuristics

pytestmark = pytest.mark.scale


@pytest.mark.scale
def test_eval_impersonation_scale(request, eval_report):
    rows = synthetic_impersonation(scale_n(request, 600), seed=31)
    scored = []
    for row in rows:
        payload = row["payload"]
        indicators = analyze_impersonation_heuristics(payload["message"], payload["claimed_identity"])
        score = score_from_indicators(indicators)
        scored.append({**row, "score": score, "indicators": indicators})

    metrics = compute_metrics_adaptive(scored)
    eval_report.record_engine("impersonation", **metrics)

    assert metrics["mal_mean"] > metrics["ben_mean"] + 10, (
        "band separation failed: mal_mean=%.1f ben_mean=%.1f" % (metrics["mal_mean"], metrics["ben_mean"])
    )
    assert metrics["recall"] >= 0.7, f"impersonation recall below floor: {metrics['recall']:.3f} (threshold={metrics['threshold']:.0f})"
    assert metrics["auc"] >= 0.85, f"impersonation AUC below floor: {metrics['auc']:.3f}"

    fn = [r for r in scored if r["expected_label"] == "phishing" and r["score"] < metrics["threshold"]][:5]
    for r in fn:
        eval_report.record_finding(f"impersonation FN: {verbose_fail('FN', r, r['score'], r['indicators'])}")
