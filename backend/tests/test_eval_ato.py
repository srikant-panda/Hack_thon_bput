"""Account-takeover (auth-log) engine evaluation at scale."""

import pytest

from tests.conftest import scale_n
from tests.datakit import synthetic_auth_events
from tests.metrics import compute_metrics_adaptive, score_from_indicators, verbose_fail

from app.services.account_takeover_detector import analyze_auth_log_heuristics

pytestmark = pytest.mark.scale


@pytest.mark.scale
def test_eval_ato_scale(request, eval_report):
    rows = synthetic_auth_events(scale_n(request, 2000), seed=23)
    scored = []
    for row in rows:
        indicators = analyze_auth_log_heuristics(row["payload"])
        score = score_from_indicators(indicators)
        scored.append({**row, "score": score, "indicators": indicators})

    metrics = compute_metrics_adaptive(scored)
    eval_report.record_engine("account_takeover", **metrics)

    assert metrics["mal_mean"] > metrics["ben_mean"] + 15, (
        "band separation failed: mal_mean=%.1f ben_mean=%.1f" % (metrics["mal_mean"], metrics["ben_mean"])
    )
    assert metrics["recall"] >= 0.85, f"ATO recall below floor: {metrics['recall']:.3f} (threshold={metrics['threshold']:.0f})"
    assert metrics["auc"] >= 0.9, f"ATO AUC below floor: {metrics['auc']:.3f}"

    fp = [r for r in scored if r["expected_label"] == "benign" and r["score"] >= metrics["threshold"]][:5]
    fn = [r for r in scored if r["expected_label"] == "phishing" and r["score"] < metrics["threshold"]][:5]
    for r in fp:
        eval_report.record_finding(f"ato FP: {verbose_fail('FP', r, r['score'], r['indicators'])}")
    for r in fn:
        eval_report.record_finding(f"ato FN: {verbose_fail('FN', r, r['score'], r['indicators'])}")
