"""Network threat engine evaluation at scale."""

import pytest

from tests.conftest import scale_n
from tests.datakit import synthetic_network_flows
from tests.metrics import compute_metrics_adaptive, score_from_indicators, verbose_fail

from app.services.network_threat_detector import analyze_network_heuristics

pytestmark = pytest.mark.scale


@pytest.mark.scale
def test_eval_network_scale(request, eval_report):
    rows = synthetic_network_flows(scale_n(request, 2000), seed=29)
    scored = []
    for row in rows:
        payload = row["payload"]
        indicators = analyze_network_heuristics(payload, [])
        score = score_from_indicators(indicators)
        scored.append({**row, "score": score, "indicators": indicators})

    metrics = compute_metrics_adaptive(scored)
    eval_report.record_engine("network", **metrics)

    assert metrics["mal_mean"] > metrics["ben_mean"] + 10, (
        "band separation failed: mal_mean=%.1f ben_mean=%.1f" % (metrics["mal_mean"], metrics["ben_mean"])
    )
    # Baseline recorded (see finding): per-flow heuristics cannot detect
    # low-and-slow beaconing (regular callbacks carry no per-flow weight).
    assert metrics["auc"] >= 0.8, f"network AUC below baseline: {metrics['auc']:.3f}"
    # Baseline (see finding): beaconing batches score 0 under per-flow
    # heuristics -> recall ceiling ~2/3 with this dataset mix.
    assert metrics["recall"] >= 0.6, f"network recall below baseline: {metrics['recall']:.3f} (threshold={metrics['threshold']:.0f})"

    fp = [r for r in scored if r["expected_label"] == "benign" and r["score"] >= metrics["threshold"]][:5]
    for r in fp:
        eval_report.record_finding(f"network FP: {verbose_fail('FP', r, r['score'], r['indicators'])}")
