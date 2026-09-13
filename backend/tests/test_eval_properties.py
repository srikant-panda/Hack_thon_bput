"""Property tests: monotonic blend, severity bands, split_ml_indicator."""

import random

import pytest

from tests.datakit import synthetic_emails, synthetic_urls
from tests.metrics import score_from_indicators

from app.services.ml_inference import score_with_ml, split_ml_indicator
from app.services.scoring_service import SEVERITY_WEIGHTS, get_severity

pytestmark = pytest.mark.scale


def test_property_monotonic_blend_at_scale(eval_report):
    """ML may raise but never lower the heuristic score, across 1000 cases."""
    rng = random.Random(77)
    rows = synthetic_emails(500, seed=51) + synthetic_urls(500, seed=53)
    lowered = []
    checked = 0
    for row in rows:
        payload = row["payload"]
        if isinstance(payload, str):
            indicators = __import__("app.services.url_detector", fromlist=["analyze_url_heuristics"]).analyze_url_heuristics(payload)
        else:
            from app.services.phishing_detector import analyze_email_heuristics

            indicators = analyze_email_heuristics(payload["sender"], payload["subject"], payload["body"])
        # Inject synthetic ML probabilities across the whole range.
        prob = rng.random()
        indicators = [i for i in indicators if i.get("type") != "ml_model"]
        from app.services.ml_inference import ml_indicator

        indicators.append(ml_indicator("synthetic-model.pkl", prob))
        heuristic, blended, ml_prob = score_with_ml(indicators)
        assert ml_prob is not None
        checked += 1
        if blended < heuristic:
            lowered.append((heuristic, blended, prob))
    eval_report.record_property("monotonic_blend_urls", checked=checked, violations=len(lowered))
    assert not lowered, f"monotonicity violated in {len(lowered)}/{checked} cases, e.g. {lowered[:5]}"


def test_property_severity_bands_monotonic():
    """Score -> severity mapping is non-decreasing with score."""
    prev_rank = -1
    order = ["safe", "low", "medium", "high", "critical"]
    for score in range(0, 101):
        severity = get_severity(score)
        rank = order.index(severity)
        assert rank >= prev_rank, f"severity regressed at score {score}: {severity}"
        prev_rank = rank


def test_property_severity_weights_cover_all_bands():
    assert SEVERITY_WEIGHTS == {"critical": 25, "high": 15, "medium": 5}


def test_property_split_ml_indicator_round_trip(eval_report):
    """split_ml_indicator extracts exactly the ml_model indicator it was given,
    across 1000 synthetic indicator sets."""
    from app.services.ml_inference import ml_indicator

    rng = random.Random(91)
    mismatches = 0
    for _ in range(1000):
        base = [
            {"type": "urgency", "value": "urgent", "severity": "high", "description": "d"},
            {"type": "lookalike_domain", "value": "evil.tk", "severity": "critical", "description": "d"},
        ]
        prob = rng.random()
        with_ml = base + [ml_indicator("model.pkl", prob)]
        clean, extracted_prob = split_ml_indicator(with_ml)
        if extracted_prob is None or abs(extracted_prob - prob) > 1e-4:
            mismatches += 1
            continue
        if any(i.get("type") == "ml_model" for i in clean):
            mismatches += 1
        if len(clean) != len(base):
            mismatches += 1
    eval_report.record_property("split_ml_round_trip", cases=1000, mismatches=mismatches)
    assert mismatches == 0
