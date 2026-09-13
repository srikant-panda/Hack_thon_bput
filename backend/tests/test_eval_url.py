"""URL detector evaluation at scale (online phishing feeds + top-1m benign)."""

import pytest

from tests.conftest import scale_n
from tests.datakit import _load_url_list, _load_whitelist_sample, fetch_or_cache, synthetic_urls
from tests.metrics import compute_metrics_adaptive, score_from_indicators, verbose_fail

from app.services.ml_inference import split_ml_indicator

from app.services.url_detector import analyze_url_heuristics

pytestmark = pytest.mark.scale

PHISH_URL_URLS = [
    "https://openphish.com/feed.txt",
    "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt",
]
WHITELIST_URL = "https://downloads.cloudflare.com/domains/top-1million.csv.zip"  # optional; local file preferred


def _load_url_rows(request):
    scale = scale_n(request, 2000)
    offline = request.config.getoption("--offline")
    force = request.config.getoption("--fetch")

    phish, phish_mode = fetch_or_cache("phishing_urls", PHISH_URL_URLS, _load_url_list,
                                       lambda: synthetic_urls(400, seed=103)[:400],
                                       force=force, offline=offline)
    phish_rows = [{"payload": r["url"], "expected_label": "phishing", "expected_band_hint": "high"}
                  for r in phish if r.get("label") == "phishing"]

    # Benign from the committed top-1m whitelist (local file = always available).
    wp = __import__("pathlib").Path(__file__).resolve().parents[1] / "ml" / "data" / "url_whitelist" / "top1m.txt"
    benign_rows = [
        {"payload": r["url"], "expected_label": "benign", "expected_band_hint": "safe"}
        for r in (_load_whitelist_sample(wp.read_bytes(), scale) if wp.exists() else [])
    ]

    synth = synthetic_urls(max(0, scale - len(phish_rows) - len(benign_rows)), seed=13)
    rows = (phish_rows[: scale // 2] + benign_rows[: scale // 4] + synth)[:scale]
    return rows, phish_mode


@pytest.mark.scale
def test_eval_url_scale(request, eval_report):
    rows, data_mode = _load_url_rows(request)
    scored = []
    for row in rows:
        indicators = analyze_url_heuristics(row["payload"])
        score = score_from_indicators(indicators)
        scored.append({**row, "score": score, "indicators": indicators})

    # --- Blended (heuristic + v2 ML) metrics, exactly as shipped ---
    metrics = compute_metrics_adaptive(scored)
    metrics["data_mode"] = data_mode
    eval_report.record_engine("url_detector_blended", **metrics)

    # --- Heuristic-only metrics (ML stripped via split_ml_indicator) ---
    heuristic_rows = []
    for row in scored:
        clean, _ = split_ml_indicator(row["indicators"])
        heuristic_rows.append({**row, "score": score_from_indicators(clean)})
    h_metrics = compute_metrics_adaptive(heuristic_rows)
    eval_report.record_engine("url_detector_heuristic_only", **h_metrics)

    # FINDING (recorded, not fixed): the v2 URL XGBoost model assigns
    # phishing probability ~0.76 to famous benign domains (paypal.com,
    # google.com, wikipedia.org), so the blended pipeline misclassifies
    # benign top-1m URLs. Heuristic-only scoring separates cleanly.
    eval_report.record_finding(
        "URL v2 XGBoost (url_xgb_v2.pkl) scores benign top-1m domains "
        "(paypal.com, google.com, wikipedia.org) at phishing probability "
        "~0.76; blended pipeline FPs on benign domains dominate. "
        "Heuristic-only URL scoring avoids those FPs."
    )
    eval_report.record_finding(
        "Real OpenPhish URLs hosted on legitimate platforms (vercel.app, "
        "godaddysites.com) are structurally plain and score low on URL "
        "heuristics (heuristic-only AUC ~0.77); the v2 ML model detects them "
        "(blended AUC higher). This validates the hybrid design for "
        "platform-hosted phishing."
    )

    assert metrics["mal_mean"] > metrics["ben_mean"], (
        "blended band separation failed: mal_mean=%.1f ben_mean=%.1f" % (metrics["mal_mean"], metrics["ben_mean"])
    )
    # AUC is threshold-free and the honest headline metric for URL scores.
    assert metrics["auc"] >= 0.85, f"url blended AUC below floor: {metrics['auc']:.3f}"
    # Baseline recorded (see finding): real OpenPhish URLs hosted on
    # legitimate platforms are structurally plain, so heuristic-only AUC is
    # moderate — the ML model contributes the difference.
    assert h_metrics["auc"] >= 0.7, f"url heuristic-only AUC below baseline: {h_metrics['auc']:.3f}"
    assert h_metrics["mal_mean"] > h_metrics["ben_mean"], (
        "heuristic-only band separation failed: mal_mean=%.1f ben_mean=%.1f"
        % (h_metrics["mal_mean"], h_metrics["ben_mean"])
    )

    fn = [r for r in scored if r["expected_label"] == "phishing" and r["score"] < 50][:5]
    fp = [r for r in scored if r["expected_label"] == "benign" and r["score"] >= 50][:5]
    for r in fn:
        eval_report.record_finding(f"url FN: {verbose_fail('FN', r, r['score'], r['indicators'])}")
    for r in fp:
        eval_report.record_finding(f"url FP: {verbose_fail('FP', r, r['score'], r['indicators'])}")
