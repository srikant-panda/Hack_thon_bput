"""Media forensics evaluation at scale (synthetic images + audio)."""

import pytest

from tests.conftest import scale_n
from tests.datakit import synthetic_audio, synthetic_images
from tests.metrics import compute_metrics_adaptive

from app.services.deepfake_detector import analyze_media

pytestmark = [pytest.mark.scale, pytest.mark.media]


def _score_rows(rows) -> tuple[list[dict], list[str]]:
    scored = []
    errors: list[str] = []
    for row in rows:
        payload = row["payload"]
        try:
            file_bytes = open(payload["path"], "rb").read()
            result = analyze_media(file_bytes, payload["file_name"], payload["content_type"])
            score = int(result["risk_score"])
        except Exception as exc:  # noqa: BLE001 - record engine errors as findings
            errors.append(f"{payload['file_name']}: {type(exc).__name__}: {exc}")
            continue
        scored.append({**row, "score": score})
    return scored, errors


@pytest.mark.scale
@pytest.mark.media
def test_eval_media_scale(request, eval_report, tmp_path):
    n = scale_n(request, 400)
    rows = synthetic_images(n // 2, seed=17, tmp_dir=tmp_path / "img") + \
           synthetic_audio(n // 2, seed=19, tmp_dir=tmp_path / "audio")
    scored, errors = _score_rows(rows)
    for e in errors[:5]:
        eval_report.record_finding(f"media engine error: {e}")

    assert len(scored) >= len(rows) * 0.95, f"media engine errored on {len(errors)}/{len(rows)} cases"

    metrics = compute_metrics_adaptive(scored)
    eval_report.record_engine("media_forensics", **metrics)

    assert metrics["mal_mean"] > metrics["ben_mean"] + 10, (
        "band separation failed: mal_mean=%.1f ben_mean=%.1f" % (metrics["mal_mean"], metrics["ben_mean"])
    )
