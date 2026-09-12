# Merging the v2 ML Integration into the Phase Chain

**Date:** 2026-09-13 · **Branch:** `phase-4-enforcement-quarantine` · **Merge commit:** `54aeee8`
**Merged:** `ml-integration` → `phase-4-enforcement-quarantine` (parent `5625b2a` "feat: phase 4 — real enforcement, quarantine, sender rules, expiry scheduler, user settings")

This document records how the v2 ML integration was restored into the
Phase -1…4 chain (Gmail connectors, RLS, enforcement, mailbox scanning)
without losing any phase work, and how each merge conflict was resolved.

---

## 1. Pre-merge verification (before touching anything)

The v2 artifacts had to be in git — not fetched from external sources — before
the merge was allowed to proceed:

```bash
git ls-tree -r ml-integration --name-only -- backend/ml
```

Confirmed present on the branch:

- Weights: `deepfake_cnn_v2.pt`, `email_phishing_xgb_v2.pkl`,
  `email_tfidf_v2.pkl`, `url_xgb_v2.pkl`, `audio_cnn_v1.pt`
- Calibration: `ml/calibration.json` **and** `ml/models/calibration.json`
- Code: `audio_model.py`, `audio_features.py`, `train_deepfake_v2.py`,
  `train_email_model.py`, `train_audio_v1.py`, `ml/data/url_whitelist/top1m.txt`
- New app modules: `app/core/calibration.py`, `app/core/url_reputation.py`

Because everything was in git, the fallback source
(`/home/srikant/Downloads/new/hackathon_01/backend/ml/models/`) was **not**
used, and nothing was pulled from external repositories.

## 2. Merge procedure

```bash
git checkout phase-4-enforcement-quarantine   # was already the checked-out tip
git merge ml-integration -m "merge v2 ML integration into phase chain"
```

The merge auto-resolved most files (ml-integration had not diverged from the
merge base on them) and produced **exactly two content conflicts**:

```
CONFLICT: backend/app/services/assistant_service.py
CONFLICT: backend/scripts/run_all_tests.py
```

Resolution rules that were agreed up-front and applied:

| Zone | Rule applied |
|---|---|
| `scripts/run_all_tests.py` | Keep **both** suite registrations, renumber sequentially |
| `DECISIONS.md`, `docs/*` | Keep both sections (no conflict actually occurred) |
| `app/core/config.py` | Keep Phase -1 settings **and** ML settings (ml never touched it — HEAD kept) |
| `backend/ml/**`, `ml_inference.py`, `deepfake_detector.py`, `calibration.py`, `media_forensics/*` | Take the ml-integration version |
| `app/db/models.py` | Keep the Phase -1 schema (`owner_user_id`, `cyberguard` schema); ML added no columns (HEAD kept) |

## 3. Conflict 1 — `backend/scripts/run_all_tests.py`

**Cause of conflict:** both branches had registered their own "Suite 9".
The phase chain had Suites 9–13 (User Foundation, RLS-PG, Email Connectors,
Mail Scanner, Enforcement); ml-integration had registered its ML gates as
Suite 9.

**Resolution:** both registrations were kept and the suite list was
renumbered sequentially. ML gates run first (they are synchronous gate
checks), then the phase suites:

| Suite | Content | Source |
|---|---|---|
| 1–8 | DB init, tenant provisioning, analysis engines, key rotator, dual-mode, server-mode, approvals, assistant | existing (renumbered 8 = assistant) |
| **9** | **ML Integration Gates** (blend contract, v2 models, audio LCNN) | ml-integration |
| 10–14 | User Foundation, RLS-PG, Email Connectors, Mail Scanner, Enforcement | phase chain (was 9–13) |

Print headers, comments, and imports were all updated to the new numbers.
No assertion was altered.

## 4. Conflict 2 — `backend/app/services/assistant_service.py`

**Cause of conflict:** both branches had refactored the same functions in
incompatible directions.

- **ml-integration** rewrote the assistant under a strict *whitelist policy*:
  renamed intents (`GREETING`, `HELP`, `OPS_STATS`, `OPS_CRITICAL`,
  `OPS_MITRE`, `OPS_PRIORITIZE`), added `INTERNAL_PROBE` (probe attempts are
  audit-logged and refused) and `OUT_OF_SCOPE` (refused; never sent to the
  LLM), added `REFUSAL_*` constants, and **deleted**
  `_reply_general_question`.
- **The phase chain** had refactored the same file to tenant-based scoping:
  `_reply_*(db, tenant)` helpers (replacing `organization_id`) and a
  `tenant=tenant` audit-log signature.

**Resolution:** ml-integration's *behavior* won; the phase chain's *scoping*
was preserved. Concretely:

1. Dropped HEAD's `_reply_general_question` (ml deleted it; the whitelist
   flow answers free-text with `REFUSAL_OUT_OF_SCOPE` and never reaches the
   LLM heuristic output).
2. Took ml's docstring and intent dispatch (`OPS_*` / `OUT_OF_SCOPE`).
3. Adapted the four OPS reply calls to the tenant-based helpers:
   `_reply_summary(db, tenant)` etc. — ml's version passed
   `organization_id`, a variable that no longer exists in the phase code.
4. The new `INTERNAL_PROBE` audit-log call was changed from
   `organization_id=organization_id` to `tenant=tenant` so it satisfies the
   Phase -1 `audit_service.log_action` signature and stays RLS-correct.

Result: ml's assistant policy, phase chain's tenancy.

## 5. Auto-merged files (verified, no manual edits)

| File | Change | Verification |
|---|---|---|
| `app/services/ml_inference.py` | v2 model loaders + blending | suite green; imports resolve v2 artifacts |
| `app/services/deepfake_detector.py` | v2 CNN blend; explicit `heuristics-only-fallback` indicator | Suite 13 media branch untouched and passing |
| `app/services/media_forensics/image_analyzer.py` | calibration-driven thresholds | suite green |
| `app/core/calibration.py`, `app/core/url_reputation.py` | new (additive) | `get_deepfake_calibration()` loads `ml/calibration.json` |
| `app/ai/prompt_templates.py` | additive audio domain-shift caveat for honest LLM output | reviewed |
| `scripts/test_assistant.py` | rewritten by ml for the new intents | Suite 8 green |
| `scripts/test_phase3.py` | FK-safe org creation in a test helper (aids Postgres) | reviewed; 7 lines |
| `backend/ml/**` (weights, corpus, training scripts) | new, additive | `ls ml/models/` shows all v2 artifacts |
| `config.py`, `app/db/models.py`, `main.py`, all migrations, all routes/services of the phase chain, entire `frontend/src` | **unchanged** — zero diff vs pre-merge tip | `git diff 5625b2a HEAD -- backend/app backend/alembic backend/scripts frontend/src` reviewed per file |

## 6. Post-merge verification checklist

```bash
ls backend/ml/models/
# audio_cnn_v1.pt  deepfake_cnn_v2.pt  email_phishing_xgb_v2.pkl  url_xgb_v2.pkl
# calibration.json audio_v1_metrics.json  deepfake_v2_metrics.json
# email_tfidf_v2.pkl  (+ v1 artifacts retained)

uv run python -c "
from app.services import ml_inference
from app.core.calibration import get_deepfake_calibration
print(get_deepfake_calibration())"
# loads ml/calibration.json (splice thresholds, noise floor, CNN real-threshold...)

DATABASE_URL="sqlite+aiosqlite:////tmp/cg_merge.db" \
  uv run python scripts/run_all_tests.py
# TEST RESULTS: 338/338 passed   (318 phase checks + 20 ML gates; exit 0)
```

## 7. Behavioral impact on the phase features

- **Unchanged:** auth, RLS/GUC wiring, connectors, OAuth, token vault,
  scanning pipeline structure, enforcement, scheduler, and the entire
  frontend (byte-identical to `5625b2a`).
- **Intended changes from the ML restore:** mailbox scans and `/analysis`
  verdicts now carry v2-blended ML scores through the same call sites as
  before (`analyze_email_heuristics` → `score_with_ml`), and deepfake analysis
  uses the v2 CNN with calibration thresholds.
- **Intended change from the assistant conflict:** the SOC Assistant now runs
  ml-integration's strict whitelist policy (out-of-scope questions refused,
  probe attempts audit-logged) with phase-tenant scoping intact.
