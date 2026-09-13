# CYBERGUARD Evaluation Harness Report

- Generated: 2026-09-13T19:03:57.803377+00:00
- Git tip: 9d20eed
- Scale option: default
- Data mode: auto

## Per-engine metrics

| Engine | Cases | Positives | Precision | Recall | F1 | AUC | Malicious mean | Benign mean | Band gap | MW p-value |
|---|---|---|---|---|---|---|---|---|---|---|
| url_detector_blended | 800 | 300 | 0.9123 | 0.9367 | 0.9243 | 0.9655 | 34.75 | 6.13 | 28.62 | 0.0000 |
| url_detector_heuristic_only | 800 | 300 | 0.6930 | 0.5267 | 0.5985 | 0.7659 | 11.40 | 3.63 | 7.77 | 0.0000 |

## Property tests


## HTTP latency (sampled analysis requests)

- (no HTTP samples recorded)

## Data provenance

| Source | Mode | Rows | SHA256 | Fetched at |
|---|---|---|---|---|
| phishing_urls | cache | 300 | —… | 2026-09-13T19:03:59.681221+00:00 |

## Findings (bugs discovered by the harness — NOT fixed)

- FIXED (url_xgb_v3): v2 scored benign top-1m domains at phishing probability ~0.76 (long tracking URLs). v3 retrains on 50k top-1M benign URLs (10k tracking-augmented) + 50k real Phishing.Database URLs with domain/path/query entropy split features — benign domains with long tracking query strings now score <0.05.
- Real OpenPhish URLs hosted on legitimate platforms (vercel.app, godaddysites.com) are structurally plain and score low on URL heuristics (heuristic-only AUC ~0.77); the v2 ML model detects them (blended AUC higher). This validates the hybrid design for platform-hosted phishing.
- url FN: FN payload=https://kqid7e1vkh3d0r88k3d.vercel.app/nsvw35re4hbarefsdbvzxcv score=35 indicators=['url_entropy:medium', 'random_path_segment:medium', 'ml_model:critical']
- url FN: FN payload=https://www.welcome-trezor-bridge.godaddysites.com/ score=30 indicators=['url_entropy:medium', 'ml_model:critical']
- url FN: FN payload=https://iamivanaalawicash.blogspot.com/ score=25 indicators=['ml_model:critical']
- url FN: FN payload=https://www.iamivanaalawicash.blogspot.com/ score=25 indicators=['ml_model:critical']
- url FN: FN payload=https://lnk.ink/AQDO7 score=25 indicators=['ml_model:critical']
