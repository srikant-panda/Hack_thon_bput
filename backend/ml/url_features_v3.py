"""URL v3 feature extraction — domain reputation separated from URL structure.

Root cause this version fixes: the v2 model over-indexed on total URL length
and total entropy, so a benign domain with a long marketing query string
(medium.com/?source=email-...&utm_medium=email) scored like a lookalike
phishing host (paypa1-secure.tk/login). v3 gives the model the evidence it
needs to separate the two cases:

  1. DOMAIN REPUTATION  — is_top_1m: registrable domain in the Umbrella top-1M
     whitelist (same set the runtime uses, loaded once into an in-memory set
     for O(1) lookups).
  2. STRUCTURAL ENTROPY — entropy computed separately for the domain, the
     path and the query, so a high-entropy tracking blob on a reputable host
     no longer contaminates the host signal.
  3. LENGTH METRICS     — domain_length / path_length / query_length split
     out of total_length.
  4. TRACKING PARAMS    — has_tracking_params / num_query_params: benign
     marketing-email signals.
  5. MALICIOUS INDICATORS — IP host, dot/subdomain count, '@' trick,
     suspicious free TLDs, domain digit-ratio and hyphen count (leet lookalikes),
     credential-path keywords.

MUST stay in sync between training (ml/scripts/train_url_v3.py) and inference
(app/services/ml_inference.py) — both go through this module, so editing here
keeps them identical.
"""

import math
import re
from urllib.parse import urlparse

# Fixed column order for the XGBoost feature matrix (flat dict -> vector).
FEATURE_COLUMNS_V3 = [
    "is_top_1m",
    "domain_entropy",
    "path_entropy",
    "query_entropy",
    "domain_length",
    "path_length",
    "query_length",
    "total_length",
    "has_tracking_params",
    "num_query_params",
    "has_ip",
    "num_dots",
    "num_subdomains",
    "has_at_symbol",
    "suspicious_tld",
    "http_only",
    "domain_digit_ratio",
    "domain_hyphens",
    "has_suspicious_path_keyword",
]

SUSPICIOUS_TLDS_V3 = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "loan", "click", "rest"}

TRACKING_PARAM_PATTERN = re.compile(r"(?:^|[?&])(utm_[a-z_]+=|source=|ref=|ref_src=|campaign=|email=|fbclid=|gclid=|mc_cid=|mc_eid=|_hsenc=|mkt_tok=)", re.IGNORECASE)

CREDENTIAL_PATH_PATTERN = re.compile(
    r"(?:login|signin|sign-in|verify|secure|account|update|billing|password|confirm|webscr|wallet)",
    re.IGNORECASE,
)

IP_HOST_PATTERN = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def shannon_entropy_v3(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    total = len(value)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _registrable(domain: str) -> str:
    """Registrable domain via the runtime reputation service (ccTLD-aware).

    Falls back to the last two labels only if the app package is not
    importable (standalone script usage outside the backend directory).
    """
    try:
        from app.core.url_reputation import get_registrable_domain

        return get_registrable_domain(domain)
    except Exception:
        parts = [p for p in domain.split(".") if p]
        return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def extract_url_features_v3(url: str, top_1m_domains: set) -> dict:
    """Flat feature dict for one URL. `top_1m_domains` must be a set of
    registrable domains (see load_top1m_domain_set) for O(1) membership."""
    try:
        parsed = urlparse(url)
    except ValueError:
        parsed = urlparse(f"http://{url}")

    domain = (parsed.hostname or "").strip().lower()
    path = parsed.path or ""
    query = parsed.query or ""

    is_top_1m = 1 if (_registrable(domain) in top_1m_domains or domain in top_1m_domains) else 0

    domain_digits = sum(c.isdigit() for c in domain)
    domain_alnum = sum(c.isalnum() for c in domain)

    labels = [p for p in domain.split(".") if p]
    num_subdomains = max(0, len(labels) - 2)

    return {
        "is_top_1m": float(is_top_1m),
        "domain_entropy": shannon_entropy_v3(domain),
        "path_entropy": shannon_entropy_v3(path),
        "query_entropy": shannon_entropy_v3(query),
        "domain_length": float(len(domain)),
        "path_length": float(len(path)),
        "query_length": float(len(query)),
        "total_length": float(len(url)),
        "has_tracking_params": 1.0 if TRACKING_PARAM_PATTERN.search(query) else 0.0,
        "num_query_params": float(query.count("&") + 1) if query else 0.0,
        "has_ip": 1.0 if IP_HOST_PATTERN.match(domain) else 0.0,
        "num_dots": float(domain.count(".")),
        "num_subdomains": float(num_subdomains),
        # '@' credential trick lives in the authority (userinfo@host), not in
        # the path — benign user-profile URLs (medium.com/@handle) must NOT trip it.
        "has_at_symbol": 1.0 if "@" in parsed.netloc else 0.0,
        "suspicious_tld": 1.0 if (labels and labels[-1].lower() in SUSPICIOUS_TLDS_V3) else 0.0,
        "http_only": 1.0 if parsed.scheme == "http" else 0.0,
        "domain_digit_ratio": domain_digits / domain_alnum if domain_alnum else 0.0,
        "domain_hyphens": float(domain.count("-")),
        "has_suspicious_path_keyword": 1.0 if CREDENTIAL_PATH_PATTERN.search(path) else 0.0,
    }


def vectorize_v3(features: dict) -> list[float]:
    """Flat dict -> fixed-order float vector (FEATURE_COLUMNS_V3 order)."""
    return [float(features[col]) for col in FEATURE_COLUMNS_V3]
