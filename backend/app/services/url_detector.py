"""URL heuristic detector (Part 3).

Lexical/rule-based analysis of a single URL. No ML or LLM logic here.
"""

import math
from collections import Counter
from urllib.parse import urlparse

from app.services.ml_inference import ml_indicator, predict_url, url_model_artifact

BRAND_NAMES = (
    "microsoft",
    "paypal",
    "google",
    "amazon",
    "apple",
    "facebook",
    "netflix",
    "office365",
    "outlook",
    "dhl",
    "fedex",
    "hsbc",
    "linkedin",
    "github",
    "dropbox",
    "slack",
    "zoom",
    "adobe",
    "chase",
    "wellsfargo",
    "bankofamerica",
    "coinbase",
    "binance",
    "discord",
    "spotify",
    "steam",
    "twitter",
    "instagram",
    "whatsapp",
    "telegram",
    "notion",
    "cloudflare",
)

SUSPICIOUS_TLDS = {"xyz", "top", "zip", "click", "link", "work", "loan", "cam", "rest", "tk", "ml", "ga", "cf", "gq"}

SUSPICIOUS_PATH_KEYWORDS = (
    "login",
    "verify",
    "secure",
    "signin",
    "sign-in",
    "update",
    "account",
    "password",
    "reset",
    "recover",
    "credential",
    "auth",
    "sso",
    "confirm",
    "wallet",
    "unlock",
    "restore",
    "mailbox",
    "billing",
    "oauth",
    "payment",
)

MAX_NORMAL_URL_LENGTH = 75
ENTROPY_THRESHOLD = 4.0

# --- URLhaus-informed indicators (Part 8 tuning) ---
# True executable/binary/script payload extensions observed in malware campaigns.
# Standard web documents/scripts (html, php, js) are excluded to avoid false positives.
EXECUTABLE_OR_PAYLOAD_EXTENSIONS = {
    "exe", "scr", "vbs", "hta", "bat", "cmd", "ps1", "sh", "bin", "apk", "jar", "msi", "dll",
    "ppc", "mips", "mipsel", "arm", "sh4", "m68k", "i586", "x32", "x64", "sparc",
}
# TLDs frequently abused by URLhaus campaigns; combined with a long path this
# is a strong distribution-page signature.
URLHAUS_SUSPICIOUS_TLDS = {"ru", "cn", "top", "xyz"}
URLHAUS_MIN_PATH_LENGTH = 20
# A path segment this long with mixed letters/digits and high entropy looks
# machine-generated (e.g. /x7f9a2b/malware.exe).
RANDOM_SEGMENT_MIN_LENGTH = 10
RANDOM_SEGMENT_ENTROPY_THRESHOLD = 3.0
# Digit share of alphanumeric characters in host+path above which the URL
# looks machine-generated (IP hosts always trip this).
EXCESSIVE_DIGIT_RATIO = 0.3
EXCESSIVE_DIGIT_MIN_COUNT = 5

AUTHENTIC_MAJOR_DOMAINS = {
    "linkedin.com", "licdn.com", "lnkd.in",
    "google.com", "gstatic.com", "googleusercontent.com", "youtube.com", "youtu.be",
    "microsoft.com", "office.com", "live.com", "microsoftonline.com", "office365.com",
    "apple.com", "icloud.com",
    "amazon.com", "aws.amazon.com",
    "github.com", "githubusercontent.com",
    "netflix.com", "medium.com", "notion.so",
    "paypal.com", "stripe.com",
    "slack.com", "zoom.us", "dropbox.com",
    "openai.com", "chatgpt.com",
    "cloudflare.com",
}


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _parse_url(url: str) -> urlparse.ParseResult:
    try:
        parsed = urlparse(url)
    except ValueError:
        try:
            parsed = urlparse(f"http://{url}")
        except ValueError:
            parsed = urlparse("http://invalid/")  # unparseable URL: fall back to defaults
    if not parsed.scheme:
        try:
            parsed = urlparse(f"http://{url}")
        except ValueError:
            parsed = urlparse("http://invalid/")
    return parsed


def _check_ip_host(host: str) -> list[dict]:
    labels = host.split(".")
    if (
        len(labels) == 4
        and all(label.isdigit() and 0 <= int(label) <= 255 for label in labels)
        and host != ""
    ):
        return [
            {
                "type": "ip_host",
                "value": host,
                "severity": "critical",
                "description": "The URL uses a raw IP address instead of a domain name.",
            }
        ]
    return []


def _check_homoglyphs(host: str) -> list[dict]:
    if not host:
        return []
    if "xn--" in host or any(not c.isascii() for c in host):
        return [
            {
                "type": "homoglyph_confusable",
                "value": host,
                "severity": "critical",
                "description": "Host uses punycode (IDN) or non-ASCII characters, indicative of homoglyph domain spoofing.",
            }
        ]
    try:
        from ml.url_features_v3 import homoglyph_skeleton
        skeleton = homoglyph_skeleton(host)
        if skeleton != host:
            return [
                {
                    "type": "homoglyph_confusable",
                    "value": host,
                    "severity": "critical",
                    "description": f"Host '{host}' contains visual homoglyphs confusable with '{skeleton}'.",
                }
            ]
    except Exception:
        pass
    return []


def _check_brand_typosquatting(host: str) -> list[dict]:
    if not host:
        return []
    try:
        from app.core.url_reputation import get_registrable_domain
        from app.services.domain_intelligence import lookalike_candidate
        from ml.url_features_v3 import BRAND_OFFICIAL_DOMAINS_V4

        reg = get_registrable_domain(host)
        brand, reason = lookalike_candidate(host)
        if brand is not None:
            official = BRAND_OFFICIAL_DOMAINS_V4.get(brand)
            if official and reg == official:
                return []
            return [
                {
                    "type": "brand_typosquatting",
                    "value": host,
                    "severity": "critical",
                    "description": f"Domain '{host}' is a lookalike / typosquatting candidate for brand '{brand}' ({reason}).",
                }
            ]
    except Exception:
        pass
    return []


def _check_subdomain_spoofing(host: str) -> list[dict]:
    try:
        from app.core.url_reputation import get_registrable_domain
        from app.services.url_token_classifier import COMMON_TLDS

        labels = [p for p in host.split(".") if p]
        if len(labels) >= 3:
            registrable = get_registrable_domain(host)
            if host.endswith("." + registrable):
                subdomain_labels = [p for p in host[: -len(registrable) - 1].split(".") if p]
                if any(lbl in COMMON_TLDS for lbl in subdomain_labels):
                    return [
                        {
                            "type": "subdomain_spoofing",
                            "value": host,
                            "severity": "high",
                            "description": "The URL uses a deceptive subdomain structure mimicking a registered domain name.",
                        }
                    ]
    except Exception:
        pass
    return []


def _check_brand_in_subdomain(host: str) -> list[dict]:
    try:
        from app.core.url_reputation import get_registrable_domain

        labels = [label for label in host.lower().split(".") if label]
        if len(labels) < 3:
            return []
        registrable = get_registrable_domain(host)
        if host.endswith("." + registrable):
            subdomain_part = host[: -len(registrable) - 1]
        else:
            subdomain_part = ".".join(labels[:-2])

        for brand in BRAND_NAMES:
            if brand in subdomain_part and brand not in registrable:
                return [
                    {
                        "type": "brand_in_subdomain",
                        "value": host,
                        "severity": "critical",
                        "description": (
                            f"Trusted brand '{brand}' appears in the subdomain but the "
                            f"actual registrable domain is '{registrable}'."
                        ),
                    }
                ]
    except Exception:
        pass
    return []


def _check_length_and_entropy(url: str) -> list[dict]:
    indicators: list[dict] = []
    if len(url) > MAX_NORMAL_URL_LENGTH:
        indicators.append(
            {
                "type": "url_length",
                "value": str(len(url)),
                "severity": "medium",
                "description": f"URL is unusually long ({len(url)} characters, threshold {MAX_NORMAL_URL_LENGTH}).",
            }
        )
    entropy = _shannon_entropy(url)
    if entropy > ENTROPY_THRESHOLD:
        indicators.append(
            {
                "type": "url_entropy",
                "value": f"{entropy:.2f}",
                "severity": "medium",
                "description": f"URL character entropy is high ({entropy:.2f}, threshold {ENTROPY_THRESHOLD}), suggesting randomized text.",
            }
        )
    return indicators


def _check_tld(host: str) -> list[dict]:
    tld = host.rsplit(".", 1)[-1].lower() if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        return [
            {
                "type": "suspicious_tld",
                "value": f".{tld}",
                "severity": "high",
                "description": f"The URL uses the suspicious TLD '.{tld}'.",
            }
        ]
    return []


def _check_scheme(scheme: str, is_authentic: bool = False) -> list[dict]:
    if scheme == "http":
        if is_authentic:
            return [
                {
                    "type": "insecure_link_hygiene",
                    "value": "http",
                    "severity": "low",
                    "description": "Hygiene note: The URL uses plain HTTP instead of HTTPS on a well-known domain.",
                }
            ]
        return [
            {
                "type": "insecure_scheme",
                "value": "http",
                "severity": "high",
                "description": "The URL uses plain HTTP instead of HTTPS.",
            }
        ]
    return []


def _check_path_keywords(path: str) -> list[dict]:
    lowered = path.lower()
    matched = [keyword for keyword in SUSPICIOUS_PATH_KEYWORDS if keyword in lowered]
    if matched:
        return [
            {
                "type": "suspicious_path_keyword",
                "value": ", ".join(matched),
                "severity": "medium",
                "description": f"URL path contains credential-harvesting keywords: {', '.join(matched)}.",
            }
        ]
    return []


def _path_extension(path: str) -> str:
    last_segment = path.rstrip("/").rsplit("/", 1)[-1]
    if "." not in last_segment:
        return ""
    return last_segment.rsplit(".", 1)[-1].lower()


def _check_executable_extension(path: str) -> list[dict]:
    extension = _path_extension(path)
    if extension and extension in EXECUTABLE_OR_PAYLOAD_EXTENSIONS:
        return [
            {
                "type": "executable_extension",
                "value": f".{extension}",
                "severity": "high",
                "description": (
                    f"The URL path serves an executable, script or payload file "
                    f"(.{extension}), typical of malware distribution pages."
                ),
            }
        ]
    return []


def _check_random_path_segments(path: str) -> list[dict]:
    for segment in path.split("/"):
        segment = segment.strip()
        if len(segment) < RANDOM_SEGMENT_MIN_LENGTH:
            continue
        letters = sum(char.isalpha() for char in segment)
        digits = sum(char.isdigit() for char in segment)
        if letters == 0 or digits == 0:
            continue
        if _shannon_entropy(segment) > RANDOM_SEGMENT_ENTROPY_THRESHOLD:
            return [
                {
                    "type": "random_path_segment",
                    "value": segment,
                    "severity": "medium",
                    "description": (
                        f"Path segment '{segment}' looks machine-generated "
                        "(high entropy, mixed letters and digits)."
                    ),
                }
            ]
    return []


def _check_excessive_digits(host: str, path: str) -> list[dict]:
    text = host + path
    digit_count = sum(char.isdigit() for char in text)
    alpha_count = sum(char.isalpha() for char in text)
    if digit_count >= EXCESSIVE_DIGIT_MIN_COUNT and alpha_count and digit_count / (digit_count + alpha_count) > EXCESSIVE_DIGIT_RATIO:
        return [
            {
                "type": "excessive_digits",
                "value": f"digit_ratio={digit_count / (digit_count + alpha_count):.2f}",
                "severity": "medium",
                "description": (
                    "The URL host/path contains an excessive proportion of digits, "
                    "typical of machine-generated malware distribution links."
                ),
            }
        ]
    return []


def _check_urlhaus_pattern(host: str, path: str) -> list[dict]:
    tld = host.rsplit(".", 1)[-1].lower() if "." in host else ""
    if tld in URLHAUS_SUSPICIOUS_TLDS and len(path) > URLHAUS_MIN_PATH_LENGTH:
        return [
            {
                "type": "urlhaus_pattern",
                "value": f".{tld} TLD with {len(path)}-character path",
                "severity": "high",
                "description": (
                    f"Abused TLD '.{tld}' combined with a long path matches the "
                    "URLhaus malware-distribution URL pattern."
                ),
            }
        ]
    return []


CRITICAL_IDENTITY_PATTERNS = (
    "sso",
    "identity-validation",
    "protection-center",
    "password-reset",
    "mail-admin",
    "document-share",
    "oauth-session",
    "cloud-drive",
    "account-protection",
    "bank-account",
    "wallet-recovery",
    "account-locked",
    "vpn-auth",
    "payment-confirmation",
    "banking-auth",
)

GENERIC_LURE_WORDS = {
    "account",
    "signin",
    "login",
    "verify",
    "secure",
    "security",
    "identity",
    "payment",
    "billing",
    "session",
    "update",
    "profile",
    "confirm",
    "mailbox",
    "support",
    "customer",
    "center",
    "portal",
    "alert",
    "notice",
    "storage",
    "check",
    "review",
    "user",
    "service",
    "cloud",
    "help",
}


def _check_credential_lure_domain(host: str, is_authentic: bool = False) -> list[dict]:
    if is_authentic or not host:
        return []
    from app.core.url_reputation import get_registrable_domain
    reg = get_registrable_domain(host)
    sld = reg.split(".")[0] if "." in reg else host
    for pat in CRITICAL_IDENTITY_PATTERNS:
        if pat in sld or pat in host:
            return [
                {
                    "type": "credential_harvesting_domain",
                    "value": host,
                    "severity": "critical",
                    "description": f"Domain uses enterprise identity or account credential lure pattern '{pat}' on an unverified domain.",
                }
            ]
    parts = sld.split("-")
    matches = [p for p in parts if p in GENERIC_LURE_WORDS]
    if len(matches) >= 2 or (len(parts) == 1 and sld in GENERIC_LURE_WORDS):
        return [
            {
                "type": "generic_credential_lure_domain",
                "value": host,
                "severity": "medium",
                "description": f"Domain uses generic account/credential lure patterns ({sld}).",
            }
        ]
    return []


def _check_subdomain_entropy(host: str, is_authentic: bool = False) -> list[dict]:
    if is_authentic or not host:
        return []
    labels = [p for p in host.split(".") if p]
    if len(labels) >= 3:
        for part in labels[:-2]:
            if len(part) >= 16 and _shannon_entropy(part) >= 3.2:
                return [
                    {
                        "type": "random_subdomain_entropy",
                        "value": part,
                        "severity": "high",
                        "description": (
                            f"Subdomain label '{part}' exhibits high character entropy "
                            f"({_shannon_entropy(part):.2f}), typical of DGA or fast-flux phishing."
                        ),
                    }
                ]
    return []


def is_authentic_host(host: str, is_spoofed: bool = False) -> bool:
    """Verify whether the host belongs to an authentic, high-reputation domain and is not spoofed."""
    if not host or is_spoofed:
        return False
    from app.core.url_reputation import get_registrable_domain, is_domain_in_top1m

    reg = get_registrable_domain(host)
    if reg in AUTHENTIC_MAJOR_DOMAINS or host in AUTHENTIC_MAJOR_DOMAINS:
        return True
    tld = host.rsplit(".", 1)[-1].lower() if "." in host else ""
    if tld in {"gov", "mil", "edu", "int"}:
        return True
    return is_domain_in_top1m(host)


def analyze_url_heuristics(url: str) -> list[dict]:
    """Run URL heuristics and return indicator list with domain authenticity and spoofing awareness.

    1. Checks host hygiene (IP host, homoglyphs, brand typosquatting, subdomain spoofing, suspicious TLD).
    2. Verifies whether the domain is an authentic, reputable platform.
    3. On authentic platforms, standard tokens (JWT, UUID, tracking IDs, session parameters) and
       legitimate authentication paths are recognized as genuine and do not trigger false threats.
    4. On un-spoofed clean domains with structured tokens, length/entropy are down-weighted.
    5. Monotonic blending with the trained ML URL model.
    """
    parsed = _parse_url(url)
    host = (parsed.hostname or "").lower()

    indicators: list[dict] = []

    # 1. Host spoofing & hygiene checks
    ip_inds = _check_ip_host(host)
    homoglyph_inds = _check_homoglyphs(host)
    typosquat_inds = _check_brand_typosquatting(host)
    subdomain_brand_inds = _check_brand_in_subdomain(host)
    subdomain_spoof_inds = _check_subdomain_spoofing(host)
    tld_inds = _check_tld(host)
    lure_inds = _check_credential_lure_domain(host, is_authentic=False)
    subdomain_entropy_inds = _check_subdomain_entropy(host, is_authentic=False)

    spoof_indicators = (
        ip_inds
        + homoglyph_inds
        + typosquat_inds
        + subdomain_brand_inds
        + subdomain_spoof_inds
        + tld_inds
        + [i for i in lure_inds if i.get("severity") == "critical"]
        + subdomain_entropy_inds
    )
    is_spoofed = bool(spoof_indicators)

    # 2. Host reputation & authenticity
    is_authentic = is_authentic_host(host, is_spoofed=is_spoofed)
    if not is_authentic:
        indicators.extend(spoof_indicators)
        indicators.extend([i for i in lure_inds if i.get("severity") != "critical"])

    # 3. Scheme check
    indicators.extend(_check_scheme(parsed.scheme, is_authentic=is_authentic))

    # 4. Executable / binary payload check
    indicators.extend(_check_executable_extension(parsed.path))

    # 5. URLhaus pattern (checked on non-authentic domains)
    if not is_authentic:
        indicators.extend(_check_urlhaus_pattern(host, parsed.path))

    # 6. Lexical & path checks
    if is_authentic:
        # Authentic platforms routinely use deep links with tracking tokens, UUIDs,
        # user/job identifiers, and legitimate login/verify paths. Do not flag them as threats.
        pass
    else:
        from app.services.url_token_classifier import is_domain_clean, analyze_url_structure

        is_clean = not is_spoofed and not bool(lure_inds) and is_domain_clean(host)
        structure = analyze_url_structure(url) if is_clean else {}
        has_tokens = structure.get("has_structured_token", False)

        if not (is_clean and has_tokens):
            indicators.extend(_check_length_and_entropy(url))
            indicators.extend(_check_path_keywords(parsed.path))
            indicators.extend(_check_random_path_segments(parsed.path))
            indicators.extend(_check_excessive_digits(host, parsed.path))
        else:
            # Clean domain with structured tokens (JWT/UUID/Base64/Hex):
            # Suppress token-induced entropy/length; check path keywords if credential harvesting
            indicators.extend(_check_path_keywords(parsed.path))

    probability = predict_url(url)
    if probability is not None:
        if is_authentic and not [i for i in indicators if i.get("severity") in ("medium", "high", "critical")]:
            # On authentic domains with zero threat indicators, ML probability reflects safe band
            probability = min(probability, 0.15)
        from app.services.scoring_service import STRONG_MALICIOUS_INDICATOR_TYPES
        has_strong = any(i.get("type") in STRONG_MALICIOUS_INDICATOR_TYPES for i in indicators)
        indicators.append(ml_indicator(url_model_artifact(), probability, has_strong_evidence=has_strong))

    return indicators
