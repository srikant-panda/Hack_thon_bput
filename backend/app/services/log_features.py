"""Feature extraction for log threat classification (LOG-ML-P2).

Mirrors the existing single-implementation pattern: the SAME functions are used
by the training script (scripts/train_log_model_v1.py) and by any future serving
path, so there is exactly one definition of each feature.

Public surface:
    tokenize(raw_line) -> list[str]                  # whitespace/punct split, keeps IPs/ports/usernames
    normalize_tokens(tokens) -> list[str]            # IP-><IP>, block ids-><BLK>, numbers-><NUM> for generalization
    ngram_text(raw_line) -> str                      # normalized unigram string (vectorizer adds 1-2 grams)
    extract_features(raw_line, source="") -> dict    # numeric structural/temporal/source features
    extract_source_entities(raw_line, source="") -> dict  # interpretable string entities (block id, node id, syscalls)
    vectorize_batch(raw_lines, sources, vectorizer=None) -> (csr_matrix, feature_names)
        vectorizer=None + fit -> fit a new TfidfVectorizer (unigrams+bigrams, max 10k)
        vectorizer given     -> transform only (serving path)
    group_split(keys, ratios, seed) -> list[set[str]]  # grouped split helper (no key straddles a split)

Model contract: the label order for the classifier is BENIGN=0, SUSPICIOUS=1,
MALICIOUS=2 (defined once here as LABELS).
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime

from scipy import sparse
from sklearn.feature_extraction.text import TfidfVectorizer

LABELS = ["benign", "suspicious", "malicious"]
LABEL_TO_IDX = {name: i for i, name in enumerate(LABELS)}
MAX_FEATURES = 10_000

_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b")
_IPV4_STRICT_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_BLOCK_RE = re.compile(r"\bblk_-?\d+\b")
_PORT_RE = re.compile(r"(?::\d{2,5})\b|\bport\s+\d+\b", re.IGNORECASE)
_USER_RE = re.compile(r"\b(?:user|ruser|euid)\s*=\s*\S+|\bfor\s+(?:invalid\s+user\s+)?\S+|\brhost\s*=\s*\S+", re.IGNORECASE)
_TIME_RE = re.compile(r"\b\d{1,2}:\d{2}:\d{2}\b")
_TOKEN_RE = re.compile(r"[A-Za-z0-9_.:@/-]+|[^\s]")

def tokenize(raw_line: str) -> list[str]:
    """Split on whitespace/punctuation but keep IPs, ports, times, usernames,
    block ids and dotted identifiers intact as single tokens."""
    return _TOKEN_RE.findall(raw_line)


def normalize_tokens(tokens: list[str]) -> list[str]:
    """Mask volatile literals so the model learns templates, not constants."""
    out = []
    for tok in tokens:
        low = tok.lower()
        if _BLOCK_RE.fullmatch(tok):
            out.append("<blk>")
        elif _IPV4_RE.fullmatch(tok):
            out.append("<ip>")
        elif _TIME_RE.fullmatch(tok):
            out.append("<time>")
        elif low.isdigit():
            out.append("<num>")
        else:
            out.append(low)
    return out


def ngram_text(raw_line: str) -> str:
    """Normalized token stream fed to the vectorizer (which builds 1-2 grams)."""
    return " ".join(normalize_tokens(tokenize(raw_line)))


def _parse_timestamp(raw_line: str) -> datetime | None:
    """Best-effort timestamp extraction (ISO, BGL dotted, syslog); None when
    absent. Year-less syslog formats default to year 1900 (weekday may then be
    off — hour_of_day is the reliable signal there)."""
    candidates = (
        (re.search(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}", raw_line),
         ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S")),
        (re.search(r"\d{4}-\d{2}-\d{2}-\d{2}\.\d{2}\.\d{2}\.\d+", raw_line),
         ("%Y-%m-%d-%H.%M.%S.%f",)),
        (re.search(r"\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d{1,2}:\d{2}:\d{2}\b", raw_line),
         ("%b %d %H:%M:%S",)),
    )
    for match, formats in candidates:
        if not match:
            continue
        for fmt in formats:
            try:
                if fmt == "%b %d %H:%M:%S":  # year-less syslog: pin a year to avoid the 3.15 ambiguity change
                    return datetime.strptime(f"1900 {match.group(0)}", f"%Y {fmt}")
                return datetime.strptime(match.group(0), fmt)
            except ValueError:
                continue
    return None


NUMERIC_FEATURES = [
    "line_length",
    "num_tokens",
    "avg_token_len",
    "digit_ratio",
    "has_ip",
    "has_port",
    "has_username",
    "has_time",
    "hour_of_day",
    "day_of_week",
    "has_block_id",
    "is_pure_numeric_seq",
]


def extract_features(raw_line: str, source: str = "") -> dict:
    """Numeric feature dict (one row); order fixed by NUMERIC_FEATURES."""
    tokens = tokenize(raw_line)
    length = len(raw_line)
    n = max(len(tokens), 1)
    digits = sum(ch.isdigit() for ch in raw_line)
    ts = _parse_timestamp(raw_line)
    pure_numeric_seq = bool(tokens) and all(t.lstrip("-").isdigit() for t in tokens)
    return {
        "line_length": length,
        "num_tokens": len(tokens),
        "avg_token_len": round(sum(len(t) for t in tokens) / n, 3),
        "digit_ratio": round(digits / max(length, 1), 3),
        "has_ip": int(bool(_IPV4_RE.search(raw_line))),
        "has_port": int(bool(_PORT_RE.search(raw_line))),
        "has_username": int(bool(_USER_RE.search(raw_line))),
        "has_time": int(bool(_TIME_RE.search(raw_line))),
        "hour_of_day": ts.hour if ts else -1,
        "day_of_week": ts.weekday() if ts else -1,
        "has_block_id": int(bool(_BLOCK_RE.search(raw_line))),
        "is_pure_numeric_seq": int(pure_numeric_seq),
    }


def extract_source_entities(raw_line: str, source: str = "") -> dict:
    """Interpretable (non-vector) entities per source, for indicators/debugging."""
    entities: dict = {
        "hdfs_block_id": "",
        "bgl_node": "",
        "syscalls": [],
        "ip": "",
        "username": "",
    }
    block = _BLOCK_RE.search(raw_line)
    if block:
        entities["hdfs_block_id"] = block.group(0)
    ip = _IPV4_STRICT_RE.search(raw_line)
    if ip:
        entities["ip"] = ip.group(0)
    user = _USER_RE.search(raw_line)
    if user:
        entities["username"] = user.group(0).split("=", 1)[-1].split()[-1]
    if source == "loghub_bgl":
        node = re.search(r"\b[RIT]\d+-M\d+-N\d+-C:J\d+-U\d+\b", raw_line)
        if node:
            entities["bgl_node"] = node.group(0)
    if source == "adfa_ld":
        candidates = [t for t in tokenize(raw_line) if t.lstrip("-").isdigit()]
        if candidates:
            entities["syscalls"] = [int(t) for t in candidates]
    return entities


def build_vectorizer() -> TfidfVectorizer:
    """Unigrams + bigrams, top 10k by training-set frequency."""
    return TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=MAX_FEATURES,
        min_df=2,
        lowercase=False,
        tokenizer=str.split,
        token_pattern=None,
    )


def vectorize_batch(raw_lines: list[str], sources: list[str], vectorizer: TfidfVectorizer | None = None):
    """Return (csr_matrix, feature_names). With vectorizer=None a new one is
    fitted on these lines (training); with one supplied, transform-only (serving)."""
    fit_here = vectorizer is None
    vec = vectorizer or build_vectorizer()
    texts = [ngram_text(line) for line in raw_lines]
    if fit_here:
        text_matrix = vec.fit_transform(texts)
    else:
        text_matrix = vec.transform(texts)
    numeric = sparse.csr_matrix(
        [[extract_features(line, src)[name] for name in NUMERIC_FEATURES]
         for line, src in zip(raw_lines, sources)],
        dtype=float,
    )
    combined = sparse.hstack([text_matrix, numeric]).tocsr()
    return combined, list(vec.get_feature_names_out()) + NUMERIC_FEATURES


def group_split(keys: list[str], ratios: tuple[float, float, float] = (0.8, 0.1, 0.1), seed: int = 1337) -> list[set[str]]:
    """Deterministic grouped split: shuffles unique keys and assigns whole groups
    to each partition so no key straddles train/val/test."""
    import random

    assert abs(sum(ratios) - 1.0) < 1e-9, ratios
    unique = sorted(set(keys))
    rng = random.Random(seed)
    rng.shuffle(unique)
    total = len(unique)
    n_train = int(total * ratios[0])
    n_val = int(total * ratios[1])
    return [
        set(unique[:n_train]),
        set(unique[n_train:n_train + n_val]),
        set(unique[n_train + n_val:]),
    ]


def fingerprint(value: str) -> int:
    """Stable small hash for entities that must stay comparable across runs."""
    return int(hashlib.sha256(value.encode()).hexdigest()[:8], 16)
