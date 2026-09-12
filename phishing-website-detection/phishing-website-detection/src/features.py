"""
features.py
-----------
Turns a raw URL string into a fixed-length numeric feature vector.

This is the heart of the project. A machine-learning model cannot read a URL --
it can only read numbers. So for every URL we compute ~25 measurable properties
("features") that tend to differ between legitimate sites and phishing sites.

Every feature below is *lexical*: it is computed from the URL text alone.
We never fetch the page. That makes detection fast (microseconds), safe (we
never visit a malicious site) and usable on URLs that are already offline.

Read docs/03-feature-engineering.md for the reasoning behind each feature.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from urllib.parse import urlparse

# --------------------------------------------------------------------------
# Reference data used by the feature functions
# --------------------------------------------------------------------------

# TLDs that are cheap / free to register and are massively over-represented in
# phishing corpora relative to their share of the legitimate web.
SUSPICIOUS_TLDS = {
    "zip", "review", "country", "kim", "cricket", "science", "work", "party",
    "gq", "link", "tk", "ml", "cf", "ga", "top", "xyz", "club", "click",
    "loan", "download", "racing", "win", "bid", "stream", "date", "faith",
    "accountant", "men", "rest", "buzz", "icu", "cyou", "sbs", "lol",
}

# URL shorteners hide the real destination, so their presence is a weak but
# real signal. (Plenty of legitimate links are shortened too -- hence "weak".)
SHORTENERS = {
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "cutt.ly", "rb.gy", "shorturl.at", "rebrand.ly",
    "tiny.cc", "soo.gd", "s2r.co", "clicky.me", "bl.ink",
}

# Words that appear far more often in phishing URLs than in normal ones,
# because the attacker is trying to manufacture urgency or legitimacy.
SENSITIVE_WORDS = [
    "login", "signin", "sign-in", "verify", "verification", "account",
    "update", "secure", "security", "banking", "bank", "confirm", "password",
    "credential", "billing", "invoice", "payment", "wallet", "recover",
    "unlock", "suspend", "alert", "webscr", "authenticate", "session",
    "support", "service", "customer", "ebayisapi", "paypal", "appleid",
]

# Well-known brands. Seeing a brand name somewhere *other than* the registered
# domain (e.g. "paypal.secure-login.xyz") is one of the strongest phishing
# indicators there is.
BRANDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "facebook", "netflix",
    "instagram", "whatsapp", "linkedin", "dropbox", "adobe", "chase", "hsbc",
    "wellsfargo", "citibank", "sbi", "icici", "hdfc", "axis", "bankofamerica",
    "outlook", "office365", "steam", "binance", "coinbase", "dhl", "fedex",
    "usps", "irs", "gov", "yahoo", "twitter", "spotify", "roblox",
]

IPV4_RE = re.compile(
    r"^(?:\d{1,3}\.){3}\d{1,3}$"
)
HEX_IP_RE = re.compile(r"^0x[0-9a-fA-F]+$")

# The order of this list defines the column order of every feature vector.
# Keep it stable -- a saved model depends on it.
FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "num_dots",
    "num_hyphens",
    "num_at",
    "num_question_marks",
    "num_equals",
    "num_underscores",
    "num_percent",
    "num_slashes",
    "num_digits",
    "digit_ratio",
    "num_subdomains",
    "has_ip_host",
    "uses_https",
    "has_port",
    "has_punycode",
    "is_shortener",
    "suspicious_tld",
    "tld_length",
    "num_sensitive_words",
    "brand_outside_domain",
    "longest_token_length",
    "hostname_entropy",
    "double_slash_in_path",
    "num_params",
]


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

def _shannon_entropy(text: str) -> float:
    """Measure how 'random' a string looks, in bits per character.

    'google' scores low (predictable letters). 'x7f3qz9a' scores high.
    Algorithmically generated phishing hostnames tend to score high.
    """
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _normalise(url: str) -> str:
    """Make sure urlparse() sees a scheme, otherwise it parses the host as a path."""
    url = url.strip()
    if "://" not in url:
        url = "http://" + url
    return url


def _registered_domain(hostname: str) -> tuple[str, str]:
    """Return (registered_domain, tld) using a simple last-two-labels rule.

    A full implementation would use the Public Suffix List (the `tldextract`
    package). We deliberately avoid that dependency so the project runs with
    nothing but scikit-learn installed. The simple rule is correct for the vast
    majority of URLs; docs/03-feature-engineering.md explains the trade-off.
    """
    labels = hostname.split(".")
    if len(labels) < 2:
        return hostname, ""
    return ".".join(labels[-2:]), labels[-1]


# --------------------------------------------------------------------------
# The main extractor
# --------------------------------------------------------------------------

def extract_features(url: str) -> dict[str, float]:
    """Compute every feature for one URL and return them as a name -> value dict."""
    raw = url.strip()
    parsed = urlparse(_normalise(raw))

    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""

    labels = [label for label in hostname.split(".") if label]
    registered_domain, tld = _registered_domain(hostname)

    # Everything in the hostname that is NOT the registered domain.
    subdomain_part = hostname[: -len(registered_domain)] if registered_domain and hostname.endswith(registered_domain) else ""

    host_is_ip = bool(IPV4_RE.match(hostname)) or bool(HEX_IP_RE.match(hostname))

    digits = sum(character.isdigit() for character in raw)

    # Split the URL into word-ish tokens to find suspiciously long chunks.
    tokens = [token for token in re.split(r"[^a-zA-Z0-9]+", raw) if token]
    longest_token = max((len(token) for token in tokens), default=0)

    lowered = raw.lower()
    sensitive_hits = sum(1 for word in SENSITIVE_WORDS if word in lowered)

    # Brand name present anywhere EXCEPT inside the registered domain.
    # "paypal.com/login"          -> 0 (brand is the real domain, fine)
    # "paypal.secure-login.xyz"   -> 1 (brand is in the subdomain: red flag)
    # "my-site.com/paypal/verify" -> 1 (brand in the path: red flag)
    brand_outside_domain = 0
    haystack = f"{subdomain_part} {path} {query}".lower()
    for brand in BRANDS:
        if brand in haystack and brand not in registered_domain:
            brand_outside_domain = 1
            break

    return {
        "url_length": len(raw),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "query_length": len(query),
        "num_dots": raw.count("."),
        "num_hyphens": raw.count("-"),
        "num_at": raw.count("@"),
        "num_question_marks": raw.count("?"),
        "num_equals": raw.count("="),
        "num_underscores": raw.count("_"),
        "num_percent": raw.count("%"),
        "num_slashes": raw.count("/"),
        "num_digits": digits,
        "digit_ratio": digits / len(raw) if raw else 0.0,
        "num_subdomains": max(len(labels) - 2, 0) if not host_is_ip else 0,
        "has_ip_host": int(host_is_ip),
        "uses_https": int(parsed.scheme == "https"),
        "has_port": int(parsed.port is not None),
        "has_punycode": int("xn--" in hostname),
        "is_shortener": int(registered_domain in SHORTENERS),
        "suspicious_tld": int(tld in SUSPICIOUS_TLDS),
        "tld_length": len(tld),
        "num_sensitive_words": sensitive_hits,
        "brand_outside_domain": brand_outside_domain,
        "longest_token_length": longest_token,
        "hostname_entropy": round(_shannon_entropy(hostname), 4),
        "double_slash_in_path": int("//" in path),
        "num_params": len(query.split("&")) if query else 0,
    }


def extract_feature_vector(url: str) -> list[float]:
    """Same as extract_features() but returns a plain list in FEATURE_NAMES order."""
    features = extract_features(url)
    return [features[name] for name in FEATURE_NAMES]


def explain(url: str, top_n: int = 6) -> list[str]:
    """Human-readable reasons a URL looks suspicious.

    This is not the model's explanation -- it is a rule-based summary shown
    alongside the prediction so a user can see *why* without reading a
    feature-importance chart. Useful in the demo and in a viva.
    """
    features = extract_features(url)
    reasons: list[tuple[int, str]] = []

    if features["has_ip_host"]:
        reasons.append((10, "Uses a raw IP address instead of a domain name"))
    if features["brand_outside_domain"]:
        reasons.append((9, "A well-known brand name appears outside the real domain"))
    if features["num_at"]:
        reasons.append((8, "Contains '@', which hides the true destination host"))
    if features["has_punycode"]:
        reasons.append((8, "Uses punycode (xn--), often a look-alike domain attack"))
    if features["suspicious_tld"]:
        reasons.append((7, "Registered on a TLD heavily abused for phishing"))
    if features["num_subdomains"] >= 3:
        reasons.append((6, f"Unusually deep subdomain chain ({int(features['num_subdomains'])} levels)"))
    if features["url_length"] > 75:
        reasons.append((5, f"Very long URL ({int(features['url_length'])} characters)"))
    if features["num_sensitive_words"] >= 2:
        reasons.append((5, "Packed with urgency words like 'verify', 'secure', 'account'"))
    if not features["uses_https"]:
        reasons.append((4, "Served over plain HTTP, not HTTPS"))
    if features["is_shortener"]:
        reasons.append((4, "Link shortener conceals the final destination"))
    if features["has_port"]:
        reasons.append((3, "Specifies a non-standard port"))
    if features["digit_ratio"] > 0.2:
        reasons.append((3, "High proportion of digits in the URL"))
    if features["hostname_entropy"] > 3.8:
        reasons.append((3, "Hostname looks machine-generated (high randomness)"))

    reasons.sort(key=lambda item: item[0], reverse=True)
    return [text for _, text in reasons[:top_n]]


if __name__ == "__main__":
    # Quick manual sanity check:  python -m src.features
    samples = [
        "https://www.google.com/search?q=python",
        "http://192.168.4.21/paypal/login/verify.php",
        "http://paypal.com.secure-login-update.xyz/account/confirm",
    ]
    for sample in samples:
        print(f"\n{sample}")
        for reason in explain(sample):
            print(f"   - {reason}")
