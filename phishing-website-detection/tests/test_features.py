"""
Unit tests for the feature extractor and the end-to-end prediction path.

Run with:   python -m pytest -q
       or:  python tests/test_features.py     (no pytest needed)
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.dataset import build_dataset, make_legitimate_url, make_phishing_url
from src.features import FEATURE_NAMES, explain, extract_features, extract_feature_vector


# -- shape ------------------------------------------------------------------

def test_vector_length_matches_feature_names():
    vector = extract_feature_vector("https://example.com")
    assert len(vector) == len(FEATURE_NAMES)


def test_all_features_are_numeric():
    features = extract_features("https://example.com/a?b=1")
    assert all(isinstance(value, (int, float)) for value in features.values())


def test_missing_scheme_is_handled():
    features = extract_features("example.com/login")
    assert features["hostname_length"] == len("example.com")


# -- individual signals -----------------------------------------------------

def test_detects_ip_host():
    assert extract_features("http://192.168.1.1/login")["has_ip_host"] == 1
    assert extract_features("http://example.com/login")["has_ip_host"] == 0


def test_detects_https():
    assert extract_features("https://example.com")["uses_https"] == 1
    assert extract_features("http://example.com")["uses_https"] == 0


def test_counts_subdomains():
    assert extract_features("http://a.b.c.example.com")["num_subdomains"] == 3
    assert extract_features("http://example.com")["num_subdomains"] == 0


def test_brand_outside_domain():
    # brand IS the real domain -> not suspicious
    assert extract_features("https://paypal.com/signin")["brand_outside_domain"] == 0
    # brand pushed into the subdomain -> suspicious
    assert extract_features("http://paypal.com.evil.tk/signin")["brand_outside_domain"] == 1
    # brand in the path of an unrelated domain -> suspicious
    assert extract_features("http://random.tk/paypal/verify")["brand_outside_domain"] == 1


def test_suspicious_tld():
    assert extract_features("http://something.tk/")["suspicious_tld"] == 1
    assert extract_features("http://something.com/")["suspicious_tld"] == 0


def test_punycode_and_at_symbol():
    assert extract_features("https://xn--pypal-4ve.com/")["has_punycode"] == 1
    assert extract_features("http://paypal.com@evil.tk/")["num_at"] == 1


def test_shortener_detection():
    assert extract_features("http://bit.ly/3xYz1")["is_shortener"] == 1
    assert extract_features("http://github.com/x")["is_shortener"] == 0


def test_port_detection():
    assert extract_features("http://1.2.3.4:8080/x")["has_port"] == 1
    assert extract_features("http://example.com/x")["has_port"] == 0


def test_entropy_ordering():
    predictable = extract_features("http://google.com")["hostname_entropy"]
    random_looking = extract_features("http://x7q3z9wk2mvb1.tk")["hostname_entropy"]
    assert random_looking > predictable


# -- explanations -----------------------------------------------------------

def test_explain_flags_obvious_phish():
    reasons = explain("http://192.168.4.21/paypal/login/verify.php")
    assert any("IP address" in reason for reason in reasons)


def test_explain_is_quiet_on_clean_url():
    assert len(explain("https://www.wikipedia.org/")) <= 1


# -- dataset ----------------------------------------------------------------

def test_dataset_is_balanced_and_labelled():
    rows = build_dataset(n_legitimate=200, n_phishing=200, seed=1)
    labels = [label for _, label in rows]
    assert labels.count(0) == 200
    assert labels.count(1) == 200


def test_generators_produce_parseable_urls():
    for _ in range(50):
        for url in (make_legitimate_url(), make_phishing_url()):
            features = extract_features(url)
            assert features["url_length"] > 0


# -- end to end (only if a model has been trained) --------------------------

def test_model_round_trip_if_trained():
    model_path = Path(__file__).resolve().parent.parent / "models" / "phishing_model.joblib"
    if not model_path.exists():
        print("  (skipped: run `python -m src.train` first)")
        return

    from src.predict import predict_one

    safe = predict_one("https://www.google.com/search?q=python")
    phish = predict_one("http://paypal.com.secure-verify-login.tk/account/confirm.php")

    assert safe["label"] == "LEGITIMATE", safe
    assert phish["label"] == "PHISHING", phish
    assert phish["phishing_probability"] > safe["phishing_probability"]


# -- plain-python runner ----------------------------------------------------

if __name__ == "__main__":
    tests = [value for name, value in sorted(globals().items())
             if name.startswith("test_") and callable(value)]
    failures = 0
    for test in tests:
        try:
            test()
            print(f"PASS  {test.__name__}")
        except AssertionError as error:
            failures += 1
            print(f"FAIL  {test.__name__}: {error}")
    print(f"\n{len(tests) - failures}/{len(tests)} tests passed")
    sys.exit(1 if failures else 0)
