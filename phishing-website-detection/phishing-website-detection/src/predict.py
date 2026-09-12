"""
predict.py
----------
Loads the trained model and scores URLs.

Two ways to use it:

    # single URL
    python -m src.predict "http://paypal.com.verify-login.tk/account"

    # a text file with one URL per line
    python -m src.predict --file urls.txt
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import joblib
import pandas as pd

from .features import FEATURE_NAMES, explain, extract_features

ROOT = Path(__file__).resolve().parent.parent
MODEL_PATH = ROOT / "models" / "phishing_model.joblib"

_CACHE: dict | None = None


def load_model(path: Path = MODEL_PATH) -> dict:
    """Load the saved bundle once and keep it in memory."""
    global _CACHE
    if _CACHE is None:
        if not path.exists():
            raise FileNotFoundError(
                f"No trained model at {path}.\n"
                f"Run:  python -m src.train"
            )
        _CACHE = joblib.load(path)
    return _CACHE


def predict_one(url: str) -> dict:
    """Score a single URL. Returns label, probability and human-readable reasons."""
    bundle = load_model()
    features = extract_features(url)
    row = pd.DataFrame([[features[name] for name in FEATURE_NAMES]],
                       columns=FEATURE_NAMES)

    probability = float(bundle["model"].predict_proba(row)[0, 1])
    label = "PHISHING" if probability >= 0.5 else "LEGITIMATE"

    if probability >= 0.85 or probability <= 0.15:
        confidence = "high"
    elif probability >= 0.65 or probability <= 0.35:
        confidence = "medium"
    else:
        confidence = "low"

    return {
        "url": url,
        "label": label,
        "phishing_probability": round(probability, 4),
        "confidence": confidence,
        "reasons": explain(url),
        "features": features,
    }


def predict_many(urls: list[str]) -> list[dict]:
    return [predict_one(url) for url in urls]


def _print_result(result: dict) -> None:
    marker = "[!]" if result["label"] == "PHISHING" else "[ok]"
    percentage = result["phishing_probability"] * 100
    print(f"\n{marker} {result['label']}  ({percentage:.1f}% phishing, "
          f"{result['confidence']} confidence)")
    print(f"    {result['url']}")
    if result["reasons"]:
        print("    Why:")
        for reason in result["reasons"]:
            print(f"      - {reason}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Classify URLs as phishing or legitimate.")
    parser.add_argument("url", nargs="?", help="a single URL to check")
    parser.add_argument("--file", help="path to a file with one URL per line")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    arguments = parser.parse_args()

    if arguments.file:
        urls = [line.strip() for line in Path(arguments.file).read_text().splitlines()
                if line.strip() and not line.startswith("#")]
    elif arguments.url:
        urls = [arguments.url]
    else:
        parser.error("give a URL or use --file")
        return

    results = predict_many(urls)

    if arguments.json:
        import json
        slim = [{key: value for key, value in result.items() if key != "features"}
                for result in results]
        print(json.dumps(slim, indent=2))
    else:
        for result in results:
            _print_result(result)
        flagged = sum(1 for result in results if result["label"] == "PHISHING")
        print(f"\n{flagged} of {len(results)} URLs flagged as phishing.")


if __name__ == "__main__":
    try:
        main()
    except FileNotFoundError as error:
        print(error, file=sys.stderr)
        sys.exit(1)
