"""
train.py
--------
Trains, compares and saves the phishing-detection model.

Pipeline
    CSV of (url, label)
      -> extract_features() on every row      [src/features.py]
      -> train / test split (stratified 80:20)
      -> fit three candidate models
      -> pick the best by F1 on the held-out test set
      -> save the winner + a metrics report + a confusion-matrix image

Run it with:   python -m src.train
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, classification_report,
                             confusion_matrix, f1_score, precision_score,
                             recall_score, roc_auc_score)
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .dataset import save_dataset
from .features import FEATURE_NAMES, extract_features

ROOT = Path(__file__).resolve().parent.parent
DATA_PATH = ROOT / "data" / "urls.csv"
MODEL_PATH = ROOT / "models" / "phishing_model.joblib"
METRICS_PATH = ROOT / "reports" / "metrics.json"
MATRIX_PATH = ROOT / "reports" / "confusion_matrix.png"
IMPORTANCE_PATH = ROOT / "reports" / "feature_importance.png"


# --------------------------------------------------------------------------
# Step 1 -- load the URLs and turn them into a feature matrix
# --------------------------------------------------------------------------

def load_feature_matrix(csv_path: Path) -> tuple[pd.DataFrame, pd.Series, pd.Series]:
    """Read the CSV and return (X, y, urls)."""
    if not csv_path.exists():
        print(f"[i] {csv_path.name} not found -- generating it now.")
        save_dataset(csv_path)

    frame = pd.read_csv(csv_path)
    print(f"[1/6] Loaded {len(frame):,} URLs "
          f"({(frame.label == 0).sum():,} legitimate, {(frame.label == 1).sum():,} phishing)")

    feature_rows = [extract_features(url) for url in frame["url"]]
    X = pd.DataFrame(feature_rows, columns=FEATURE_NAMES)
    y = frame["label"]

    print(f"[2/6] Extracted {X.shape[1]} features per URL -> matrix {X.shape}")
    return X, y, frame["url"]


# --------------------------------------------------------------------------
# Step 2 -- define the candidate models
# --------------------------------------------------------------------------

def candidate_models() -> dict[str, Pipeline]:
    """Three models of increasing capacity, each wrapped in a scaling pipeline.

    Scaling matters for LogisticRegression and is harmless for the tree models,
    so using one Pipeline shape everywhere keeps the code uniform.
    """
    return {
        "LogisticRegression": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(max_iter=2000, C=1.0, random_state=42)),
        ]),
        "RandomForest": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", RandomForestClassifier(
                n_estimators=300, max_depth=None, min_samples_leaf=2,
                n_jobs=-1, random_state=42)),
        ]),
        "GradientBoosting": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", GradientBoostingClassifier(
                n_estimators=200, learning_rate=0.1, max_depth=3, random_state=42)),
        ]),
    }


# --------------------------------------------------------------------------
# Step 3 -- evaluate one model
# --------------------------------------------------------------------------

def evaluate(model: Pipeline, X_test: pd.DataFrame, y_test: pd.Series) -> dict:
    predictions = model.predict(X_test)
    probabilities = model.predict_proba(X_test)[:, 1]
    return {
        "accuracy": round(accuracy_score(y_test, predictions), 4),
        "precision": round(precision_score(y_test, predictions), 4),
        "recall": round(recall_score(y_test, predictions), 4),
        "f1": round(f1_score(y_test, predictions), 4),
        "roc_auc": round(roc_auc_score(y_test, probabilities), 4),
    }


# --------------------------------------------------------------------------
# Step 4 -- charts
# --------------------------------------------------------------------------

def save_confusion_matrix(y_test, predictions, model_name: str, path: Path) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    matrix = confusion_matrix(y_test, predictions)
    figure, axes = plt.subplots(figsize=(5.2, 4.4))
    axes.imshow(matrix, cmap="Blues")

    labels = ["Legitimate", "Phishing"]
    axes.set_xticks([0, 1], labels)
    axes.set_yticks([0, 1], labels)
    axes.set_xlabel("Predicted")
    axes.set_ylabel("Actual")
    axes.set_title(f"Confusion matrix -- {model_name}")

    threshold = matrix.max() / 2
    for row in range(2):
        for column in range(2):
            axes.text(column, row, f"{matrix[row, column]:,}",
                      ha="center", va="center", fontsize=14,
                      color="white" if matrix[row, column] > threshold else "black")

    figure.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(path, dpi=140)
    plt.close(figure)


def save_feature_importance(model: Pipeline, path: Path, top_n: int = 15) -> None:
    classifier = model.named_steps["clf"]
    if not hasattr(classifier, "feature_importances_"):
        return

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    importances = classifier.feature_importances_
    order = np.argsort(importances)[-top_n:]

    figure, axes = plt.subplots(figsize=(7.5, 5.5))
    axes.barh([FEATURE_NAMES[i] for i in order], importances[order], color="#2a6f97")
    axes.set_xlabel("Relative importance")
    axes.set_title(f"Top {top_n} features driving the decision")
    figure.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(path, dpi=140)
    plt.close(figure)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main() -> None:
    started = time.time()

    X, y, _urls = load_feature_matrix(DATA_PATH)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42)
    print(f"[3/6] Split into {len(X_train):,} training and {len(X_test):,} test rows")

    results: dict[str, dict] = {}
    fitted: dict[str, Pipeline] = {}

    print("[4/6] Training candidates...")
    for name, model in candidate_models().items():
        model.fit(X_train, y_train)
        scores = evaluate(model, X_test, y_test)
        cv = cross_val_score(model, X_train, y_train, cv=5, scoring="f1", n_jobs=-1)
        scores["cv_f1_mean"] = round(float(cv.mean()), 4)
        scores["cv_f1_std"] = round(float(cv.std()), 4)
        results[name] = scores
        fitted[name] = model
        print(f"      {name:<20} acc={scores['accuracy']:.4f}  "
              f"f1={scores['f1']:.4f}  auc={scores['roc_auc']:.4f}  "
              f"cv_f1={scores['cv_f1_mean']:.4f}+/-{scores['cv_f1_std']:.4f}")

    best_name = max(results, key=lambda name: results[name]["f1"])
    best_model = fitted[best_name]
    print(f"[5/6] Best model: {best_name} (F1 = {results[best_name]['f1']:.4f})")

    predictions = best_model.predict(X_test)
    print("\n" + classification_report(
        y_test, predictions, target_names=["Legitimate", "Phishing"], digits=4))

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": best_model, "feature_names": FEATURE_NAMES,
                 "model_name": best_name}, MODEL_PATH)

    save_confusion_matrix(y_test, predictions, best_name, MATRIX_PATH)
    save_feature_importance(best_model, IMPORTANCE_PATH)

    report = {
        "best_model": best_name,
        "n_samples": int(len(X)),
        "n_features": int(X.shape[1]),
        "train_size": int(len(X_train)),
        "test_size": int(len(X_test)),
        "results": results,
        "confusion_matrix": confusion_matrix(y_test, predictions).tolist(),
        "training_seconds": round(time.time() - started, 2),
    }
    METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)
    METRICS_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"[6/6] Saved:\n"
          f"      model    -> {MODEL_PATH.relative_to(ROOT)}\n"
          f"      metrics  -> {METRICS_PATH.relative_to(ROOT)}\n"
          f"      matrix   -> {MATRIX_PATH.relative_to(ROOT)}\n"
          f"      features -> {IMPORTANCE_PATH.relative_to(ROOT)}\n"
          f"Done in {report['training_seconds']}s")


if __name__ == "__main__":
    main()
