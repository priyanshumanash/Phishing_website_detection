# 04 — Model Training

*Three candidate models, how they are compared, and why Gradient Boosting wins.*

---

## 4.1 The six steps `src/train.py` performs

```
[1/6]  Load data/urls.csv                      6,000 URLs
[2/6]  Extract 28 features from every URL      -> matrix (6000, 28)
[3/6]  Stratified 80/20 split                  4,800 train / 1,200 test
[4/6]  Fit three candidate models              + 5-fold CV on the training set
[5/6]  Pick the winner by test F1
[6/6]  Save model, metrics.json, two charts
```

Run it:

```bash
python -m src.train
```

Takes about 13 seconds on an ordinary laptop.

---

## 4.2 Why compare three models instead of picking one

Most student projects grab Random Forest because a tutorial did, report 97%, and stop. That leaves two questions unanswered: *would something simpler do just as well?* and *is the extra complexity buying anything?*

Training three models costs 13 seconds and answers both. It also produces the most interesting result in the whole project — see §4.7.

The three were chosen to span a deliberate range of capacity:

| Model | Family | Capacity | Interpretability |
|---|---|---|---|
| Logistic Regression | Linear | Low — one weight per feature | Very high |
| Random Forest | Bagged trees | High — 300 independent deep trees | Medium |
| Gradient Boosting | Boosted trees | High — 200 sequential shallow trees | Medium |

---

## 4.3 Every model is a Pipeline

```python
Pipeline([
    ("scaler", StandardScaler()),
    ("clf",    LogisticRegression(max_iter=2000, C=1.0, random_state=42)),
])
```

A `Pipeline` chains preprocessing and the model into one object.

**Why this matters — it prevents data leakage.** `StandardScaler` computes a mean and standard deviation. If you scale the whole dataset *before* splitting, the test set's statistics leak into the training set, and your reported score is optimistic. Inside a Pipeline, `fit()` computes scaler statistics from the training fold only, and `predict()` applies those same statistics to the test data. During 5-fold cross-validation this happens correctly for every fold, automatically.

**Why scale at all?** The features have wildly different ranges: `url_length` runs 15–250, `uses_https` is 0 or 1, `digit_ratio` is 0–1. Logistic Regression is distance-based and would let `url_length` dominate purely because its numbers are larger. `StandardScaler` rewrites every feature as `(x - mean) / std`, so all of them are centred at 0 with unit variance.

Tree models don't need scaling — they split on thresholds, and a monotonic rescaling doesn't change which splits are possible. It's harmless, though, and using one Pipeline shape for all three keeps the code uniform.

---

## 4.4 The three candidates

### Logistic Regression — the baseline

```python
LogisticRegression(max_iter=2000, C=1.0, random_state=42)
```

Fits one weight per feature and passes the weighted sum through a sigmoid:

```
P(phishing) = 1 / (1 + e^-(w·x + b))
```

`max_iter=2000` because the default 100 does not converge on 28 scaled features. `C=1.0` is the inverse regularisation strength — smaller means stronger L2 penalty.

**Why include it.** Every project needs a baseline that answers "is the complicated thing actually necessary?" If Logistic Regression matched the ensembles, the honest conclusion would be to ship Logistic Regression: it's faster, smaller, and you can read its coefficients directly.

### Random Forest — bagging

```python
RandomForestClassifier(n_estimators=300, min_samples_leaf=2, n_jobs=-1, random_state=42)
```

Trains 300 decision trees, each on a bootstrap sample of the rows and a random subset of features at each split, then averages their votes. Individual trees overfit badly; averaging many decorrelated overfit trees cancels most of that error out.

`min_samples_leaf=2` stops the trees memorising single rows. `n_jobs=-1` uses all CPU cores — the trees are independent, so this parallelises perfectly.

### Gradient Boosting — boosting

```python
GradientBoostingClassifier(n_estimators=200, learning_rate=0.1, max_depth=3, random_state=42)
```

Trains 200 trees **sequentially**. Each new tree is fitted to the *residual errors* of everything built so far, so each one specialises in the cases its predecessors got wrong.

`max_depth=3` keeps each tree deliberately weak — boosting works by combining many weak learners, and deep trees would overfit fast. `learning_rate=0.1` shrinks each tree's contribution, trading training time for generalisation.

**Bagging vs boosting, in one line:** bagging reduces *variance* by averaging independent models; boosting reduces *bias* by stacking corrections. They fail differently, which is exactly why both are worth testing.

---

## 4.5 How the winner is chosen

Two separate evaluations run for every model.

**Test-set metrics** — the 1,200 held-out rows, scored once:

```python
accuracy, precision, recall, f1, roc_auc
```

**5-fold cross-validation** on the *training* set only:

```python
cross_val_score(model, X_train, y_train, cv=5, scoring="f1")
```

The training set is split into 5 parts; each part takes a turn as validation while the other 4 train. Reporting mean ± standard deviation tells you whether a score is stable or a fluke of one lucky split.

**Selection uses test F1**, and here is the reasoning for F1 rather than accuracy:

- **Accuracy** is misleading on imbalanced data. This dataset is balanced 50/50 so it's fine here — but writing code that only works on balanced data is a trap if you later swap in a real corpus, which will not be balanced.
- **Precision** = of everything flagged as phishing, how much really was. Low precision means false alarms, and users who are cried wolf at start ignoring warnings.
- **Recall** = of all real phishing, how much was caught. Low recall means victims.
- **F1** is their harmonic mean, which punishes a model that sacrifices one for the other.

**In production you would not use F1.** Missing a phishing site (false negative) costs a compromised account; over-flagging a safe one (false positive) costs an annoyed click-through. The costs are not equal, so you would weight recall higher — F2 rather than F1, or tune the decision threshold directly. §4.8 covers this. F1 is used here because it's the neutral choice for comparing models on their merits.

---

## 4.6 Measured results

```
      LogisticRegression   acc=0.9425  f1=0.9424  auc=0.9892  cv_f1=0.9568 +/- 0.0059
      RandomForest         acc=0.9908  f1=0.9908  auc=0.9997  cv_f1=0.9917 +/- 0.0028
      GradientBoosting     acc=0.9925  f1=0.9925  auc=0.9996  cv_f1=0.9925 +/- 0.0014
```

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | CV F1 |
|---|---|---|---|---|---|---|
| Logistic Regression | 0.9425 | 0.9447 | 0.9400 | 0.9424 | 0.9892 | 0.9568 ± 0.0059 |
| Random Forest | 0.9908 | 0.9933 | 0.9883 | 0.9908 | 0.9997 | 0.9917 ± 0.0028 |
| **Gradient Boosting** | **0.9925** | **0.9950** | **0.9900** | **0.9925** | 0.9996 | 0.9925 ± 0.0014 |

**Winner: Gradient Boosting**, F1 = 0.9925.

Two sanity checks that the numbers are trustworthy:

1. **CV scores sit close to test scores.** Gradient Boosting: CV F1 0.9925 vs test F1 0.9925 — identical to four decimal places. Random Forest: 0.9917 vs 0.9908. A test score far above CV would suggest a lucky split; these agree.
2. **CV standard deviations are small** (0.0014–0.0059). The models are stable across different data partitions, not balanced on a knife edge. Note that Logistic Regression has the largest σ (0.0059), which fits — a linear model is more sensitive to exactly which hard cases land in which fold.

---

## 4.7 The interesting result: the 5-point gap

Logistic Regression scores 0.9425. The tree ensembles score 0.9908 and 0.9925. That 5-point gap is the most informative number in the project.

**It means the decision boundary is non-linear.** Logistic Regression can only learn "more of feature X → more likely phishing", with a fixed weight per feature. The tree models can learn *conditional* rules:

> "High hostname entropy usually means phishing — **unless** the TLD is `.net` and the path starts with `/assets/`, in which case it's a CDN."

> "A raw IP host usually means phishing — **unless** the IP is in a private range (`192.168.*`, `10.*`) and there's a port, in which case it's an internal dashboard."

Those are exactly the hard cases from [doc 02](02-dataset.md). A linear model cannot express "unless"; a tree expresses it with two nested splits.

This is also why the hard cases matter so much. At `hard_fraction=0.0`, all three models score exactly 1.0000 and the comparison reveals nothing at all:

| `hard_fraction` | LogReg | RF | GB | What you learn |
|---|---|---|---|---|
| 0.00 | 0.9992 | 1.0000 | 1.0000 | Nothing — two models are literally perfect |
| 0.30 | 0.9424 | 0.9908 | 0.9925 | The boundary is non-linear |
| 0.50 | 0.9313 | 0.9892 | 0.9891 | The ensembles absorb ambiguity; the linear model can't |

**Should Gradient Boosting be declared the winner over Random Forest?** Strictly, no. The test-set gap is 0.9925 vs 0.9908 — two URLs out of 1,200. Their cross-validation scores are 0.9925 ± 0.0014 and 0.9917 ± 0.0028: overlapping intervals, a difference far inside one standard deviation. The two are statistically indistinguishable, and the script picks Gradient Boosting only because the tie-break rule is test F1. Saying "Gradient Boosting is better" would be overclaiming — the defensible claim is that **both tree ensembles clearly beat the linear baseline**, and which of the two you ship is a matter of taste.

Verify it yourself — rerun with different dataset seeds:

| Seed | LogReg F1 | RF F1 | GB F1 | Winner |
|---|---|---|---|---|
| 42 *(default)* | 0.9424 | 0.9908 | 0.9925 | Gradient Boosting |
| 7 | 0.9508 | 0.9917 | 0.9942 | Gradient Boosting |
| 99 | 0.9620 | 0.9942 | 0.9925 | **Random Forest** |

The two ensembles swap places depending on the seed, while Logistic Regression trails by 3–5 points every single time. That is the clearest possible evidence: the linear/non-linear gap is real, the RF-vs-GB gap is noise.

---

## 4.8 The decision threshold

The default is 0.5:

```python
label = "PHISHING" if probability >= 0.5 else "LEGITIMATE"
```

There is nothing sacred about 0.5. Lowering it catches more phishing (higher recall) at the cost of more false alarms (lower precision). For a security tool, that trade is usually worth making — an unnecessary warning costs a second; a missed phishing site costs an account.

To change it, edit `predict_one()` in `src/predict.py`. Choosing the value properly means plotting precision and recall against the threshold and picking the point that matches your tolerance — a good extension, listed in [doc 10](10-future-work.md).

The output also reports a coarse confidence band, which is more useful to a human than a bare probability:

| Probability | Confidence |
|---|---|
| ≥ 0.85 or ≤ 0.15 | high |
| ≥ 0.65 or ≤ 0.35 | medium |
| otherwise | low |

---

## 4.9 What gets saved

```python
joblib.dump({
    "model":         best_model,      # the entire fitted Pipeline
    "feature_names": FEATURE_NAMES,   # column order, for validation
    "model_name":    best_name,
}, "models/phishing_model.joblib")
```

Saving the **whole Pipeline**, not just the classifier, means the scaler travels with the model. Loading it and calling `predict()` applies exactly the same preprocessing that was used at training time. Saving a bare classifier and forgetting to scale at inference is a classic and silent source of garbage predictions.

`feature_names` is stored alongside so a future version can detect a mismatch rather than silently scoring a misaligned vector.

Also written:

| File | Contents |
|---|---|
| `reports/metrics.json` | Every score for every model, the confusion matrix, timings |
| `reports/confusion_matrix.png` | Chart for the winning model |
| `reports/feature_importance.png` | Top 15 features by importance |

---

## 4.10 Reproducibility

`random_state=42` appears in four places: the dataset generator, the train/test split, and each model. Rerunning the pipeline from a clean checkout gives byte-identical results. Every number in these docs was produced by:

```bash
python -m src.dataset && python -m src.train
```

---

**Previous:** [03 — Feature engineering](03-feature-engineering.md) | **Next:** [05 — Architecture](05-architecture.md)
