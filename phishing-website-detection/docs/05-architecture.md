# 05 — Architecture

*How the pieces fit together.*

---

## 5.1 The whole system on one page

```
                         TRAINING TIME  (run once)
 ┌──────────────────────────────────────────────────────────────────────┐
 │                                                                      │
 │   src/dataset.py                                                     │
 │   ┌────────────────────────────────┐                                 │
 │   │ 120 real domains  ──┐          │                                 │
 │   │ 8 phishing patterns ├─ 50/50 ──┼──►  data/urls.csv               │
 │   │ 11 hard generators ─┘          │     6,000 rows (url, label)     │
 │   └────────────────────────────────┘                 │               │
 │                                                      ▼               │
 │   src/features.py          ┌──────────────────────────────────┐      │
 │   extract_features()  ◄────┤ for every URL in the CSV         │      │
 │                            └──────────────────────────────────┘      │
 │                                         │                            │
 │                                         ▼                            │
 │                              X = matrix (6000 × 28)                  │
 │                              y = labels (6000,)                      │
 │                                         │                            │
 │   src/train.py                          ▼                            │
 │   ┌───────────────────────────────────────────────────────────┐      │
 │   │  stratified 80/20 split                                   │      │
 │   │       │                          │                        │      │
 │   │   X_train (4800)             X_test (1200)                │      │
 │   │       │                          │                        │      │
 │   │       ▼                          │                        │      │
 │   │  fit 3 pipelines                 │                        │      │
 │   │  + 5-fold CV                     │                        │      │
 │   │       │                          ▼                        │      │
 │   │       └──────────────►  evaluate, pick best F1            │      │
 │   └───────────────────────────────────────────────────────────┘      │
 │                                         │                            │
 │                ┌────────────────────────┼────────────────────┐       │
 │                ▼                        ▼                    ▼       │
 │   models/phishing_model.joblib   reports/metrics.json   reports/*.png│
 └──────────────────────────────────────────────────────────────────────┘
                                          │
 ─────────────────────────────────────────┼────────────────────────────────
                                          │
                        INFERENCE TIME  (every request)
 ┌────────────────────────────────────────┼─────────────────────────────┐
 │                                        ▼                             │
 │   src/predict.py    load_model()  ── cached in memory after first use│
 │                          │                                           │
 │   URL string ──► extract_features() ──► DataFrame(1 × 28)            │
 │                                                │                     │
 │                                                ▼                     │
 │                                      pipeline.predict_proba()        │
 │                                                │                     │
 │                                                ▼                     │
 │                       { label, probability, confidence, reasons }    │
 │                                                │                     │
 │            ┌───────────────────────────────────┼──────────────┐      │
 │            ▼                                   ▼              ▼      │
 │      CLI (predict.py)              Flask page (app.py)   JSON API    │
 └──────────────────────────────────────────────────────────────────────┘
```

---

## 5.2 Layers

The code is deliberately arranged so each layer depends only on the one below it.

| Layer | File | Responsibility | Depends on |
|---|---|---|---|
| **Interface** | `app.py` | HTTP routes, HTML rendering | `predict.py` |
| **Interface** | `predict.py` (CLI) | Argument parsing, output formatting | `predict.py` (core) |
| **Inference** | `predict.py` (core) | Load model, score a URL, package the result | `features.py`, the saved model |
| **Training** | `train.py` | Split, fit, compare, persist | `features.py`, `dataset.py` |
| **Features** | `features.py` | URL → 28 numbers | nothing (stdlib only) |
| **Data** | `dataset.py` | Generate labelled URLs | nothing (stdlib only) |

Two properties fall out of this that are worth pointing at in a review:

**`features.py` depends on nothing.** No scikit-learn, no pandas — just the standard library. So it can be imported anywhere: a browser extension's Python backend, a log-analysis script, a Jupyter notebook. It's also why the unit tests run without a trained model present.

**The interfaces are interchangeable.** CLI, web page and JSON API all call the same `predict_one()`. Adding a fourth interface — a Slack bot, a batch job — means writing a wrapper, not duplicating logic.

---

## 5.3 The inference path, step by step

```python
predict_one("http://paypal.com.verify.tk/login.php")
```

**1. Load the model (first call only).**

```python
_CACHE = None
def load_model(path=MODEL_PATH):
    global _CACHE
    if _CACHE is None:
        _CACHE = joblib.load(path)
    return _CACHE
```

Deserialising a 200-tree ensemble takes ~50 ms. Doing that per request would make the API twenty times slower than the actual prediction. The module-level cache means it happens once per process. For a Flask app serving many requests, this is the difference between 50 ms and 0.2 ms per call.

**2. Extract features.**

```python
features = extract_features(url)                      # dict of 28 values
row = pd.DataFrame([[features[n] for n in FEATURE_NAMES]], columns=FEATURE_NAMES)
```

Building a one-row DataFrame with named columns (rather than a bare list) means scikit-learn can verify the column names match what the Pipeline was fitted on, and warns loudly if they don't.

**3. Predict.**

```python
probability = float(bundle["model"].predict_proba(row)[0, 1])
```

The Pipeline applies `StandardScaler` with the *training* statistics, then the classifier. `predict_proba` returns `[[P(legit), P(phish)]]`; column 1 is what we want.

**4. Package the answer.**

```python
{
  "url": ...,
  "label": "PHISHING" | "LEGITIMATE",
  "phishing_probability": 0.9938,
  "confidence": "high" | "medium" | "low",
  "reasons": [...],        # from the rule-based explain()
  "features": {...},       # all 28, for the UI's detail panel
}
```

Returning the raw features alongside the verdict is what lets the web UI show its "Show all 28 extracted features" panel — useful for a demo, because you can point at exactly which number caused the flag.

---

## 5.4 The web interface

`src/app.py` is a single Flask module with three routes.

| Route | Method | Purpose |
|---|---|---|
| `/` | GET, POST | The HTML page. Accepts `?url=` on GET so results are shareable links |
| `/api/check` | POST | JSON in, JSON out — for integration |
| `/health` | GET | Liveness check |

```bash
curl -X POST http://127.0.0.1:5000/api/check \
     -H 'Content-Type: application/json' \
     -d '{"url":"http://192.168.4.21/paypal/login/verify.php"}'
```

```json
{
  "label": "PHISHING",
  "phishing_probability": 0.9969,
  "confidence": "high",
  "reasons": ["Uses a raw IP address instead of a domain name", "..."]
}
```

**Design decisions:**

- **The template is inlined** as a Python string via `render_template_string`, rather than a `templates/` directory. One fewer file to lose, and the whole interface is readable in one place. For anything larger than a single page this would be the wrong call.
- **No JavaScript.** The form posts, the server renders. Nothing to break, nothing to bundle, works with JS disabled.
- **No database.** Nothing is stored. A URL you check is not logged anywhere — which is the right default for a tool people paste potentially sensitive links into.
- **The page is dark-themed and responsive** because the demo is usually given on a projector.

---

## 5.5 Failure handling

| Failure | Where it's caught | What the user sees |
|---|---|---|
| No trained model | `load_model()` raises `FileNotFoundError` | CLI: "Run: python -m src.train". Web: an error card. API: HTTP 503 with a message |
| Missing `data/urls.csv` | `load_feature_matrix()` | Generates it automatically and prints a note |
| Malformed URL | `_normalise()` prepends a scheme | Scored normally — no crash |
| Empty POST body | `api_check()` | HTTP 400 with an example payload |

The design rule: **never crash on user input.** A URL is untrusted text; `urlparse` is lenient, and every feature function is written to handle an empty hostname or path.

---

## 5.6 Performance

| Operation | Time |
|---|---|
| Feature extraction | 0.04 ms |
| Model inference | ~0.15 ms |
| **Total per URL** | **< 0.2 ms** |
| Model load (once per process) | ~50 ms |
| Full training run | ~13 s |
| Dataset generation | ~2 s |

At under 0.2 ms per URL, a single process handles roughly 5,000 URLs/second single-threaded. That is comfortably fast enough to sit inline in an email gateway, which was the motivating scenario in [doc 01](01-problem-statement.md).

**Memory:** the saved model is ~270 KB; the loaded process sits around 120 MB, dominated by importing scikit-learn and pandas rather than by the model itself.

---

## 5.7 What a production version would add

This is a coursework system. Deploying it for real would need:

| Concern | What's missing |
|---|---|
| **Serving** | Gunicorn/uvicorn behind nginx; Flask's dev server is single-threaded and explicitly not for production |
| **Rate limiting** | The API is currently open |
| **Model versioning** | The model file has no version tag; a rollback would be manual |
| **Monitoring** | No metrics on prediction distribution, which is how you detect concept drift |
| **Retraining** | Phishing patterns shift monthly; this needs a scheduled retrain on fresh data |
| **Caching** | Popular URLs get re-scored every time; an LRU cache would cut most of that |

Expanded in [doc 10](10-future-work.md).

---

**Previous:** [04 — Model training](04-model-training.md) | **Next:** [06 — Setup & run](06-setup-and-run.md)
