# 07 — Code Walkthrough

*File by file, function by function. Read this with the source open beside you.*

Roughly 1,100 lines across five modules. Nothing is clever for the sake of it.

---

## `src/features.py` — URL → 28 numbers

The most important file. If you only read one, read this one.

### Module-level reference data

```python
SUSPICIOUS_TLDS = {"tk", "ml", "cf", "ga", "gq", "xyz", "top", ...}   # 30 entries
SHORTENERS      = {"bit.ly", "tinyurl.com", "t.co", ...}              # 18
SENSITIVE_WORDS = ["login", "verify", "secure", "account", ...]       # 31
BRANDS          = ["paypal", "apple", "microsoft", "sbi", ...]        # 35
FEATURE_NAMES   = [...]                                                # 28, ORDER MATTERS
```

`SUSPICIOUS_TLDS` and `SHORTENERS` are **sets** — membership testing is O(1). `SENSITIVE_WORDS` and `BRANDS` are **lists** because they're iterated in order, not looked up.

`FEATURE_NAMES` defines the column order of every feature vector. A saved model was fitted against this exact order, so reordering it silently corrupts every prediction. Guarded by `test_vector_length_matches_feature_names`.

### `_shannon_entropy(text) -> float`

```python
counts = Counter(text)
total = len(text)
return -sum((c / total) * math.log2(c / total) for c in counts.values())
```

Bits per character. Returns 0.0 for the empty string rather than dividing by zero.

### `_normalise(url) -> str`

```python
if "://" not in url:
    url = "http://" + url
```

Three lines that prevent a whole class of silent bugs. `urlparse("example.com/login")` returns an empty hostname and puts everything in `.path` — half the feature set would quietly read zero.

### `_registered_domain(hostname) -> (domain, tld)`

Last two labels. `www.google.com` → `("google.com", "com")`.

Wrong for multi-part suffixes: `www.bbc.co.uk` → `("co.uk", "uk")`. The trade-off — zero dependencies versus perfect parsing — is argued in [doc 03 §3.4](03-feature-engineering.md#34-design-decisions-worth-defending). The error applies identically to both classes, so it doesn't bias the classifier.

### `extract_features(url) -> dict`

The main function. About 90 lines, entirely straight-line: parse, then compute.

Three parts deserve attention.

**Subdomain isolation:**

```python
subdomain_part = hostname[:-len(registered_domain)] if hostname.endswith(registered_domain) else ""
```

String slicing rather than re-splitting. For `paypal.com.evil.tk` with registered domain `evil.tk`, this yields `"paypal.com."`.

**Brand placement:**

```python
haystack = f"{subdomain_part} {path} {query}".lower()
for brand in BRANDS:
    if brand in haystack and brand not in registered_domain:
        brand_outside_domain = 1
        break
```

The `haystack` is everything *except* the registered domain. The second condition prevents `https://paypal.com/signin` from flagging itself. `break` on first match — it's a boolean, not a count.

**Tokenisation:**

```python
tokens = [t for t in re.split(r"[^a-zA-Z0-9]+", raw) if t]
longest_token = max((len(t) for t in tokens), default=0)
```

`default=0` handles a URL with no alphanumerics at all. `max()` on an empty sequence raises otherwise.

Returns a **dict**, not a list, so callers can read features by name. `extract_feature_vector()` wraps it to produce the ordered list the model needs.

### `explain(url, top_n=6) -> list[str]`

A hand-written rule layer, separate from the model:

```python
reasons = []
if features["has_ip_host"]:
    reasons.append((10, "Uses a raw IP address instead of a domain name"))
...
reasons.sort(key=lambda item: item[0], reverse=True)
return [text for _, text in reasons[:top_n]]
```

Each rule carries a hand-assigned severity (3–10); the list is sorted and truncated so the most serious signals surface first.

**This is not the model's reasoning** and the docstring says so. A 200-tree ensemble's decision path is not expressible in five bullets. The rules track the model's learned importances closely enough to be useful, and honesty about the distinction matters more than pretending otherwise. The principled version is SHAP — see [doc 10](10-future-work.md).

---

## `src/dataset.py` — building labelled data

### Layout

```
LEGIT_DOMAINS, LEGIT_SUBDOMAINS, LEGIT_PATHS      building blocks
TARGET_BRANDS, CHEAP_TLDS, PHISH_WORDS, ...       building blocks
_random_string, _random_ip, _typosquat, _fill     helpers
_phish_*()          ×8                            the eight attack patterns
_legit_*()          ×7                            hard negatives
_phish_clean_*()    ×4                            hard positives
make_legitimate_url / make_phishing_url           dispatchers
build_dataset / save_dataset                      public API
```

Every pattern is its own named function. That's deliberate: `_phish_at_symbol()` documents itself, and a reviewer can read exactly what each pattern produces without untangling one giant generator.

### `_typosquat(brand) -> str`

Four styles, chosen at random:

```python
style 0: character substitution   paypal -> paypa1, payp4l
style 1: doubled letter           paypal -> payppal
style 2: dropped letter           paypal -> papal
style 3: suffix                   paypal -> paypal-support
```

Style 0 uses `LOOKALIKE_SWAPS = {"o": "0", "i": "1", "l": "1", "e": "3", ...}` and only substitutes at positions where a swap exists — no-op otherwise.

### `_fill(template) -> str`

Expands `{r8}`-style placeholders into random strings of that length:

```python
"d{r8}.cloudfront.net"  ->  "d8kf2m9x.cloudfront.net"
```

A tiny templating language, so cloud hostnames can be declared as data rather than code.

### `build_dataset(...) -> list[(url, label)]`

```python
random.seed(seed)
rows: set[tuple[str, int]] = set()

legit_count = 0
while legit_count < n_legitimate and guard < n_legitimate * 200:
    before = len(rows)
    rows.add((make_legitimate_url(hard_fraction), 0))
    legit_count += len(rows) - before      # only counts NEW rows
```

Three things happen here:

1. **`set` deduplicates.** Duplicate URLs straddling a train/test split inflate accuracy.
2. **`legit_count` counts only newly-added rows**, so a collision doesn't consume a slot. Without `before`/`after`, the loop would produce fewer rows than asked for.
3. **`guard`** caps iterations in case the generator's space is smaller than the requested count — the loop exits rather than hanging.

`HARD_FRACTION = 0.30` is a module constant with a comment explaining what 0.0 does to the results. That number is the single most consequential line in the file; see [doc 02 §2.3](02-dataset.md#23-the-part-that-matters-most-hard-cases).

---

## `src/train.py` — fit, compare, save

Six numbered steps, printed as it goes, so a long run shows progress.

### `load_feature_matrix(csv_path)`

```python
if not csv_path.exists():
    save_dataset(csv_path)
frame = pd.read_csv(csv_path)
X = pd.DataFrame([extract_features(u) for u in frame["url"]], columns=FEATURE_NAMES)
```

The existence check is what makes "swap in a real dataset" a zero-code change: if `data/urls.csv` is already there, the generator never runs.

Passing `columns=FEATURE_NAMES` explicitly rather than letting pandas infer from dict keys guarantees column order even if `extract_features` returns keys in a different sequence.

### `candidate_models() -> dict[str, Pipeline]`

Returns a fresh dict each call, so the caller always gets unfitted models. Returning a module-level dict would mean the second caller receives already-fitted estimators — a subtle and nasty bug.

### `evaluate(model, X_test, y_test) -> dict`

Five metrics, each rounded to 4 places. `roc_auc_score` needs probabilities, not labels:

```python
probabilities = model.predict_proba(X_test)[:, 1]
```

Column 1 is P(phishing). Passing hard labels here is a common mistake that produces a meaningless AUC.

### `save_confusion_matrix(...)` and `save_feature_importance(...)`

```python
import matplotlib
matplotlib.use("Agg")
```

`Agg` is the non-interactive backend. Without it, matplotlib tries to open a window and crashes on a headless server or in CI. It's set *inside* the function so importing `train.py` doesn't have the side effect of configuring matplotlib globally.

`save_feature_importance` returns early for models without `feature_importances_` — Logistic Regression has `coef_` instead. Guarding rather than assuming means the script doesn't break if the linear model wins.

### `main()`

```python
best_name = max(results, key=lambda name: results[name]["f1"])
```

One line for model selection. Change `"f1"` to `"recall"` to prefer catching more phishing at the cost of more false alarms — see [doc 04 §4.5](04-model-training.md#45-how-the-winner-is-chosen).

```python
joblib.dump({"model": best_model, "feature_names": FEATURE_NAMES, "model_name": best_name}, MODEL_PATH)
```

Saves the **whole Pipeline**, scaler included. Saving a bare classifier and forgetting to scale at inference produces silently wrong predictions — no error, just garbage.

---

## `src/predict.py` — inference

### `load_model(path)` — the caching pattern

```python
_CACHE: dict | None = None

def load_model(path=MODEL_PATH):
    global _CACHE
    if _CACHE is None:
        if not path.exists():
            raise FileNotFoundError(f"No trained model at {path}.\nRun:  python -m src.train")
        _CACHE = joblib.load(path)
    return _CACHE
```

Deserialising the model takes ~50 ms; predicting takes ~0.15 ms. Without the cache the API would be 300× slower than necessary. `global` is the right tool here — a module-level singleton is exactly what's wanted.

The error message tells you the fix rather than just stating the problem.

### `predict_one(url) -> dict`

```python
row = pd.DataFrame([[features[n] for n in FEATURE_NAMES]], columns=FEATURE_NAMES)
probability = float(bundle["model"].predict_proba(row)[0, 1])
```

A one-row DataFrame with named columns lets scikit-learn verify the schema matches training and warn on mismatch. A bare list would skip that check.

`float(...)` converts `numpy.float64` to a native Python float, so the dict is JSON-serialisable without a custom encoder.

Confidence banding:

```python
if probability >= 0.85 or probability <= 0.15:   confidence = "high"
elif probability >= 0.65 or probability <= 0.35: confidence = "medium"
else:                                            confidence = "low"
```

Symmetric around 0.5 — high confidence means *confidently either way*, not "confidently phishing".

### `main()` — the CLI

`argparse` with a positional URL and a `--file` alternative. File mode filters blanks and `#` comments so you can annotate a URL list. `--json` drops the bulky `features` dict from each result to keep output readable.

---

## `src/app.py` — the web interface

### One inlined template

```python
PAGE = """<!doctype html> ... """

@app.route("/", methods=["GET", "POST"])
def index():
    url = request.form.get("url") or request.args.get("url")
```

`render_template_string` instead of a `templates/` directory: one page, one file. For a larger app this would be wrong.

Reading from **both** `request.form` and `request.args` means POST (the form) and GET (`/?url=...`) both work — so results are shareable links, which is convenient during a demo.

### The three routes

| Route | Notes |
|---|---|
| `/` | Catches `FileNotFoundError` and renders an error card rather than a 500 page |
| `/api/check` | `get_json(silent=True)` returns `None` on malformed JSON instead of raising; returns 400 with an example payload |
| `/health` | Two lines, for uptime checks |

### The styling

CSS custom properties at the top (`--bg`, `--accent`, `--danger`) so the whole theme changes from six lines. Dark by default — demos usually happen on a projector. The probability bar is a `<div>` with a percentage width, no chart library.

The verdict card uses a colour *and* a word ("Likely phishing"), never colour alone — ~8% of men have some form of colour-vision deficiency, and a red/green-only signal is unreadable to them.

---

## `tests/test_features.py`

17 tests in five groups: shape, individual signals, explanations, dataset integrity, end-to-end round trip.

### Import path fix

```python
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
```

Lets the file run as `python tests/test_features.py` as well as under pytest.

### Testing relationships, not magic numbers

```python
def test_entropy_ordering():
    predictable = extract_features("http://google.com")["hostname_entropy"]
    random_looking = extract_features("http://x7q3z9wk2mvb1.tk")["hostname_entropy"]
    assert random_looking > predictable
```

Asserting `entropy == 2.65` would break the moment the calculation changed in a harmless way. Asserting the *ordering* tests the property that actually matters.

### A test that skips rather than fails

```python
def test_model_round_trip_if_trained():
    if not model_path.exists():
        print("  (skipped: run `python -m src.train` first)")
        return
```

The test suite must pass on a fresh clone before anything is trained. Failing there would train people to ignore red output.

### A runner with no dependencies

```python
if __name__ == "__main__":
    tests = [v for n, v in sorted(globals().items()) if n.startswith("test_") and callable(v)]
```

Collects and runs every `test_*` function, printing PASS/FAIL and exiting non-zero on failure. Means the tests run on a machine with nothing but Python — one less barrier for whoever clones this.

---

## Conventions used throughout

| Convention | Why |
|---|---|
| `from __future__ import annotations` | Lets `dict[str, float]` syntax work on Python 3.8+ |
| Descriptive names (`registered_domain`, not `rd`) | Read far more often than written |
| Module docstrings explaining *why* | The *what* is readable from the code |
| Pure functions, no hidden state | Except `_CACHE`, which is documented |
| `pathlib.Path` over string paths | Works identically on Windows |
| Type hints on public functions | Documentation the reader can trust |

---

**Previous:** [06 — Setup & run](06-setup-and-run.md) | **Next:** [08 — Results & evaluation](08-results-and-evaluation.md)
