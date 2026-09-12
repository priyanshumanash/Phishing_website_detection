# 06 — Setup & Run

*Every command, in order, with the output you should see. Written so you can follow it without knowing the project.*

---

## 6.1 Requirements

| | |
|---|---|
| **Python** | 3.10 or newer (`match`-free, but uses `X \| Y` type syntax) |
| **Disk** | ~200 MB including dependencies |
| **RAM** | 500 MB during training |
| **OS** | Linux, macOS or Windows |
| **Network** | Only to install packages. The system itself never makes a request |

Check your Python:

```bash
python --version
```

If that prints 2.x or "command not found", try `python3 --version` and use `python3` everywhere below.

---

## Step 1 — Get the code

```bash
git clone https://github.com/<your-username>/phishing-website-detection.git
cd phishing-website-detection
```

---

## Step 2 — Create a virtual environment

A virtual environment keeps this project's packages separate from everything else on your machine. Skipping it works but is a bad habit.

**Linux / macOS**

```bash
python -m venv .venv
source .venv/bin/activate
```

**Windows (PowerShell)**

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

**Windows (Command Prompt)**

```cmd
python -m venv .venv
.venv\Scripts\activate.bat
```

Your prompt should now start with `(.venv)`. That's how you know it's active.

> **PowerShell blocks the activation script?**
> `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` then try again.

---

## Step 3 — Install dependencies

```bash
pip install -r requirements.txt
```

Takes 1–3 minutes. What gets installed:

| Package | Needed for |
|---|---|
| `scikit-learn` | The models, the split, the metrics |
| `pandas` | The feature matrix |
| `numpy` | Array maths (pulled in by the others anyway) |
| `joblib` | Saving and loading the trained model |
| `matplotlib` | The two charts in `reports/` |
| `Flask` | Optional — the web interface |
| `pytest` | Optional — the tests also run with plain Python |

Verify:

```bash
python -c "import sklearn, pandas, joblib; print('ok')"
```

---

## Step 4 — Generate the dataset

```bash
python -m src.dataset
```

```
Wrote 6000 labelled URLs to data/urls.csv
```

Takes about 2 seconds. Look at what it made:

```bash
head -5 data/urls.csv
```

```csv
url,label
https://accounts.asana.com/cart/checkout,0
https://mail.gitlab.com/pricing,0
http://e8fgzqqh9j.icu/yahoo/login/support/recovery/auth.aspx?session=x1fkr9,1
https://www.account-paypal.com/signin,1
```

**Options:**

```bash
python -m src.dataset --legit 5000 --phish 5000     # bigger dataset
python -m src.dataset --hard 0.5                    # harder problem
python -m src.dataset --seed 7                      # different random data
python -m src.dataset --out data/mine.csv           # somewhere else
```

> You can skip this step. `src/train.py` generates the CSV automatically if it's missing. Running it separately is useful when you want to inspect the data first.

---

## Step 5 — Train the model

```bash
python -m src.train
```

```
[1/6] Loaded 6,000 URLs (3,000 legitimate, 3,000 phishing)
[2/6] Extracted 28 features per URL -> matrix (6000, 28)
[3/6] Split into 4,800 training and 1,200 test rows
[4/6] Training candidates...
      LogisticRegression   acc=0.9425  f1=0.9424  auc=0.9892  cv_f1=0.9568+/-0.0059
      RandomForest         acc=0.9908  f1=0.9908  auc=0.9997  cv_f1=0.9917+/-0.0028
      GradientBoosting     acc=0.9925  f1=0.9925  auc=0.9996  cv_f1=0.9925+/-0.0014
[5/6] Best model: GradientBoosting (F1 = 0.9925)

              precision    recall  f1-score   support

  Legitimate     0.9900    0.9950    0.9925       600
    Phishing     0.9950    0.9900    0.9925       600

    accuracy                         0.9925      1200
   macro avg     0.9925    0.9925    0.9925      1200
weighted avg     0.9925    0.9925    0.9925      1200

[6/6] Saved:
      model    -> models/phishing_model.joblib
      metrics  -> reports/metrics.json
      matrix   -> reports/confusion_matrix.png
      features -> reports/feature_importance.png
Done in 13.24s
```

About 13 seconds. Your numbers should match exactly — everything is seeded.

**New files:**

```
models/phishing_model.joblib     the trained model (~270 KB)
reports/metrics.json             every score, machine-readable
reports/confusion_matrix.png     chart
reports/feature_importance.png   chart
```

---

## Step 6 — Check a URL from the command line

**One URL:**

```bash
python -m src.predict "http://paypal.com.secure-verify-login.tk/account/confirm.php"
```

```
[!] PHISHING  (99.6% phishing, high confidence)
    http://paypal.com.secure-verify-login.tk/account/confirm.php
    Why:
      - A well-known brand name appears outside the real domain
      - Registered on a TLD heavily abused for phishing
      - Packed with urgency words like 'verify', 'secure', 'account'
      - Served over plain HTTP, not HTTPS
      - Hostname looks machine-generated (high randomness)

1 of 1 URLs flagged as phishing.
```

```bash
python -m src.predict "https://www.google.com/search?q=python"
```

```
[ok] LEGITIMATE  (0.3% phishing, high confidence)
    https://www.google.com/search?q=python

0 of 1 URLs flagged as phishing.
```

**A whole file.** Put one URL per line (lines starting with `#` are ignored):

```bash
cat > check.txt <<'EOF'
https://github.com/torvalds/linux
http://192.168.4.21/paypal/login/verify.php
https://bit.ly/3xYz1Ab
http://apple.com@x7kf9d2a.gq/verify
EOF

python -m src.predict --file check.txt
```

**JSON output**, for piping into something else:

```bash
python -m src.predict "http://evil.tk/paypal/login" --json
```

---

## Step 7 — Run the web interface

```bash
python -m src.app
```

```
 * Running on http://127.0.0.1:5000
```

Open <http://127.0.0.1:5000> in a browser. Paste a URL, press **Check URL**.

Stop it with `Ctrl+C`.

**Use the JSON API:**

```bash
curl -X POST http://127.0.0.1:5000/api/check \
     -H 'Content-Type: application/json' \
     -d '{"url":"http://paypal.com.evil.tk/login"}'
```

**Shareable result links** — the page accepts a URL on the query string:

```
http://127.0.0.1:5000/?url=https://github.com
```

Handy for a demo: prepare the links in advance so you're not typing during a presentation.

---

## Step 8 — Run the tests

The test file has its own runner and needs no extra packages:

```bash
python tests/test_features.py
```

```
PASS  test_all_features_are_numeric
PASS  test_brand_outside_domain
...
17/17 tests passed
```

If you have pytest installed, `python -m pytest -q` works too.

---

## 6.2 Troubleshooting

### `ModuleNotFoundError: No module named 'src'`

You're running from the wrong directory, or using the wrong command form.

```bash
pwd            # must be .../phishing-website-detection
python -m src.train      # correct   (-m, dots, no .py)
python src/train.py      # wrong     (relative imports break)
```

The `-m` flag matters: it adds the current directory to the import path, which is what makes `from .features import ...` work.

### `FileNotFoundError: No trained model at models/phishing_model.joblib`

You skipped Step 5.

```bash
python -m src.train
```

### `ModuleNotFoundError: No module named 'sklearn'`

Either the virtual environment isn't active, or dependencies didn't install.

```bash
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Note the name mismatch: the package is `scikit-learn`, the import is `sklearn`.

### `Address already in use` on port 5000

Something else has the port. On macOS this is often AirPlay Receiver.

Edit the last line of `src/app.py`:

```python
app.run(host="127.0.0.1", port=5001, debug=False)
```

Or find and stop the other process:

```bash
lsof -i :5000        # macOS / Linux
netstat -ano | findstr :5000    # Windows
```

### Training is slow

13 seconds is normal; most of it is the 5-fold cross-validation, which fits each model six times over. To skip CV while experimenting, comment out the `cross_val_score` line in `src/train.py`.

### Results don't match this document

You changed something — `--seed`, `--hard`, or the dataset size. Reset:

```bash
rm -f data/urls.csv models/phishing_model.joblib
python -m src.dataset && python -m src.train
```

### Windows: `python` opens the Microsoft Store

Windows ships an alias that does that. Use `py` instead:

```powershell
py -m venv .venv
py -m src.train
```

Or turn the alias off in Settings → Apps → App execution aliases.

---

## 6.3 The whole thing, copy-pasteable

```bash
git clone https://github.com/<your-username>/phishing-website-detection.git
cd phishing-website-detection
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m src.dataset
python -m src.train
python -m src.predict "http://paypal.com.secure-login.tk/verify.php"
python tests/test_features.py
python -m src.app
```

---

**Previous:** [05 — Architecture](05-architecture.md) | **Next:** [07 — Code walkthrough](07-code-walkthrough.md)
