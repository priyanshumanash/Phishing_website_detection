# Phishing Website Detection System

A machine-learning system that decides whether a URL belongs to a phishing site or a legitimate one — using only the text of the URL, without ever visiting the page.

[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.3%2B-orange)](https://scikit-learn.org/)
[![Tests](https://img.shields.io/badge/tests-17%20passing-brightgreen)](tests/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## What this does

You paste in a URL. The system extracts **28 measurable properties** of that URL — its length, how many subdomains it has, whether a brand name appears somewhere it shouldn't, how random the hostname looks — and feeds them to a trained classifier. You get back a verdict, a probability, and a plain-English list of the signals that drove the decision.

| | |
|---|---|
| **Best model** | Gradient Boosting |
| **Accuracy** | 99.25% on a 1,200-URL held-out test set |
| **F1 score** | 0.9925 |
| **ROC-AUC** | 0.9996 |
| **Speed** | ~0.04 ms per URL (no network request) |
| **Dataset** | 6,000 URLs, balanced, generated locally |

> **Read the honesty note before quoting that accuracy.** These figures come from a synthetic dataset. See [Results & honest limitations](#results--honest-limitations).

---


## Why URL-only detection?

Most tutorials build phishing detectors that download the page and inspect the HTML. That approach has three problems this project avoids:

1. **It's slow.** A network round trip is ~200 ms. Reading the URL text is ~0.04 ms — thousands of times faster. That difference matters if you want to sit inline in an email gateway scanning millions of links.
2. **It's dangerous.** Fetching an attacker's page reveals your IP, can trigger drive-by payloads, and tells the attacker their link is being analysed.
3. **It stops working.** Phishing sites live for a median of a few hours. By the time you analyse one, it's usually a 404 — but the URL is still in someone's inbox.

The trade-off is that URL-only detection can't catch a phishing page hosted on a hacked but perfectly legitimate domain. This project includes exactly those cases in its dataset so the limitation shows up honestly in the numbers rather than being hidden.

---

## Quick start

```bash
git clone https://github.com/<your-username>/phishing-website-detection.git
cd phishing-website-detection

python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

pip install -r requirements.txt

python -m src.dataset              # 1. build the dataset  (~2 s)
python -m src.train                # 2. train the model    (~15 s)
python -m src.predict "http://paypal.com.secure-login.tk/verify.php"
```

Expected output:

```
[!] PHISHING  (99.7% phishing, high confidence)
    http://paypal.com.secure-login.tk/verify.php
    Why:
      - A well-known brand name appears outside the real domain
      - Registered on a TLD heavily abused for phishing
      - Packed with urgency words like 'verify', 'secure', 'account'
      - Served over plain HTTP, not HTTPS
```

Then launch the web interface:

```bash
python -m src.app     # open http://127.0.0.1:5000
```

Full step-by-step setup, including troubleshooting, is in **[docs/06-setup-and-run.md](docs/06-setup-and-run.md)**.

---

## Documentation

The docs are written to be read **in order**. Each one is self-contained and explains one stage of the project, so you can understand the system without reading a single line of code first.

| # | Document | What it covers |
|---|----------|----------------|
| 01 | [Problem statement](docs/01-problem-statement.md) | What phishing is, why it's hard to stop, what exactly this system claims to solve |
| 02 | [Dataset](docs/02-dataset.md) | Where the data comes from, the eight phishing patterns, why hard cases were added, how to swap in a real corpus |
| 03 | [Feature engineering](docs/03-feature-engineering.md) | All 28 features, one by one, with the reasoning behind each |
| 04 | [Model training](docs/04-model-training.md) | The three candidate models, how they're compared, why Gradient Boosting wins |
| 05 | [Architecture](docs/05-architecture.md) | How the pieces fit together, with diagrams and data-flow |
| 06 | [Setup & run](docs/06-setup-and-run.md) | Installation, every command, expected output, troubleshooting |
| 07 | [Code walkthrough](docs/07-code-walkthrough.md) | File by file, function by function |
| 08 | [Results & evaluation](docs/08-results-and-evaluation.md) | Metrics, confusion matrix, feature importance, error analysis |
| 09 | [Viva questions](docs/09-viva-questions.md) | 30 questions an examiner is likely to ask, with answers |
| 10 | [Future work](docs/10-future-work.md) | Honest limitations and what to build next |

---

## Project structure

```
phishing-website-detection/
├── README.md                      you are here
├── requirements.txt
├── LICENSE
├── docs/                          the ten-part written documentation
│   ├── 01-problem-statement.md
│   ├── ...
│   └── images/                    screenshots used in this README
├── src/
│   ├── features.py                URL  -> 28 numbers   (the core idea)
│   ├── dataset.py                 builds the labelled training data
│   ├── train.py                   trains, compares, saves the best model
│   ├── predict.py                 loads the model and scores URLs
│   └── app.py                     Flask web interface + JSON API
├── tests/
│   └── test_features.py           17 unit tests
├── data/
│   └── urls.csv                   generated dataset (6,000 rows)
├── models/
│   └── phishing_model.joblib      the trained, saved model
└── reports/
    ├── metrics.json               every score, machine-readable
    ├── confusion_matrix.png
    └── feature_importance.png
```

---

## How it works, in one picture

```
   "http://paypal.com.verify.tk/login.php"
                  |
                  v
    +-----------------------------+
    |  src/features.py            |   Parse the URL. Count dots, hyphens, digits.
    |  extract_features()         |   Check for IP hosts, punycode, brand names
    |                             |   in the wrong place, abused TLDs, entropy.
    +-----------------------------+
                  |
                  v        [12, 31, 10, 0, 3, 0, 0, ... ]   28 numbers
                  |
    +-----------------------------+
    |  StandardScaler             |   Put every feature on the same scale
    +-----------------------------+
                  |
    +-----------------------------+
    |  GradientBoostingClassifier |   200 shallow decision trees, each one
    |                             |   correcting the previous one's mistakes
    +-----------------------------+
                  |
                  v
        P(phishing) = 0.994  ->  "PHISHING, high confidence"
```

---

## Results & honest limitations

**The measured numbers** (1,200 held-out URLs, none seen during training):

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC |
|-------|----------|-----------|--------|-----|---------|
| Logistic Regression | 0.9425 | 0.9447 | 0.9400 | 0.9424 | 0.9892 |
| Random Forest | 0.9908 | 0.9933 | 0.9883 | 0.9908 | 0.9997 |
| **Gradient Boosting** | **0.9925** | **0.9950** | **0.9900** | **0.9925** | 0.9996 |

Confusion matrix for the winning model: 597 / 600 legitimate URLs correct and 594 / 600 phishing URLs correct — 3 false alarms and 6 missed phishing sites out of 1,200.

**What that number does and does not mean.** The dataset is generated by `src/dataset.py`, not downloaded from PhishTank. That was a deliberate choice so the repository clones and runs with no API keys and no stale download links. The generator reproduces the eight real lexical patterns phishing URLs follow, and 30% of every class is drawn from deliberately *hard* generators — legitimate bank login pages stuffed with the word "verify", internal dashboards on raw IP addresses, phishing kits hosted on hacked but genuine `.com` domains.

Even so, **a generator cannot reproduce the full messiness of the real web.** On a real corpus such as PhishTank + Alexa/Tranco, expect accuracy in the **93–96%** range with these same features. That drop is normal and expected; anyone reporting 99% on real phishing data has almost certainly leaked test data into training.

`docs/02-dataset.md` shows exactly how to point the pipeline at a real CSV — it is a one-line change — and `docs/08-results-and-evaluation.md` analyses the errors the model does make.

**Other limitations, stated plainly:**

- A phishing page on a compromised legitimate domain with an innocuous path is essentially invisible to lexical features. Nothing in the URL is wrong.
- The brand list and suspicious-TLD list are hand-maintained and will go stale. A production system refreshes these weekly.
- The model has no memory of *time*. Domain age (via WHOIS) is one of the strongest real-world signals and is not used here, because it requires a network lookup.
- This is a **defensive** tool for coursework and research. It is not a substitute for a commercial email-security gateway.

---

## Testing

```bash
python tests/test_features.py    # no extra packages needed
python -m pytest -q              # or via pytest, if you have it
```

All 17 tests pass. They cover feature-vector shape, each individual signal (IP hosts, punycode, brand placement, TLDs, entropy ordering), dataset balance, and an end-to-end model round trip.

---

## License

MIT — see [LICENSE](LICENSE).

## Author

**Priyanshu Manash** — final-year engineering project, cyber security.
