# 02 — The Dataset

*Where the training data comes from, how it's built, why it's synthetic, and how to replace it with a real corpus.*

---

## 2.1 The honest starting point

A phishing detector is only as credible as the data it was measured on. So this document is deliberately blunt about what the data is.

**The shipped dataset is generated, not downloaded.** `src/dataset.py` produces 6,000 labelled URLs — 3,000 legitimate, 3,000 phishing — every time you run it.

### Why not just download PhishTank?

| Option | Problem |
|---|---|
| PhishTank live feed | Needs an API key; the free tier has been intermittently unavailable |
| OpenPhish | Commercial licence for the full feed |
| UCI "Phishing Websites" dataset | Only 11,055 rows, and it ships **pre-extracted features** — you never see the URLs, so you can't do your own feature engineering, which is the entire point of this project |
| Kaggle phishing URL dumps | Quality varies wildly; many are unlabelled scrapes; links rot |
| A committed CSV of real phishing URLs | Shipping thousands of live malicious URLs in a public Git repo is irresponsible |

Every one of these makes `git clone && python -m src.train` fail for whoever reads this repo six months from now. A generator always works.

**The trade-off is stated up front and repeated in the README:** generated data cannot reproduce the full messiness of the real web, and the accuracy reported here is therefore an upper bound. Section 2.6 covers what to expect on real data and how to run it.

---

## 2.2 What gets generated

### Legitimate URLs (label `0`)

Built from a curated list of **120 real domains** across categories that actually reflect normal browsing:

```
Tech / social      google.com, github.com, reddit.com, linkedin.com, ...
News               nytimes.com, bbc.co.uk, reuters.com, theguardian.com, ...
Banking            chase.com, hsbc.com, sbi.co.in, hdfcbank.com, icicibank.com, ...
Indian services    irctc.co.in, flipkart.com, paytm.com, zomato.com, ...
Developer          python.org, scikit-learn.org, pytorch.org, kaggle.com, ...
Academic           mit.edu, ox.ac.uk, iitb.ac.in, arxiv.org, nature.com, ...
Government         gov.uk, india.gov.in, nasa.gov, who.int, europa.eu, ...
SaaS               slack.com, notion.so, figma.com, zoom.us, ...
Commerce           amazon.com, etsy.com, shopify.com, booking.com, ...
```

Each URL combines a domain, an optional realistic subdomain (`www.`, `docs.`, `support.`, `api.`, `accounts.`), and one of 29 realistic path shapes — including deep paths, query strings and search parameters, so "long URL" alone never becomes a giveaway.

88% use HTTPS, 12% use HTTP. That mirrors reality: most of the web has migrated, but a meaningful tail hasn't.

### Phishing URLs (label `1`)

Built from **eight attack patterns** documented in the phishing literature. Each is a separate function in `src/dataset.py`.

| # | Pattern | Example produced | Real-world basis |
|---|---|---|---|
| 1 | **IP host** | `http://203.44.19.8:8080/paypal/verify/login.php` | Attacker uses a raw VPS IP, skipping domain registration entirely |
| 2 | **Brand in subdomain** | `http://paypal.com.secure-verify-x8k2.tk/confirm.php` | The most common pattern. Reads as "paypal.com" to a hurried eye |
| 3 | **Typosquat** | `https://www.paypa1-secure.xyz/login.php` | Character substitution (`l`→`1`, `o`→`0`), doubled or dropped letters |
| 4 | **`@` trick** | `http://paypal.com@x7kf9d2a.gq/verify` | Browsers ignore everything before `@`. The real host is `x7kf9d2a.gq` |
| 5 | **Deep padded path** | `http://k2m9x.tk/amazon/secure/verify/confirm/unlock/login.php?session=…` | Long chains of reassuring words plus a long random session token |
| 6 | **Punycode homograph** | `https://xn--appl9kd2-x4m2.top/signin.html` | Unicode look-alike characters; renders as the real brand in some browsers |
| 7 | **Shortener** | `http://tinyurl.com/k3Jm9q` | Hides the destination completely |
| 8 | **DGA-style host** | `http://x7q3z9wk2mvb1n.club/netflix-verify/login.php` | Algorithmically generated domain names, registered in bulk |

---

## 2.3 The part that matters most: hard cases

Here is the thing most student projects get wrong.

When the first version of this generator was written — the eight patterns above versus the 120 clean domains — **the tree models scored exactly 100.00% accuracy** and Logistic Regression managed 99.92%.

That result is worthless. It doesn't mean the models are good; it means the two classes were trivially separable. Every phishing URL had a cheap TLD *and* a brand in the wrong place *and* no HTTPS. A single `if` statement would have scored 99%. And you cannot compare three models when two of them are perfect.

Real data is not like that. So the generator now draws **30% of every class** from deliberately *hard* generators that manufacture overlap between the classes.

### Hard negatives — legitimate URLs that look suspicious

| Generator | Example | Why it fools naive rules |
|---|---|---|
| `_legit_real_login` | `https://accounts.google.com/signin/v2/identifier?flowName=GlifWebSignIn` | Real sign-in pages are *full* of the words "signin", "account", "verify", "secure" |
| `_legit_cloud_host` | `https://d8kf2m9x.cloudfront.net/assets/a8f2kd9m.min.js` | Real CDN hostnames are machine-generated, so entropy is high |
| `_legit_internal_ip` | `http://192.168.1.42:8080/jenkins/job/nightly-build/lastBuild/console` | Raw IP + odd port + HTTP — and completely normal inside any company |
| `_legit_hyphenated` | `https://state-bank-of-india.co.in/login` | Hyphens are not inherently suspicious |
| `_legit_legacy_http` | `http://results.bteup.ac.in/btechresult/2023/odd/sem3.php` | University and government sites: HTTP-only, deep paths, `.php` endpoints |
| `_legit_long_tracking` | `https://www.amazon.in/dp/B0CX7K2M9P/ref=sr_1_3?crid=…&qid=…&sr=8-3&th=1` | 180-character legitimate URLs are routine on marketplaces |
| `_legit_shortened` | `https://t.co/kM9x2Qp7` | News outlets and social posts use shorteners constantly |

### Hard positives — phishing URLs that look clean

| Generator | Example | Why it's hard |
|---|---|---|
| `_phish_clean_lookalike` | `https://www.paypal-secure.com/login` | HTTPS, `.com`, short path. Only the domain itself is wrong |
| `_phish_compromised_site` | `https://www.greenleafgardens.com/wp-content/uploads/paypal/login.php` | **The hardest case in the dataset.** The domain is genuinely legitimate — a small business whose WordPress site was hacked. Every hostname feature is useless; only the path hints at anything |
| `_phish_on_cloud_host` | `https://firebasestorage.googleapis.com/v0/b/xk29fm3-48211.appspot.com/o/apple-verify.html` | Hosted on Google infrastructure. The domain is *literally trusted* |
| `_phish_short_https` | `https://netflixalert.com/` | Two words, HTTPS, no path. Nothing for a length feature to grab |

### The effect on results

Sensitivity of test accuracy to `--hard`:

| `hard_fraction` | Logistic Regression | Random Forest | Gradient Boosting |
|---|---|---|---|
| 0.00 | 0.9992 | 1.0000 | 1.0000 |
| 0.30 *(default)* | 0.9424 | 0.9908 | **0.9925** |
| 0.50 | 0.9313 | 0.9892 | 0.9891 |

At `0.00`, two of the three models are literally perfect and the comparison in [doc 04](04-model-training.md) is meaningless. At `0.30`, a 5-point gap opens between the linear model and the tree ensembles — which tells you something real: the decision boundary is **non-linear**, because the hard cases require *combinations* of features rather than any single one.

You can reproduce this yourself:

```bash
python -m src.dataset --hard 0.0  && python -m src.train   # everything scores 1.0
python -m src.dataset --hard 0.3  && python -m src.train   # the honest version
python -m src.dataset --hard 0.5  && python -m src.train   # harder still
```

---

## 2.4 Dataset integrity

Three safeguards, all in `build_dataset()`:

1. **Deduplication with a stable order.** A `set` tracks which URLs have been seen, but the rows themselves accumulate in a **list**. This matters more than it looks: Python randomises string hashing per process, so iterating a set gives a different order on every run — and an unstable order means a different train/test split every time, silently destroying reproducibility even though every `random_state` is set. This was a real bug during development; see [doc 08 §8.9](08-results-and-evaluation.md#89-reproducing-everything-here).
2. **Exact balance.** The loop continues until each class has hit its target count. A 50/50 split means accuracy is directly interpretable (a coin flip scores 50%, not 90%).
3. **Seeded randomness.** `random.seed(seed)`, default `42`. Rerun the pipeline and you get byte-identical data, so every number in these docs is reproducible.

### The train/test split

```python
train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
```

- **80 / 20** → 4,800 training rows, 1,200 test rows
- **`stratify=y`** → the test set keeps the same 50/50 class ratio
- **`random_state=42`** → the same split every run

The test set is touched exactly once, at the very end, to report final numbers. Model selection uses 5-fold cross-validation on the *training* set only, so the test score is not contaminated by the choice of model.

---

## 2.5 Generated file format

`data/urls.csv` — two columns, nothing else:

```csv
url,label
https://accounts.asana.com/cart/checkout,0
http://e8fgzqqh9j.icu/yahoo/login/support/recovery/webscr/auth.aspx?session=x1fkr9,1
https://blog.thepotterystudio.co.uk/wp-content/plugins/wp-file-manager/amazon/confirm.html,1
https://prod-eu-west-1-ltv377.elasticbeanstalk.com/v1/users/52274/profile?token=a44wmz,0
```

`0` = legitimate, `1` = phishing. Nothing is pre-computed — features are extracted at training time by `src/features.py`, so you can change the feature set without regenerating data.

### CLI options

```bash
python -m src.dataset --help

  --out    data/urls.csv   output path
  --legit  3000            number of legitimate URLs
  --phish  3000            number of phishing URLs
  --seed   42              random seed
  --hard   0.3             share of hard/ambiguous cases per class
```

---

## 2.6 Swapping in a real dataset

This is the change to make if you want defensible real-world numbers — for a paper, or if an examiner asks you to prove the pipeline isn't tuned to its own generator.

### Step 1 — get real URLs

| Source | What you get | How |
|---|---|---|
| [PhishTank](https://phishtank.org/developer_info.php) | Verified phishing URLs, hourly CSV | Free API key |
| [OpenPhish](https://openphish.com/) | Phishing feed | Free tier is a sample |
| [Tranco](https://tranco-list.eu/) | Top 1M legitimate domains, research-grade | Direct download, no key |
| [Majestic Million](https://majestic.com/reports/majestic-million) | Top 1M legitimate domains | Direct download |

A reasonable real setup: **PhishTank verified URLs** as the positive class, **Tranco top-N with realistic paths appended** as the negative class.

### Step 2 — write it as the same two-column CSV

```csv
url,label
http://real-phishing-url-from-phishtank.tk/login,1
https://legitimate-domain-from-tranco.com/,0
```

### Step 3 — that's it

Nothing else changes. `src/train.py` reads `data/urls.csv`; if the file already exists it is used as-is and the generator never runs:

```python
if not csv_path.exists():
    save_dataset(csv_path)        # only fires when the file is missing
frame = pd.read_csv(csv_path)
```

So: drop your real CSV at `data/urls.csv` and run `python -m src.train`.

### Step 4 — what to expect

**Accuracy will drop, and that is the correct outcome.** Realistic expectations with this feature set on a real corpus:

| Metric | Synthetic (this repo) | Real corpus (expected) |
|---|---|---|
| Accuracy | 0.9925 | 0.93 – 0.96 |
| Precision | 0.9950 | 0.92 – 0.96 |
| Recall | 0.9900 | 0.91 – 0.95 |

If you get 99% on real PhishTank data, be suspicious of yourself before you celebrate — the usual causes are duplicate URLs across the split, or a negative class that's all bare domains (`https://google.com`) while the positive class is all deep paths, making path length a perfect giveaway.

### One trap to avoid

Don't build the negative class from bare domains alone. If every legitimate URL is `https://domain.com/` and every phishing URL has a path, the model learns "has a path → phishing" and reports 99% while being completely useless. Append realistic paths to your legitimate domains — this is exactly what `LEGIT_PATHS` in the generator does.

---

**Previous:** [01 — Problem statement](01-problem-statement.md) | **Next:** [03 — Feature engineering](03-feature-engineering.md)
