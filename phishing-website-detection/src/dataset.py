"""
dataset.py
----------
Builds the labelled URL dataset the model trains on.

WHY SYNTHETIC DATA?
-------------------
Real phishing corpora (PhishTank, OpenPhish, the UCI "Phishing Websites" set)
are the right thing to use for a serious evaluation, but they require network
access, an API key, or a manual download -- which makes a project impossible to
clone-and-run. So this repo ships a *generator* that produces URLs exhibiting
the same lexical patterns the real corpora contain.

The generator is not a toy: legitimate URLs are built from a list of 120 real
domains and realistic path shapes, and phishing URLs are built from the eight
attack patterns documented in docs/02-dataset.md. Crucially, the generator
introduces deliberate overlap (some legitimate URLs are long and full of
parameters; some phishing URLs are short and use HTTPS) so the problem is not
trivially separable and the reported accuracy is meaningful.

Swapping in a real dataset is a one-line change -- see docs/02-dataset.md.
"""

from __future__ import annotations

import csv
import random
from pathlib import Path

# --------------------------------------------------------------------------
# Building blocks for LEGITIMATE URLs
# --------------------------------------------------------------------------

LEGIT_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "wikipedia.org", "amazon.com",
    "reddit.com", "instagram.com", "linkedin.com", "netflix.com", "twitter.com",
    "microsoft.com", "apple.com", "github.com", "stackoverflow.com", "medium.com",
    "nytimes.com", "bbc.co.uk", "theguardian.com", "cnn.com", "forbes.com",
    "bloomberg.com", "reuters.com", "espn.com", "imdb.com", "spotify.com",
    "dropbox.com", "adobe.com", "salesforce.com", "oracle.com", "ibm.com",
    "intel.com", "nvidia.com", "samsung.com", "sony.com", "dell.com",
    "paypal.com", "chase.com", "hsbc.com", "citibank.com", "wellsfargo.com",
    "sbi.co.in", "icicibank.com", "hdfcbank.com", "axisbank.com", "rbi.org.in",
    "irctc.co.in", "flipkart.com", "myntra.com", "zomato.com", "swiggy.com",
    "ola.com", "paytm.com", "phonepe.com", "nseindia.com", "bseindia.com",
    "python.org", "djangoproject.com", "flask.palletsprojects.com", "numpy.org",
    "pandas.pydata.org", "scikit-learn.org", "pytorch.org", "tensorflow.org",
    "kaggle.com", "colab.research.google.com", "arxiv.org", "nature.com",
    "sciencedirect.com", "springer.com", "ieee.org", "acm.org", "jstor.org",
    "mit.edu", "stanford.edu", "harvard.edu", "ox.ac.uk", "cam.ac.uk",
    "iitb.ac.in", "iitd.ac.in", "iisc.ac.in", "nptel.ac.in", "ugc.gov.in",
    "gov.uk", "india.gov.in", "nic.in", "who.int", "un.org", "worldbank.org",
    "nasa.gov", "noaa.gov", "cdc.gov", "nih.gov", "europa.eu",
    "cloudflare.com", "digitalocean.com", "heroku.com", "vercel.com",
    "netlify.com", "gitlab.com", "bitbucket.org", "atlassian.com", "slack.com",
    "zoom.us", "notion.so", "figma.com", "canva.com", "trello.com", "asana.com",
    "shopify.com", "etsy.com", "ebay.com", "walmart.com", "target.com",
    "booking.com", "airbnb.com", "expedia.com", "tripadvisor.com", "uber.com",
    "duolingo.com", "coursera.org", "edx.org", "udemy.com", "khanacademy.org",
]

LEGIT_SUBDOMAINS = ["", "", "", "", "www.", "www.", "blog.", "docs.", "support.",
                    "shop.", "news.", "help.", "api.", "mail.", "accounts."]

LEGIT_PATHS = [
    "", "/", "/about", "/contact", "/pricing", "/products", "/blog",
    "/blog/2024/03/how-we-scaled-our-api", "/docs/getting-started",
    "/docs/reference/authentication", "/help/article/12045",
    "/search?q=machine+learning", "/search?q=best+laptops+2024&sort=rating",
    "/watch?v=dQw4w9WgXcQ", "/user/profile/settings", "/cart/checkout",
    "/news/world/asia/article-48293", "/careers/engineering/backend-developer",
    "/downloads/release-notes", "/legal/privacy-policy", "/legal/terms",
    "/questions/2003505/how-do-i-delete-a-git-branch-locally-and-remotely",
    "/wiki/Machine_learning", "/p/CxY7ZqKLm2n/", "/status/1745829301928",
    "/en-us/support/kb/4567123", "/category/electronics/laptops?page=3",
    "/orders/history?from=2024-01-01&to=2024-06-30",
    "/dashboard/analytics/overview?range=30d&tz=UTC",
]


# --------------------------------------------------------------------------
# Building blocks for PHISHING URLs
# --------------------------------------------------------------------------

TARGET_BRANDS = [
    "paypal", "apple", "appleid", "microsoft", "office365", "outlook",
    "amazon", "netflix", "facebook", "instagram", "whatsapp", "linkedin",
    "dropbox", "chase", "hsbc", "wellsfargo", "citibank", "sbi", "icici",
    "hdfc", "axisbank", "paytm", "phonepe", "binance", "coinbase", "steam",
    "dhl", "fedex", "usps", "irs", "google", "yahoo", "spotify", "roblox",
]

CHEAP_TLDS = ["tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "click",
              "link", "work", "buzz", "icu", "cyou", "sbs", "rest", "zip",
              "loan", "win", "bid", "info", "online", "site", "store"]

PHISH_WORDS = ["secure", "login", "signin", "verify", "verification", "update",
               "account", "confirm", "billing", "payment", "support", "alert",
               "unlock", "recovery", "webscr", "authenticate", "validate",
               "suspended", "limited", "notice"]

PHISH_FILES = ["login.php", "signin.html", "verify.php", "index.php",
               "update.php", "confirm.html", "secure.php", "account.php",
               "webscr.php", "auth.aspx", "validate.jsp", "session.php"]

SHORTENER_HOSTS = ["bit.ly", "tinyurl.com", "cutt.ly", "is.gd", "rb.gy",
                   "shorturl.at", "ow.ly", "tiny.cc", "bit.do"]

# Characters used to build look-alike domains (typosquatting).
LOOKALIKE_SWAPS = {"o": "0", "i": "1", "l": "1", "e": "3", "a": "@", "s": "5"}


def _random_string(length: int, alphabet: str = "abcdefghijklmnopqrstuvwxyz0123456789") -> str:
    return "".join(random.choice(alphabet) for _ in range(length))


def _random_ip() -> str:
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def _typosquat(brand: str) -> str:
    """Create a look-alike of a brand name: paypal -> paypa1, payp4l, paypall."""
    style = random.randint(0, 3)
    if style == 0:                                    # character substitution
        letters = list(brand)
        positions = [i for i, ch in enumerate(letters) if ch in LOOKALIKE_SWAPS]
        if positions:
            index = random.choice(positions)
            letters[index] = LOOKALIKE_SWAPS[letters[index]]
        return "".join(letters)
    if style == 1:                                    # doubled letter
        index = random.randrange(len(brand))
        return brand[:index] + brand[index] + brand[index:]
    if style == 2:                                    # missing letter
        index = random.randrange(len(brand))
        return brand[:index] + brand[index + 1:]
    return brand + random.choice(["-inc", "-support", "-help", "sec", "id"])


# --------------------------------------------------------------------------
# The eight phishing URL patterns
# --------------------------------------------------------------------------

def _phish_ip_host() -> str:
    """Pattern 1: bare IP address hosting a brand-named folder."""
    brand = random.choice(TARGET_BRANDS)
    port = f":{random.choice([8080, 8000, 8888, 81, 8443])}" if random.random() < 0.4 else ""
    return (f"http://{_random_ip()}{port}/{brand}/"
            f"{random.choice(PHISH_WORDS)}/{random.choice(PHISH_FILES)}")


def _phish_brand_subdomain() -> str:
    """Pattern 2: real brand pushed into the subdomain of an attacker domain."""
    brand = random.choice(TARGET_BRANDS)
    words = "-".join(random.sample(PHISH_WORDS, random.randint(1, 3)))
    attacker = f"{words}-{_random_string(random.randint(4, 9))}"
    scheme = "https" if random.random() < 0.35 else "http"
    return (f"{scheme}://{brand}.com.{attacker}.{random.choice(CHEAP_TLDS)}/"
            f"{random.choice(PHISH_WORDS)}/{random.choice(PHISH_FILES)}")


def _phish_typosquat() -> str:
    """Pattern 3: look-alike domain, e.g. paypa1-secure.com."""
    brand = random.choice(TARGET_BRANDS)
    fake = _typosquat(brand)
    tld = random.choice(CHEAP_TLDS + ["com", "net"])
    scheme = "https" if random.random() < 0.45 else "http"
    suffix = random.choice(["", f"-{random.choice(PHISH_WORDS)}"])
    return (f"{scheme}://www.{fake}{suffix}.{tld}/"
            f"{random.choice(PHISH_WORDS)}/{random.choice(PHISH_FILES)}")


def _phish_at_symbol() -> str:
    """Pattern 4: the '@' trick -- everything before '@' is ignored by browsers."""
    brand = random.choice(TARGET_BRANDS)
    return (f"http://{brand}.com@{_random_string(8)}.{random.choice(CHEAP_TLDS)}/"
            f"{random.choice(PHISH_WORDS)}")


def _phish_deep_path() -> str:
    """Pattern 5: extremely long path stuffed with reassuring words."""
    brand = random.choice(TARGET_BRANDS)
    segments = random.sample(PHISH_WORDS, random.randint(4, 6))
    token = _random_string(random.randint(24, 48))
    return (f"http://{_random_string(10)}.{random.choice(CHEAP_TLDS)}/"
            f"{brand}/{'/'.join(segments)}/{random.choice(PHISH_FILES)}"
            f"?session={token}&redirect=https%3A%2F%2F{brand}.com&ref={_random_string(12)}")


def _phish_punycode() -> str:
    """Pattern 6: punycode homograph domain (looks identical in the address bar)."""
    brand = random.choice(TARGET_BRANDS)
    return (f"https://xn--{brand[:4]}{_random_string(6)}-{_random_string(4)}."
            f"{random.choice(CHEAP_TLDS)}/{random.choice(PHISH_WORDS)}/"
            f"{random.choice(PHISH_FILES)}")


def _phish_shortener() -> str:
    """Pattern 7: shortened link hiding the destination."""
    return f"http://{random.choice(SHORTENER_HOSTS)}/{_random_string(random.randint(5, 8), 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789')}"


def _phish_random_host() -> str:
    """Pattern 8: algorithmically generated hostname (DGA-style), high entropy."""
    host = _random_string(random.randint(12, 22))
    brand = random.choice(TARGET_BRANDS)
    return (f"http://{host}.{random.choice(CHEAP_TLDS)}/{brand}-"
            f"{random.choice(PHISH_WORDS)}/{random.choice(PHISH_FILES)}")


PHISH_GENERATORS = [
    _phish_ip_host,
    _phish_brand_subdomain,
    _phish_typosquat,
    _phish_at_symbol,
    _phish_deep_path,
    _phish_punycode,
    _phish_shortener,
    _phish_random_host,
]


# --------------------------------------------------------------------------
# HARD CASES -- the part that makes this dataset honest
# --------------------------------------------------------------------------
# Without these, the two classes are trivially separable and every model scores
# 100%, which tells you nothing. Real life is messy: plenty of legitimate URLs
# are long, hyphenated, HTTP-only or full of the word "login", and plenty of
# phishing URLs are short, HTTPS and sit on a perfectly ordinary .com domain.
#
# These generators deliberately manufacture that overlap, so the reported
# accuracy reflects a problem that is actually hard.
# --------------------------------------------------------------------------

# ---- Legitimate URLs that LOOK suspicious (hard negatives) ----------------

REAL_LOGIN_URLS = [
    "https://accounts.google.com/signin/v2/identifier?flowName=GlifWebSignIn&flowEntry=ServiceLogin",
    "https://appleid.apple.com/account/manage/section/security",
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=4765445b&response_type=code",
    "https://secure.chase.com/web/auth/dashboard#/dashboard/index/index",
    "https://www.paypal.com/signin?country.x=US&locale.x=en_US",
    "https://netbanking.hdfcbank.com/netbanking/entry?_ga=2.18273",
    "https://retail.onlinesbi.sbi/retail/login.htm",
    "https://www.icicibank.com/personal-banking/login/verify-account",
    "https://signin.ebay.com/ws/eBayISAPI.dll?SignIn&ru=https%3A%2F%2Fwww.ebay.com",
    "https://www.amazon.in/ap/signin?openid.pape.max_auth_age=0&openid.return_to=https%3A%2F%2Fwww.amazon.in",
    "https://github.com/login?return_to=%2Fsettings%2Fsecurity",
    "https://secure.login.gov/account/verify/phone",
    "https://www.dropbox.com/login?cont=%2Fhome&_tk=web_login",
    "https://id.atlassian.com/login?continue=https%3A%2F%2Fadmin.atlassian.com",
    "https://auth.services.adobe.com/en_US/index.html?callback=https%3A%2F%2Fims-na1.adobelogin.com",
]

CLOUD_HOSTS = [
    "d{r8}.cloudfront.net", "{r10}.s3.amazonaws.com",
    "storage.googleapis.com/{r8}-prod-assets", "{r6}.blob.core.windows.net",
    "prod-eu-west-1-{r6}.elasticbeanstalk.com", "{r8}.execute-api.us-east-1.amazonaws.com",
    "{r7}.herokuapp.com", "{r6}.vercel.app", "{r7}.netlify.app",
    "cdn-{r5}.jsdelivr.net", "{r6}.pages.dev", "{r8}.firebaseapp.com",
]

HYPHENATED_LEGIT = [
    "state-bank-of-india.co.in", "my-account.spotify.com", "online-banking.hsbc.co.uk",
    "customer-support.zoom.us", "developer-docs.atlassian.com", "help-center.slack.com",
    "secure-checkout.shopify.com", "account-settings.figma.com",
    "student-portal.mit.edu", "e-filing.incometax.gov.in", "digi-locker.gov.in",
]

LEGACY_HTTP_SITES = [
    "results.bteup.ac.in/btechresult/2023/odd/sem3.php",
    "onlineresults.vtu.ac.in/student/marks.php?usn=1AB20CS045",
    "exam.du.ac.in/result/ug/2024/semester4/download.php?rollno=20881234",
    "tenders.gov.in/notice/view.php?id=88231&dept=PWD",
    "nic.in/circulars/2024/dept-notice-483.pdf",
    "library.university.ac.in/opac/search.php?q=network+security&page=4",
]


def _fill(template: str) -> str:
    """Expand {r8}-style placeholders into random strings of that length."""
    result = template
    while "{r" in result:
        start = result.index("{r")
        end = result.index("}", start)
        length = int(result[start + 2:end])
        result = result[:start] + _random_string(length) + result[end + 1:]
    return result


def _legit_real_login() -> str:
    """Genuine sign-in pages -- full of 'login', 'verify', 'secure', 'account'."""
    return random.choice(REAL_LOGIN_URLS)


def _legit_cloud_host() -> str:
    """Real CDN / cloud hostnames, which look machine-generated because they are."""
    host = _fill(random.choice(CLOUD_HOSTS))
    path = random.choice([
        f"/assets/{_random_string(8)}.min.js",
        f"/static/media/logo.{_random_string(8)}.svg",
        f"/uploads/2024/06/report-{random.randint(1000, 9999)}.pdf",
        f"/v1/users/{random.randint(10000, 99999)}/profile?token={_random_string(22)}",
        "/api/health",
    ])
    return f"https://{host}{path}"


def _legit_internal_ip() -> str:
    """Internal dashboards on private IPs and odd ports -- normal in any company."""
    private = random.choice([
        f"192.168.{random.randint(0, 5)}.{random.randint(2, 250)}",
        f"10.0.{random.randint(0, 9)}.{random.randint(2, 250)}",
        f"172.16.{random.randint(0, 9)}.{random.randint(2, 250)}",
        "localhost", "127.0.0.1",
    ])
    port = random.choice([3000, 8080, 8000, 9090, 5601, 15672, 8081])
    path = random.choice([
        "/jenkins/job/nightly-build/lastBuild/console",
        f"/grafana/d/{_random_string(9)}/service-overview?orgId=1&refresh=30s",
        "/kibana/app/discover", "/admin/login", "/api/v1/status",
        f"/pgadmin/browser/?sid={random.randint(1, 40)}",
    ])
    return f"http://{private}:{port}{path}"


def _legit_hyphenated() -> str:
    domain = random.choice(HYPHENATED_LEGIT)
    path = random.choice(["/login", "/account/overview", "/help/faq",
                          "/services/apply-online", "/dashboard", "/"])
    return f"https://{domain}{path}"


def _legit_legacy_http() -> str:
    """University / government sites: HTTP-only, deep paths, .php endpoints."""
    return f"http://{random.choice(LEGACY_HTTP_SITES)}"


def _legit_long_tracking() -> str:
    """Marketplace URLs with enormous tracking query strings."""
    domain = random.choice(["amazon.com", "amazon.in", "flipkart.com",
                            "ebay.com", "walmart.com", "aliexpress.com"])
    return (f"https://www.{domain}/dp/B0{_random_string(8).upper()}/"
            f"ref=sr_1_{random.randint(1, 20)}?crid={_random_string(13).upper()}"
            f"&keywords=wireless%20headphones&qid={random.randint(1700000000, 1750000000)}"
            f"&sprefix=wireless%2Caps%2C{random.randint(100, 300)}"
            f"&sr=8-{random.randint(1, 20)}&th=1")


def _legit_shortened() -> str:
    """Legitimate shortened links -- news outlets and social posts use these constantly."""
    return (f"https://{random.choice(['t.co', 'bit.ly', 'buff.ly', 'ow.ly'])}/"
            f"{_random_string(random.randint(7, 10), 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789')}")


HARD_LEGIT_GENERATORS = [
    _legit_real_login,
    _legit_cloud_host,
    _legit_internal_ip,
    _legit_hyphenated,
    _legit_legacy_http,
    _legit_long_tracking,
    _legit_shortened,
]


# ---- Phishing URLs that LOOK clean (hard positives) ----------------------

COMPROMISED_HOSTS = [
    "www.greenleafgardens.com", "blog.thepotterystudio.co.uk", "shop.bellavistacafe.com",
    "www.riversidedental.net", "portal.springfieldschools.org", "www.acmelogistics.in",
    "news.localgazette.co.za", "www.harborviewrealty.com", "store.craftbrewco.com",
    "www.mountaintrektours.com", "www.silverlinefinance.co", "info.brightsmileclinic.org",
]


def _phish_clean_lookalike() -> str:
    """HTTPS, .com/.net/.org, short path -- nothing 'weird' except the domain itself."""
    brand = random.choice(TARGET_BRANDS)
    shape = random.choice([
        f"{brand}-{random.choice(['secure', 'verify', 'account', 'support', 'id'])}",
        f"{random.choice(['secure', 'my', 'login', 'account'])}-{brand}",
        f"{brand}{random.choice(['help', 'care', 'team', 'centre'])}",
    ])
    tld = random.choice(["com", "net", "org", "co", "io"])
    path = random.choice(["/", "/login", "/signin", "/account", "/verify"])
    return f"https://www.{shape}.{tld}{path}"


def _phish_compromised_site() -> str:
    """A real, innocent website that has been hacked to host a phishing kit.

    The domain is genuinely legitimate, so hostname features are useless here --
    only the path gives it away. This is the hardest case in the whole dataset.
    """
    host = random.choice(COMPROMISED_HOSTS)
    brand = random.choice(TARGET_BRANDS)
    folder = random.choice([
        "wp-content/uploads", "wp-content/plugins/wp-file-manager", "wp-includes",
        "assets/js/vendor", "images/gallery", "cgi-bin", "old/backup", ".well-known",
    ])
    return (f"https://{host}/{folder}/{brand}/{random.choice(PHISH_FILES)}")


def _phish_on_cloud_host() -> str:
    """Phishing page hosted on a trusted cloud provider -- extremely common in practice."""
    brand = random.choice(TARGET_BRANDS)
    host = random.choice([
        f"firebasestorage.googleapis.com/v0/b/{_random_string(9)}-{random.randint(10000, 99999)}.appspot.com/o",
        f"{_random_string(8)}.web.app",
        f"{_random_string(9)}.000webhostapp.com",
        f"{_random_string(8)}.weebly.com",
        f"sites.google.com/view/{brand}-{random.choice(PHISH_WORDS)}",
        f"{_random_string(7)}.glitch.me",
        f"{_random_string(8)}.repl.co",
    ])
    tail = random.choice([f"/{brand}-{random.choice(PHISH_WORDS)}.html",
                          f"/{random.choice(PHISH_FILES)}", "/"])
    return f"https://{host}{tail}"


def _phish_short_https() -> str:
    """Two words, HTTPS, no path at all -- nothing for a length feature to catch."""
    brand = random.choice(TARGET_BRANDS)
    word = random.choice(["alert", "notice", "update", "service", "online", "portal"])
    return f"https://{brand}{word}.{random.choice(['com', 'net', 'org', 'info', 'site'])}/"


HARD_PHISH_GENERATORS = [
    _phish_clean_lookalike,
    _phish_compromised_site,
    _phish_on_cloud_host,
    _phish_short_https,
]


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

# Share of each class drawn from the "hard case" generators above.
# 0.0 makes the problem trivial (every model scores 100%).
# 0.30 keeps it realistic. See docs/02-dataset.md for the sensitivity table.
HARD_FRACTION = 0.30


def make_legitimate_url(hard_fraction: float = HARD_FRACTION) -> str:
    if random.random() < hard_fraction:
        return random.choice(HARD_LEGIT_GENERATORS)()

    domain = random.choice(LEGIT_DOMAINS)
    subdomain = random.choice(LEGIT_SUBDOMAINS)
    path = random.choice(LEGIT_PATHS)
    # Most real traffic is HTTPS, but a meaningful minority is still HTTP.
    scheme = "https" if random.random() < 0.88 else "http"
    return f"{scheme}://{subdomain}{domain}{path}"


def make_phishing_url(hard_fraction: float = HARD_FRACTION) -> str:
    if random.random() < hard_fraction:
        return random.choice(HARD_PHISH_GENERATORS)()
    return random.choice(PHISH_GENERATORS)()


def build_dataset(n_legitimate: int = 3000, n_phishing: int = 3000,
                  seed: int = 42,
                  hard_fraction: float = HARD_FRACTION) -> list[tuple[str, int]]:
    """Return a shuffled list of (url, label) with label 1 = phishing."""
    random.seed(seed)

    # `seen` deduplicates; `dataset` preserves insertion order.
    #
    # Why not just build a set and call list() on it? Because Python randomises
    # string hashing per process (PYTHONHASHSEED), so set iteration order is
    # NOT stable between runs -- and an unstable order means a different
    # train/test split every time, which silently destroys reproducibility.
    # This bug is easy to miss: the code looks seeded, and it isn't.
    seen: set[str] = set()
    dataset: list[tuple[str, int]] = []

    for generate, label, target in ((make_legitimate_url, 0, n_legitimate),
                                    (make_phishing_url, 1, n_phishing)):
        added = 0
        guard = 0
        while added < target and guard < target * 200:
            url = generate(hard_fraction)
            guard += 1
            if url in seen:            # collision: try again, don't use a slot
                continue
            seen.add(url)
            dataset.append((url, label))
            added += 1

    random.shuffle(dataset)
    return dataset


def save_dataset(path: str | Path, n_legitimate: int = 3000,
                 n_phishing: int = 3000, seed: int = 42,
                 hard_fraction: float = HARD_FRACTION) -> Path:
    """Generate the dataset and write it to a two-column CSV."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    dataset = build_dataset(n_legitimate, n_phishing, seed, hard_fraction)

    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["url", "label"])
        writer.writerows(dataset)

    return path


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Generate the phishing URL dataset.")
    parser.add_argument("--out", default="data/urls.csv", help="output CSV path")
    parser.add_argument("--legit", type=int, default=3000, help="number of legitimate URLs")
    parser.add_argument("--phish", type=int, default=3000, help="number of phishing URLs")
    parser.add_argument("--seed", type=int, default=42, help="random seed")
    parser.add_argument("--hard", type=float, default=HARD_FRACTION,
                        help="share of hard/ambiguous cases in each class (0.0-1.0)")
    arguments = parser.parse_args()

    written = save_dataset(arguments.out, arguments.legit, arguments.phish,
                           arguments.seed, arguments.hard)
    print(f"Wrote {arguments.legit + arguments.phish} labelled URLs to {written}")
