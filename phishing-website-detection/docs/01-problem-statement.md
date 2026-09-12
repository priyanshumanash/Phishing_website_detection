# 01 — Problem Statement

*Read this first. It explains what problem exists, why the obvious solutions don't fully work, and exactly what this project claims to do about it.*

---

## 1.1 What phishing actually is

Phishing is a **social-engineering attack delivered through a link**. The attacker builds a web page that looks like one you trust — your bank, your college portal, Microsoft 365 — and gets you to type your credentials into it. The page forwards what you type to the attacker and usually redirects you to the real site, so you never notice.

The entire attack depends on one moment: **you looking at a URL and deciding it's safe.**

That's the moment this project targets.

## 1.2 Why it's still unsolved

You'd think this would be a solved problem by now. It isn't, for four structural reasons.

**Phishing sites are disposable.** The median phishing site is alive for a few hours. Blocklists work by listing known-bad URLs, so a blocklist is always behind: by the time a URL is reported, verified, and pushed to browsers, the campaign has moved to a new domain. Anti-Phishing Working Group data consistently shows a large share of phishing URLs are never blocklisted at all before they go dark.

**Domains are nearly free.** A `.tk`, `.ml` or `.xyz` domain costs cents or nothing. An attacker can burn a thousand domains in a campaign without caring.

**HTTPS is no longer a signal.** Ten years ago, "look for the padlock" was reasonable advice. Free certificates from Let's Encrypt mean the majority of phishing sites now serve HTTPS. The padlock proves the connection is encrypted; it says nothing about who is on the other end. A large fraction of users still read it as a safety signal.

**Humans are bad at reading URLs.** Given `paypal.com.secure-login.tk`, most people see "paypal.com" at the start and stop reading. The actual registered domain is `secure-login.tk`. The brand name is decoration.

## 1.3 The three families of solution

| Approach | How it works | Strength | Weakness |
|---|---|---|---|
| **Blocklists** | Maintain a list of known phishing URLs (Google Safe Browsing, PhishTank) | Zero false positives on listed URLs | Useless against a URL first seen 20 minutes ago |
| **Content analysis** | Fetch the page, inspect HTML, forms, logos, JavaScript | Very accurate — it sees what the user sees | Slow (network round trip), risky (you visit the attacker), fails once the site is taken down |
| **Lexical URL analysis** | Learn statistical patterns from the URL text alone | Fast, safe, works on dead URLs, catches unseen domains | Blind to a phishing page on a hacked legitimate domain |

**This project implements the third.** Not because it is the best in isolation — in a real deployment you'd layer all three — but because it is the one that generalises to URLs nobody has ever reported, which is precisely where blocklists fail.

## 1.4 The core insight

Phishing URLs are not random. They are *manufactured*, and the manufacturing process leaves fingerprints:

- The attacker wants the brand name visible, but can't register the real domain. So the brand ends up in the **subdomain** (`paypal.com.evil.tk`) or the **path** (`evil.tk/paypal/login`).
- The attacker wants the victim to feel urgency, so the URL is stuffed with **words like `verify`, `suspended`, `confirm`, `unlock`**.
- The attacker registers domains in bulk, often programmatically, so the hostname is frequently **random-looking** (`x7q3z9wk2mvb.tk`) — statistically high-entropy in a way `wikipedia.org` is not.
- The attacker uses **cheap TLDs** massively out of proportion to their share of the legitimate web.

None of these signals is conclusive on its own. `accounts.google.com/signin` contains the word "signin" and is perfectly legitimate. `bit.ly/3xY2z` is a shortener and is usually fine.

**But combined, they are highly predictive.** That is exactly the kind of problem supervised machine learning is good at: many individually weak signals, combined into one decision by learning from labelled examples.

## 1.5 Formal problem definition

> Given a URL string `u`, produce `P(phishing | u) ∈ [0, 1]` using only features computable from `u` itself, without issuing any network request.

- **Task type:** binary classification
- **Input:** one string
- **Output:** a probability, thresholded at 0.5 for a label
- **Constraint:** no network access at inference time
- **Target latency:** under 1 ms per URL

## 1.6 Objectives

1. Design a lexical feature set that captures the fingerprints described above. → *28 features, see [doc 03](03-feature-engineering.md)*
2. Build a labelled dataset that includes genuinely ambiguous cases, so the evaluation is not self-flattering. → *see [doc 02](02-dataset.md)*
3. Train and compare multiple classifiers rather than assuming one. → *see [doc 04](04-model-training.md)*
4. Evaluate on held-out data with precision, recall, F1 and ROC-AUC — not accuracy alone. → *see [doc 08](08-results-and-evaluation.md)*
5. Make the decision **explainable**: a user should see *why* a URL was flagged, not just that it was.
6. Ship a working interface (CLI, JSON API, and a browser UI) so the system is demonstrable, not just a notebook.

## 1.7 Scope — what is explicitly out

Being clear about this matters more than it sounds; an examiner will ask.

| Out of scope | Why |
|---|---|
| Fetching and analysing page content | Defeats the speed and safety advantages that motivate the approach |
| WHOIS / domain-age lookups | Requires network access at inference time; breaks the latency target |
| Browser extension | A deployment concern, not a detection concern — noted in [doc 10](10-future-work.md) |
| Email header / sender analysis | A different problem (email authentication: SPF, DKIM, DMARC) |
| Real-time blocklist integration | Complementary, not what is being studied here |

## 1.8 Success criteria

The project is successful if:

- Accuracy and F1 exceed 0.90 on held-out data **that includes hard cases**
- Recall on the phishing class is high — missing a phishing site is far worse than over-flagging a safe one
- A single URL is scored in under 1 ms
- Every prediction comes with human-readable reasons
- Every number in the README is reproducible by running two commands

All five are met. The measured figures are in [doc 08](08-results-and-evaluation.md).

---

**Next:** [02 — Dataset](02-dataset.md)
