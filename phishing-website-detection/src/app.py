"""
app.py
------
A small Flask web interface so the detector can be demonstrated in a browser.

    python -m src.app          # then open http://127.0.0.1:5000

Two endpoints:
    GET  /            the HTML page with the input box
    POST /api/check   JSON API -> {"url": "..."}  returns the full result
"""

from __future__ import annotations

from flask import Flask, jsonify, render_template_string, request

from .predict import predict_one

app = Flask(__name__)

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Phishing Website Detection System</title>
<style>
  :root {
    --bg: #0f1720; --card: #17212b; --line: #24313d;
    --text: #e6edf3; --muted: #93a4b3; --accent: #4ea3ff;
    --safe: #2ea043; --danger: #e5534b; --warn: #d29922;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 32px 16px; background: var(--bg); color: var(--text);
    font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  }
  .wrap { max-width: 760px; margin: 0 auto; }
  h1 { font-size: 24px; margin: 0 0 6px; }
  .sub { color: var(--muted); margin: 0 0 28px; font-size: 14px; }
  form { display: flex; gap: 10px; flex-wrap: wrap; }
  input[type=url], input[type=text] {
    flex: 1 1 340px; padding: 12px 14px; border-radius: 8px;
    border: 1px solid var(--line); background: var(--card); color: var(--text);
    font-size: 15px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  }
  input:focus { outline: 2px solid var(--accent); outline-offset: 1px; }
  button {
    padding: 12px 22px; border-radius: 8px; border: 0; cursor: pointer;
    background: var(--accent); color: #04121f; font-weight: 650; font-size: 15px;
  }
  .card {
    margin-top: 26px; background: var(--card); border: 1px solid var(--line);
    border-radius: 12px; padding: 20px 22px;
  }
  .verdict { font-size: 20px; font-weight: 700; margin: 0 0 4px; }
  .verdict.safe { color: var(--safe); }
  .verdict.danger { color: var(--danger); }
  .url {
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px;
    color: var(--muted); word-break: break-all; margin-bottom: 16px;
  }
  .bar { height: 10px; border-radius: 6px; background: #0b1219; overflow: hidden; }
  .bar > div { height: 100%; border-radius: 6px; }
  .meta { display: flex; justify-content: space-between; font-size: 13px;
          color: var(--muted); margin-top: 7px; }
  h3 { font-size: 13px; text-transform: uppercase; letter-spacing: .07em;
       color: var(--muted); margin: 22px 0 8px; }
  ul { margin: 0; padding-left: 20px; }
  li { margin-bottom: 5px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  td { padding: 5px 0; border-bottom: 1px solid var(--line); }
  td:last-child { text-align: right;
                  font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  details summary { cursor: pointer; color: var(--muted); font-size: 13px; }
  .examples { margin-top: 18px; font-size: 13px; color: var(--muted); }
  .examples a { color: var(--accent); text-decoration: none; margin-right: 14px; }
  .err { color: var(--danger); }
</style>
</head>
<body>
<div class="wrap">
  <h1>Phishing Website Detection System</h1>
  <p class="sub">Machine-learning classifier over 28 lexical URL features. The page is never fetched, so checking a malicious link is safe.</p>

  <form method="post" action="/">
    <input type="text" name="url" placeholder="https://example.com/login"
           value="{{ url or '' }}" required autofocus>
    <button type="submit">Check URL</button>
  </form>

  <div class="examples">
    Try:
    <a href="/?url=https://www.google.com/search%3Fq%3Dpython">a safe one</a>
    <a href="/?url=http://paypal.com.secure-verify-login.tk/account/confirm.php">a phishing one</a>
  </div>

  {% if error %}<div class="card err">{{ error }}</div>{% endif %}

  {% if result %}
  {% set phishing = result.label == 'PHISHING' %}
  <div class="card">
    <p class="verdict {{ 'danger' if phishing else 'safe' }}">
      {{ 'Likely phishing' if phishing else 'Looks legitimate' }}
    </p>
    <p class="url">{{ result.url }}</p>

    <div class="bar">
      <div style="width: {{ (result.phishing_probability * 100) | round(1) }}%;
                  background: {{ '#e5534b' if phishing else '#2ea043' }};"></div>
    </div>
    <div class="meta">
      <span>{{ (result.phishing_probability * 100) | round(1) }}% phishing probability</span>
      <span>{{ result.confidence }} confidence</span>
    </div>

    {% if result.reasons %}
      <h3>Signals found</h3>
      <ul>{% for reason in result.reasons %}<li>{{ reason }}</li>{% endfor %}</ul>
    {% endif %}

    <h3>Feature values</h3>
    <details>
      <summary>Show all {{ result.features | length }} extracted features</summary>
      <table>
        {% for name, value in result.features.items() %}
        <tr><td>{{ name }}</td><td>{{ value }}</td></tr>
        {% endfor %}
      </table>
    </details>
  </div>
  {% endif %}
</div>
</body>
</html>
"""


@app.route("/", methods=["GET", "POST"])
def index():
    url = request.form.get("url") or request.args.get("url")
    result = None
    error = None

    if url:
        try:
            result = predict_one(url)
        except FileNotFoundError as exc:
            error = str(exc)

    return render_template_string(PAGE, url=url, result=result, error=error)


@app.route("/api/check", methods=["POST"])
def api_check():
    payload = request.get_json(silent=True) or {}
    url = payload.get("url")
    if not url:
        return jsonify({"error": "send JSON like {\"url\": \"https://...\"}"}), 400
    try:
        return jsonify(predict_one(url))
    except FileNotFoundError as exc:
        return jsonify({"error": str(exc)}), 503


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
