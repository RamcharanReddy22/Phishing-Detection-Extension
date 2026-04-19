from flask import Flask, request, jsonify
from flask_cors import CORS
from db import db, ScanLog
import joblib
import numpy as np
import re
import os
import csv
import io
import threading
import requests as req
from scipy.sparse import hstack, csr_matrix
from urllib.parse import urlparse
from features import extract_features
from intelligence import get_domain_age

app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scanlogs.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)
with app.app_context():
    db.create_all()

# ── Load model ────────────────────────────────────────────────────────────────
model = joblib.load("model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

# ── Google Safe Browsing API ──────────────────────────────────────────────────
SAFE_BROWSING_API_KEY = os.environ.get("SAFE_BROWSING_API_KEY", "")
SAFE_BROWSING_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}"

def check_safe_browsing(url):
    try:
        payload = {
            "client": {"clientId": "phishing-detector", "clientVersion": "2.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        resp = req.post(SAFE_BROWSING_URL, json=payload, timeout=5)
        data = resp.json()
        return "matches" in data and len(data["matches"]) > 0
    except Exception:
        return False

SKIP_SCHEMES = {"chrome", "chrome-extension", "edge", "about", "moz-extension", "file"}
ABUSE_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click", "link"}
_cache = {}

TRANCO_DOMAINS = set()
TRANCO_FILE = "tranco_top100k.txt"
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"

def load_tranco_from_file():
    global TRANCO_DOMAINS
    if os.path.exists(TRANCO_FILE):
        with open(TRANCO_FILE, "r") as f:
            TRANCO_DOMAINS = set(line.strip() for line in f if line.strip())
        print(f"✅ Loaded {len(TRANCO_DOMAINS)} trusted domains from Tranco cache")
        return True
    return False

def download_tranco():
    global TRANCO_DOMAINS
    try:
        print("🌐 Downloading Tranco top sites list...")
        import zipfile
        r = req.get(TRANCO_URL, timeout=30, stream=True)
        z = zipfile.ZipFile(io.BytesIO(r.content))
        csv_data = z.read("top-1m.csv").decode("utf-8")
        domains = set()
        reader = csv.reader(io.StringIO(csv_data))
        for i, row in enumerate(reader):
            if i >= 1000000:
                break
            if len(row) >= 2:
                domains.add(row[1].lower().strip())
        TRANCO_DOMAINS = domains
        with open(TRANCO_FILE, "w") as f:
            for d in domains:
                f.write(d + "\n")
        print(f"✅ Tranco list ready: {len(TRANCO_DOMAINS)} trusted domains")
    except Exception as e:
        print(f"⚠️ Could not download Tranco list: {e}. Continuing without it.")

if not load_tranco_from_file():
    threading.Thread(target=download_tranco, daemon=True).start()

def get_root_domain(domain):
    parts = domain.lstrip("www.").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain

def get_domain(url):
    return urlparse(url).netloc.lower()

def is_trusted(root_domain):
    return root_domain in TRANCO_DOMAINS

def rule_based_adjustments(url, parsed, domain, root_domain):
    penalty = 0.0
    if re.match(r"^\d+\.\d+\.\d+\.\d+(:\d+)?$", domain):
        penalty -= 0.5
    if parsed.scheme != "https":
        penalty -= 0.15
    if "@" in url:
        penalty -= 0.4
    tld = domain.split(".")[-1]
    if tld in ABUSE_TLDS:
        penalty -= 0.25
    subdomain_depth = max(0, domain.count(".") - 1)
    if subdomain_depth >= 3:
        penalty -= 0.2
    BRANDS = ["paypal", "amazon", "apple", "google", "microsoft", "netflix", "ebay", "bankof"]
    for brand in BRANDS:
        if brand in domain and brand not in root_domain:
            penalty -= 0.45
            break
    if "//" in parsed.path:
        penalty -= 0.15
    return max(-1.0, penalty)


@app.route("/analyze")
def analyze():
    url = request.args.get("url", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"})

    scheme = url.split(":")[0].lower()
    if scheme in SKIP_SCHEMES:
        return jsonify({"url": url, "score": 10, "status": "Safe", "note": "Internal page"})

    if url in _cache:
        return jsonify(_cache[url])

    try:
        parsed = urlparse(url)
        domain = get_domain(url)
        root_domain = get_root_domain(domain)

        if check_safe_browsing(url):
            result = {
                "url": url,
                "score": 1,
                "status": "Phishing",
                "note": "Flagged by Google Safe Browsing",
                "ml_confidence": 100.0,
                "domain_age_days": 0
            }
            _cache[url] = result
            return jsonify(result)

        if is_trusted(root_domain):
            result = {"url": url, "score": 10, "status": "Safe", "note": "Top trusted site"}
            _cache[url] = result
            try:
                log = ScanLog(url=url, score=10, status="Safe", ml_confidence=0.0, domain_age=None)
                db.session.add(log)
                db.session.commit()
            except Exception as e:
                print("DB Error:", e)
            return jsonify(result)

        X_text = vectorizer.transform([domain])
        extra = np.array([extract_features(url)])
        extra_sparse = csr_matrix(extra)
        X = hstack([X_text, extra_sparse])
        probs = model.predict_proba(X)[0]
        phishing_prob = float(probs[1])
        ml_safe_score = 1.0 - phishing_prob

        rule_penalty = rule_based_adjustments(url, parsed, domain, root_domain)

        age = get_domain_age(url)
        if age is None or age == 0:
            age_score = 0.6
        elif age < 30:
            age_score = 0.3
        elif age < 180:
            age_score = 0.7
        elif age < 365:
            age_score = 0.85
        else:
            age_score = 1.0

        combined = (
            ml_safe_score * 0.55 +
            age_score     * 0.15 +
            0.30
        ) + rule_penalty

        combined = max(0.0, min(1.0, combined))
        score = max(1, min(10, round(combined * 10)))

        if score <= 3 and rule_penalty < -0.3:
            status = "Phishing"
        elif score <= 5:
            status = "Suspicious"
        else:
            status = "Safe"

        result = {
            "url": url,
            "score": score,
            "status": status,
            "ml_confidence": round(phishing_prob * 100, 1),
            "domain_age_days": age
        }
        _cache[url] = result
        try:
            log = ScanLog(url=result['url'], score=result['score'], status=result['status'], ml_confidence=result.get('ml_confidence'), domain_age=result.get('domain_age_days'))
            db.session.add(log)
            db.session.commit()
        except Exception as e:
            print("DB Error:", e)
        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e), "url": url})


@app.route("/tranco_status")
def tranco_status():
    return jsonify({"loaded": len(TRANCO_DOMAINS), "ready": len(TRANCO_DOMAINS) > 0})


@app.route("/logs")
def logs():
    all_logs = ScanLog.query.order_by(ScanLog.timestamp.desc()).limit(100).all()
    return jsonify([l.to_dict() for l in all_logs])


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)