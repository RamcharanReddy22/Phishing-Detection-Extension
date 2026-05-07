from flask import Flask, request, jsonify
from flask_cors import CORS
from db import db, ScanLog
from sheets import log_report, get_report_count
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
from email_notifications import email_received, email_approved, email_rejected

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
    """
    Returns True if Google Safe Browsing flags the URL as dangerous.
    Returns False if safe or if the API call fails.
    """
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

# ── Internal/browser pages (skip analysis) ────────────────────────────────────
SKIP_SCHEMES = {"chrome", "chrome-extension", "edge", "about", "moz-extension", "file"}

# ── Suspicious TLDs ───────────────────────────────────────────────────────────
ABUSE_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click", "link"}

# ── In-memory cache ───────────────────────────────────────────────────────────
_cache = {}

# ── Tranco trusted domains ────────────────────────────────────────────────────
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

        # ── Google Safe Browsing (highest priority) ───────────────────────
        # If Google says it's dangerous, we trust Google — score 1, Phishing
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

        # ── Tranco trusted domain ─────────────────────────────────────────
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

        # ── ML score ──────────────────────────────────────────────────────
        X_text = vectorizer.transform([domain])
        extra = np.array([extract_features(url)])
        extra_sparse = csr_matrix(extra)
        X = hstack([X_text, extra_sparse])
        probs = model.predict_proba(X)[0]
        phishing_prob = float(probs[1])
        ml_safe_score = 1.0 - phishing_prob

        # ── Rule-based penalty ────────────────────────────────────────────
        rule_penalty = rule_based_adjustments(url, parsed, domain, root_domain)

        # ── Domain age ────────────────────────────────────────────────────
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


@app.route("/report", methods=["POST"])
def report():
    data = request.get_json()
    url = data.get("url", "").strip()
    note = data.get("note", "User reported")
    if not url:
        return jsonify({"error": "No URL provided"})
    success = log_report(url, "Phishing", note)
    # Invalidate cache so score recalculates with community boost
    if url in _cache:
        del _cache[url]
    return jsonify({"status": "reported", "success": success})

@app.route("/report_count")
def report_count():
    url = request.args.get("url", "").strip()
    count = get_report_count(url)
    return jsonify({"url": url, "reports": count})

@app.route("/logs")
def logs():
    all_logs = ScanLog.query.order_by(ScanLog.timestamp.desc()).limit(100).all()
    return jsonify([l.to_dict() for l in all_logs])
# ── ADD THESE TO YOUR EXISTING app.py ────────────────────────────────────────
# Paste this entire block at the bottom of your app.py (before if __name__ == "__main__")

import os
import uuid
import jwt as pyjwt
import datetime
from werkzeug.utils import secure_filename
from flask import send_from_directory

# ── CONFIG ────────────────────────────────────────────────────────────────────
ADMIN_PASSWORD = "Hanvisha@4888"   # 🔴 CHANGE THIS to a strong password!
JWT_SECRET     = "Hanvisha@4888"  # 🔴 CHANGE THIS too!
UPLOAD_FOLDER  = "/home/ubuntu/phishing_output/screenshots"
ALLOWED_EXT    = {"png", "jpg", "jpeg", "gif", "webp"}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ── REPORT MODEL (add to db.py or keep here) ──────────────────────────────────
# Use your existing db instance — just add this model

class WebReport(db.Model):
    __tablename__ = 'web_reports'
    id          = db.Column(db.Integer, primary_key=True)
    url         = db.Column(db.String(2048), nullable=False)
    note        = db.Column(db.Text)
    email       = db.Column(db.String(256))
    screenshot  = db.Column(db.String(512))   # filename
    status      = db.Column(db.String(32), default='pending')  # pending/approved/rejected
    timestamp   = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def to_dict(self):
        return {
            "id":         self.id,
            "url":        self.url,
            "note":       self.note,
            "email":      self.email,
            "screenshot": bool(self.screenshot),
            "status":     self.status,
            "timestamp":  self.timestamp.isoformat() if self.timestamp else None,
        }

# Run this once to create the table (already handled by db.create_all() in your app)


# ── HELPERS ───────────────────────────────────────────────────────────────────
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXT

def verify_token(request):
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return False
    token = auth[7:]
    try:
        pyjwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return True
    except Exception:
        return False


# ── ROUTES ────────────────────────────────────────────────────────────────────

@app.route('/report_web', methods=['POST'])
def report_web():
    """Receives report form submissions from the website."""
    url   = request.form.get('url', '').strip()
    note  = request.form.get('note', 'User report from website')
    email = request.form.get('email', '').strip()

    if not url:
        return jsonify({"error": "No URL"}), 400

    screenshot_filename = None
    if 'screenshot' in request.files:
        file = request.files['screenshot']
        if file and file.filename and allowed_file(file.filename):
            ext = file.filename.rsplit('.', 1)[1].lower()
            screenshot_filename = f"{uuid.uuid4().hex}.{ext}"
            file.save(os.path.join(UPLOAD_FOLDER, screenshot_filename))

    report = WebReport(url=url, note=note, email=email, screenshot=screenshot_filename)
    db.session.add(report)
    db.session.commit()
    if email:
    	email_received(email, url)
    # Also log to Google Sheet (reuse your existing function)
    try:
        log_report(url, "Pending", note)
    except Exception as e:
        print("Sheet log error:", e)

    return jsonify({"status": "reported", "id": report.id})


@app.route('/admin/login', methods=['POST'])
def admin_login():
    """Returns a JWT token if password is correct."""
    data = request.get_json()
    if data.get('password') == ADMIN_PASSWORD:
        token = pyjwt.encode(
            {"admin": True, "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=8)},
            JWT_SECRET, algorithm='HS256'
        )
        return jsonify({"token": token})
    return jsonify({"error": "Invalid password"}), 401


@app.route('/admin/reports', methods=['GET'])
def admin_reports():
    """Returns all web reports (admin only)."""
    if not verify_token(request):
        return jsonify({"error": "Unauthorized"}), 401
    reports = WebReport.query.order_by(WebReport.timestamp.desc()).all()
    return jsonify([r.to_dict() for r in reports])


@app.route('/admin/reports/<int:report_id>', methods=['PATCH'])
def update_report(report_id):
    """Approve or reject a report (admin only)."""
    if not verify_token(request):
        return jsonify({"error": "Unauthorized"}), 401
    data   = request.get_json()
    status = data.get('status')
    if status not in ('approved', 'rejected', 'pending'):
        return jsonify({"error": "Invalid status"}), 400
    report = WebReport.query.get_or_404(report_id)
    report.status = status
    db.session.commit()
    if report.email:
    	if status == 'approved':
        	email_approved(report.email, report.url)
    	elif status == 'rejected':
        	email_rejected(report.email, report.url)
    return jsonify({"ok": True, "id": report_id, "status": status})


@app.route('/admin/screenshot/<int:report_id>')
def get_screenshot(report_id):
    """Serves screenshot image (admin only — token in query param)."""
    token = request.args.get('token', '')
    try:
        pyjwt.decode(token, JWT_SECRET, algorithms=['HS256'])
    except Exception:
        return jsonify({"error": "Unauthorized"}), 401
    report = WebReport.query.get_or_404(report_id)
    if not report.screenshot:
        return jsonify({"error": "No screenshot"}), 404
    return send_from_directory(UPLOAD_FOLDER, report.screenshot)


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)

@app.route('/blocklist')
def blocklist():
    approved = WebReport.query.filter_by(status='approved').all()
    urls = [r.url for r in approved]
    return jsonify({"urls": urls, "count": len(urls)})

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
