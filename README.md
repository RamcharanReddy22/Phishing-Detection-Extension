Phishing Detection Extension


Real-time phishing detection browser extension powered by a 5-layer hybrid ML pipeline. Live on Chrome and Firefox.



Live Backend: phishdect.ddns.net
Firefox Add-on: addons.mozilla.org/en-US/firefox/addon/phishdect


Why I built this

I wanted to go beyond training a model and leaving it as a notebook. This is a full system — ML, backend, and browser extension working together in real time, deployed on AWS with 24/7 uptime.


How it works

Every URL you visit is checked through 5 layers:

URL Input
    │
    ▼
Layer 1: Google Safe Browsing API      → known phishing/malware database
    │
    ▼
Layer 2: WHOIS Domain Age Check        → domains < 6 months = high risk
    │
    ▼
Layer 3: URL Feature Extraction        → 30+ hand-crafted features
         (length, subdomains, special chars, suspicious keywords, TLD, etc.)
    │
    ▼
Layer 4: TF-IDF (char n-grams)         → XGBoost classifier
         + hand-crafted features
    │
    ▼
Layer 5: Risk Score Fusion             → weighted combination → score 1–10
    │
    ▼
Browser Extension UI                   → green badge / warning / blocking popup

Accuracy: 96.4% on a 1,000-URL test set (TP=482, TN=479, FP=21, FN=18)


Why hybrid instead of just ML?

No single layer is enough:


Pure ML misses URLs already in known databases (Layer 1 catches these instantly)
ML alone can't detect brand-new phishing domains registered hours ago (Layer 2 catches these)
TF-IDF captures URL pattern signals that rule-based checks miss
Score fusion gives defense-in-depth — each layer covers the others' blind spots



Tech Stack

ComponentTechnologyML ModelXGBoost + TF-IDF (char n-grams)Feature Engineeringscikit-learn, custom extractorsDomain IntelligenceWHOIS, Google Safe Browsing APIBackendFlask, Gunicorn, Flask-SQLAlchemyDatabaseSQLite (scan logging)Community ReportingGoogle Sheets APIBrowser ExtensionJavaScript, Manifest V3DeploymentAWS EC2, Nginx, systemd, Let's Encrypt SSL


Project Structure

Phishing-Detection-Extension/
├── backend/
│   ├── app.py              # Flask API — main endpoint: POST /check_url
│   ├── features.py         # URL feature extraction (30+ features)
│   ├── domain_features.py  # WHOIS domain age lookup
│   ├── intelligence.py     # Google Safe Browsing API integration
│   ├── model.pkl           # Trained XGBoost model
│   └── vectorizer.pkl      # Fitted TF-IDF vectorizer
├── extension/
│   ├── manifest.json       # Chrome/Firefox Manifest V3
│   ├── popup.html          # Extension UI
│   ├── popup.js            # Handles user interaction + API call
│   └── background.js       # Tab URL change listener
└── requirements.txt


Setup & Run

Backend:

bashcd backend
pip install -r requirements.txt
export SAFE_BROWSING_API_KEY=your_key_here
python app.py

Load Extension in Chrome:


Go to chrome://extensions/
Enable Developer Mode
Click "Load unpacked" → select the extension/ folder


Firefox: Install directly from addons.mozilla.org
---
## Screenshots

### Homepage
![Homepage](screenshots/HOMEPAGE.png)

### Safe Website Detection
![Safe Detection](screenshots/POPUP-UI.png)

### Phishing Website Detection
![Phishing Detection](screenshots/Phishing-Detected-UI.png)

### Community Reporting System
![Report Page](screenshots/Report-Site.png)

### Admin Panel
![Admin Panel](screenshots/Admin-Dashboard.png)

---

Community Reporting

Users can report suspicious URLs directly from the extension popup. Reports are logged to Google Sheets via the Sheets API, and reported URLs get their risk score boosted for all users — crowdsourcing catches newly-emerging phishing sites before databases pick them up.


Deployment

Flask backend deployed on AWS EC2 (Ubuntu) with:


Gunicorn as WSGI server (multiple workers)
Nginx as reverse proxy with SSL termination
systemd service (phishsim) for 24/7 uptime
Let's Encrypt SSL — live at phishdect.ddns.net



Future Work


 Redis caching for WHOIS lookups (reduce 200-500ms latency)
 Visual similarity detection vs. top-1000 brand logos
 Levenshtein lookalike domain detection (e.g. paypa1.com vs paypal.com)
 User feedback loop + periodic model retraining
 Multilingual URL support (Telugu/Hindi)
 Manifest V3 full migration



Demo

LinkedIn Demo Post(https://www.linkedin.com/posts/ramcharan-reddy-5994402a3_cybersecurity-machinelearning-chromeextension-ugcPost-7448353586692112385-7eg4/?utm_source=share&utm_medium=member_desktop&rcm=ACoAAEk2p0UB3k_-e_CGd6FWjo_QAFsWaJjr5dY) 
