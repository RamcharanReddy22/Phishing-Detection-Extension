# PhishDect — Real-Time Phishing Detection Extension

> A hybrid ML-powered browser extension that detects phishing URLs instantly — before the page loads.

🦊 **[Firefox — Live](https://addons.mozilla.org/en-US/firefox/addon/phishdect/)**  &nbsp;|&nbsp;  🌐 **[Live Demo](https://phishdect.ddns.net)**  &nbsp;|&nbsp;  🔵 Chrome — Coming Soon

---
## Screenshots

### Homepage
![Homepage](screenshots/homepage.png)

### Safe Website Detection
![Safe Detection](screenshots/safe-detection.png)

### Phishing Website Detection
![Phishing Detection](screenshots/phishing-detection.png)

### Community Reporting System
![Report Page](screenshots/report-page.png)

### Admin Panel
![Admin Panel](screenshots/admin-panel.png)

---

## What it does

- Checks every URL you visit against a trained XGBoost model in real time
- Returns a safety score (1–10) with ML confidence percentage
- Flags suspicious domains instantly — even if the site hasn't loaded
- Community reporting system for new phishing threats

---

## How it works

This is not a simple ML wrapper. It's a hybrid detection system:

| Layer | Method |
|---|---|
| ML Model | XGBoost trained on URL features |
| Text Analysis | TF-IDF character n-grams |
| URL Features | Length, special chars, subdomains, entropy |
| Rule Engine | Pattern-based heuristics |
| Domain Intel | WHOIS-based domain age lookup |
| Threat DB | Google Safe Browsing API |

---

## Architecture
Browser Extension (JS)
↓
Flask REST API  ←→  XGBoost Model + Feature Extractor
↓
AWS EC2 (HTTPS)
↓
Google Safe Browsing API + WHOIS

## Tech Stack

- **Backend:** Python, Flask, XGBoost, Scikit-learn
- **Extension:** JavaScript, Chrome/Firefox Extension API
- **Infrastructure:** AWS EC2, HTTPS, DDNS
- **APIs:** Google Safe Browsing, WHOIS lookup

---

## Performance

- 97% model accuracy
- <80ms API response time
- Live deployed at [phishdect.ddns.net](https://phishdect.ddns.net)

---

## Project Structure
backend/
├── app.py              # Flask REST API
├── features.py         # URL feature extraction
├── domain_features.py  # WHOIS domain intelligence
├── intelligence.py     # Threat scoring logic
├── model.pkl           # Trained XGBoost model
└── vectorizer.pkl      # TF-IDF vectorizer
extension/
├── manifest.json
├── popup.html
├── popup.js
└── background.js

## Setup

```bash
# Clone the repo
git clone https://github.com/RamcharanReddy22/Phishing-Detection-Extension.git

# Install dependencies
pip install -r requirements.txt

# Set API key
export SAFE_BROWSING_API_KEY=your_key_here

# Run backend
cd backend
python app.py
```

---

## Why I built this

Most ML projects stop at the model. I wanted to build something actually usable — a full system where ML, backend, and a browser extension work together in real time. This project taught me how production security tools are architected, not just how models are trained.

---

Built by [Ramcharan Reddy](https://github.com/RamcharanReddy22) 
