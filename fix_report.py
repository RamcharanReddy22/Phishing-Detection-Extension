with open('app.py', 'r') as f:
    content = f.read()

# Add import at top
content = content.replace(
    'from db import db, ScanLog',
    'from db import db, ScanLog\nfrom sheets import log_report, get_report_count'
)

# Add report route before if __name__
content = content.replace(
    '@app.route("/logs")',
    '''@app.route("/report", methods=["POST"])
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

@app.route("/logs")'''
)

# Boost score if community reported
content = content.replace(
    '        if url in _cache:\n            return jsonify(_cache[url])',
    '''        if url in _cache:
            result = _cache[url].copy()
            from sheets import get_report_count
            reports = get_report_count(url)
            if reports >= 3:
                result['score'] = max(1, result['score'] - 3)
                result['status'] = 'Phishing'
                result['community_reports'] = reports
            return jsonify(result)'''
)

with open('app.py', 'w') as f:
    f.write(content)
print("Done!")
