with open('app.py', 'r') as f:
    content = f.read()

content = content.replace(
    '''        if is_trusted(root_domain):
            result = {"url": url, "score": 10, "status": "Safe", "note": "Top trusted site"}
            _cache[url] = result
            return jsonify(result)''',
    '''        if is_trusted(root_domain):
            result = {"url": url, "score": 10, "status": "Safe", "note": "Top trusted site"}
            _cache[url] = result
            try:
                log = ScanLog(url=url, score=10, status="Safe", ml_confidence=0.0, domain_age=None)
                db.session.add(log)
                db.session.commit()
            except Exception as e:
                print("DB Error:", e)
            return jsonify(result)'''
)

with open('app.py', 'w') as f:
    f.write(content)

print("Done!")
