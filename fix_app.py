with open('app.py', 'r') as f:
    content = f.read()

content = content.replace('from flask_cors import CORS', 'from flask_cors import CORS\nfrom db import db, ScanLog')

content = content.replace("CORS(app)", """CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scanlogs.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)
with app.app_context():
    db.create_all()""")

content = content.replace("_cache[url] = result\n        return jsonify(result)", """_cache[url] = result
        try:
            log = ScanLog(url=result['url'], score=result['score'], status=result['status'], ml_confidence=result.get('ml_confidence'), domain_age=result.get('domain_age_days'))
            db.session.add(log)
            db.session.commit()
        except:
            pass
        return jsonify(result)""")

content = content.replace('if __name__ == "__main__"', '''@app.route("/logs")
def logs():
    all_logs = ScanLog.query.order_by(ScanLog.timestamp.desc()).limit(100).all()
    return jsonify([l.to_dict() for l in all_logs])

if __name__ == "__main__"''')

with open('app.py', 'w') as f:
    f.write(content)

print("Done!")
