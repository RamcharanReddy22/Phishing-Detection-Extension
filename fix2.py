with open('app.py', 'r') as f:
    content = f.read()

content = content.replace(
    '''        try:
            log = ScanLog(url=result['url'], score=result['score'], status=result['status'], ml_confidence=result.get('ml_confidence'), domain_age=result.get('domain_age_days'))
            db.session.add(log)
            db.session.commit()
        except:
            pass''',
    '''        try:
            with app.app_context():
                log = ScanLog(url=result['url'], score=result['score'], status=result['status'], ml_confidence=result.get('ml_confidence'), domain_age=result.get('domain_age_days'))
                db.session.add(log)
                db.session.commit()
        except Exception as e:
            print("DB Error:", e)'''
)

with open('app.py', 'w') as f:
    f.write(content)

print("Done!")
