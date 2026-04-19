from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class ScanLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(2048), nullable=False)
    score = db.Column(db.Integer)
    status = db.Column(db.String(50))
    ml_confidence = db.Column(db.Float)
    domain_age = db.Column(db.Integer)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "url": self.url,
            "score": self.score,
            "status": self.status,
            "ml_confidence": self.ml_confidence,
            "domain_age": self.domain_age,
            "timestamp": self.timestamp.isoformat()
        }