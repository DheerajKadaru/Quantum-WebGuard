from datetime import datetime, timezone

from app.extensions import db


class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.Text, nullable=False)
    ml_prediction = db.Column(db.String(20), nullable=False)
    rule_prediction = db.Column(db.String(20), nullable=False)
    final_prediction = db.Column(db.String(20), nullable=False)
    attack_type = db.Column(db.String(60), nullable=False, default="None")
    confidence = db.Column(db.Float, nullable=False, default=0.0)
    risk_score = db.Column(db.Float, nullable=False, default=0.0)
    timestamp = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
