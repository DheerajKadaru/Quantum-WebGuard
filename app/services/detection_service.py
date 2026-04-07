from datetime import datetime, timezone
from typing import Dict

from app.models.scan import Scan
from app.services.rule_engine import RuleEngine


class DetectionService:
    """Orchestrates ML and rule engine to produce a final verdict."""

    def __init__(self, model_loader, db) -> None:
        self.model_loader = model_loader
        self.db = db
        self.rule_engine = RuleEngine()

    def scan_url(self, url: str) -> Dict[str, str | float]:
        ml_result = self.model_loader.predict_with_confidence(url)
        rule_result = self.rule_engine.classify(url)

        if rule_result.high_risk and rule_result.prediction == "Malicious":
            final_prediction = "Malicious"
            attack_type = rule_result.attack_type
            risk_score = max(rule_result.risk_score, ml_result["confidence"] * 100)
        else:
            final_prediction = ml_result["prediction"]
            attack_type = rule_result.attack_type if rule_result.attack_type != "None" else "None"
            risk_score = max(rule_result.risk_score, ml_result["confidence"] * 100)

        record = Scan(
            url=url,
            ml_prediction=ml_result["prediction"],
            rule_prediction=rule_result.prediction,
            final_prediction=final_prediction,
            attack_type=attack_type,
            confidence=float(ml_result["confidence"]),
            risk_score=float(min(100.0, risk_score)),
            timestamp=datetime.now(timezone.utc),
        )
        self.db.session.add(record)
        self.db.session.commit()

        return {
            "scan_id": record.id,
            "prediction": final_prediction,
            "confidence": f"{float(ml_result['confidence']) * 100:.2f}%",
            "confidence_value": round(float(ml_result["confidence"]) * 100, 2),
            "attack_type": attack_type,
            "risk_score": round(float(record.risk_score), 2),
            "timestamp": record.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
        }
