import math
from typing import Any, Dict

import joblib


class ModelLoader:
    """Loads model artifacts once and provides prediction + confidence."""

    def __init__(self, vectorizer_path: str, model_path: str) -> None:
        self.vectorizer = joblib.load(vectorizer_path)
        self.model = joblib.load(model_path)

    def predict_with_confidence(self, url: str) -> Dict[str, Any]:
        """Return class label and confidence score for a single URL."""
        features = self.vectorizer.transform([url])
        raw_prediction = int(self.model.predict(features)[0])

        if hasattr(self.model, "predict_proba"):
            probabilities = self.model.predict_proba(features)[0]
            confidence = float(probabilities[raw_prediction])
        elif hasattr(self.model, "decision_function"):
            score = float(self.model.decision_function(features)[0])
            confidence = 1.0 / (1.0 + math.exp(-abs(score)))
        else:
            confidence = 0.5

        label = "Malicious" if raw_prediction == 1 else "Safe"
        return {
            "prediction": label,
            "confidence_float": confidence,
            "confidence": f"{confidence * 100:.2f}%",
        }
