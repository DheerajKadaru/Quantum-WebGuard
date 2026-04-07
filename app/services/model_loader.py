import math
from typing import Dict

import joblib


class ModelLoader:
    """Load and serve model artifacts once per app lifecycle."""

    def __init__(self, vectorizer_path: str, model_path: str) -> None:
        self.vectorizer = joblib.load(vectorizer_path)
        self.model = joblib.load(model_path)

    def predict_with_confidence(self, url: str) -> Dict[str, float | str]:
        features = self.vectorizer.transform([url])
        prediction_raw = int(self.model.predict(features)[0])

        if hasattr(self.model, "predict_proba"):
            probabilities = self.model.predict_proba(features)[0]
            confidence = float(probabilities[prediction_raw])
        elif hasattr(self.model, "decision_function"):
            decision = float(self.model.decision_function(features)[0])
            confidence = 1.0 / (1.0 + math.exp(-abs(decision)))
        else:
            confidence = 0.50

        prediction = "Malicious" if prediction_raw == 1 else "Safe"
        return {
            "prediction": prediction,
            "confidence": confidence,
            "confidence_text": f"{confidence * 100:.2f}%",
        }
