import math
import re
from urllib.parse import urlparse

import joblib
import pandas as pd

from rule_engine import RuleEngine
from utils import normalize_url, is_valid_url


class URLDetector:
    def __init__(self, vectorizer_path: str, model_path: str, confidence_threshold: float = 0.92) -> None:
        self.vectorizer = joblib.load(vectorizer_path)
        self.model = joblib.load(model_path)
        self.rule_engine = RuleEngine()
        self.confidence_threshold = confidence_threshold

    def analyze(self, raw_url: str) -> dict:
        normalized_url = normalize_url(raw_url)
        if not is_valid_url(normalized_url):
            raise ValueError("Invalid URL format. Please provide a valid URL.")

        # 1. Rule-Based & Trusted Overrides (Highest Priority)
        rule_result = self.rule_engine.classify(normalized_url)
        
        # Handle Trusted Domain (Source: Trusted Domain)
        if rule_result.get("source") == "Trusted Domain":
            return {
                "url": normalized_url,
                "prediction": "Safe",
                "final_prediction": "Safe",
                "confidence": 100.0,
                "source": "Trusted Domain",
                "attack_type": "None",
                "risk_score": 0.0,
                "reasoning": rule_result["reasoning"]
            }

        # Handle Numeric Spoofing (Source: Rule-Based)
        if rule_result.get("source") == "Rule-Based":
            return {
                "url": normalized_url,
                "prediction": "Unsafe",
                "final_prediction": "Malicious",
                "confidence": 100.0,
                "source": "Rule-Based",
                "attack_type": rule_result["attack_type"],
                "risk_score": 100.0,
                "reasoning": rule_result["reasoning"]
            }

        # 2. SVC Model Prediction (Primary System)
        features = self.vectorizer.transform([normalized_url])
        
        # Get raw prediction
        prediction_raw = int(self.model.predict(features)[0])
        
        # Calculate confidence from SVC
        if hasattr(self.model, "predict_proba"):
            probabilities = self.model.predict_proba(features)[0]
            confidence = float(probabilities[prediction_raw])
        elif hasattr(self.model, "decision_function"):
            decision = float(self.model.decision_function(features)[0])
            # Sigmoid normalization for decision function
            confidence = 1.0 / (1.0 + math.exp(-abs(decision)))
        else:
            confidence = 0.5

        # 3. Confidence Check & Fallback Logic
        if confidence >= self.confidence_threshold:
            # High confidence → SVC governs the verdict
            prediction_label = "Unsafe" if prediction_raw == 1 else "Safe"
            return {
                "url": normalized_url,
                "prediction": prediction_label,
                "final_prediction": "Malicious" if prediction_raw == 1 else "Safe",
                "confidence": round(confidence * 100, 2),
                "source": "SVC",
                "attack_type": "None" if prediction_raw == 0 else "Phishing", # Default for SVC
                "risk_score": round(confidence * 100, 2) if prediction_raw == 1 else round((1 - confidence) * 100, 2),
                "reasoning": f"SVC model identified this URL with high confidence ({confidence:.2%})."
            }
        else:
            # Low confidence or unknown pattern → Trigger Fallback Generalization
            # We use the rule engine's heuristic classification here
            fallback_prediction = "Likely Malicious" if rule_result["prediction"] == "Malicious" else "Likely Safe"
            
            return {
                "url": normalized_url,
                "prediction": fallback_prediction,
                "final_prediction": "Malicious" if rule_result["prediction"] == "Malicious" else "Safe",
                "confidence": round(confidence * 100, 2), # Show SVC confidence but mark result as fallback
                "source": "Heuristic Fallback",
                "attack_type": rule_result["attack_type"],
                "risk_score": rule_result["risk_score"],
                "reasoning": f"SVC confidence was low ({confidence:.2%}). Fallback logic applied: {rule_result['reasoning']}"
            }
