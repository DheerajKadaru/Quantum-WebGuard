from flask import Blueprint, current_app, jsonify, request

from app.services.validators import is_valid_url, normalize_url


api_routes = Blueprint("api_routes", __name__, url_prefix="/api")


@api_routes.route("/predict", methods=["POST"])
def predict():
    if not request.is_json:
        return jsonify({"error": "Expected application/json body."}), 415

    payload = request.get_json(silent=True)
    if payload is None:
        return jsonify({"error": "Invalid JSON payload."}), 400

    raw_url = str(payload.get("url", "")).strip()
    normalized = normalize_url(raw_url)

    if not normalized:
        return jsonify({"error": "URL is required."}), 400
    if not is_valid_url(normalized):
        return jsonify({"error": "Invalid URL format."}), 422

    detector = current_app.extensions["detector_service"]
    result = detector.scan_url(normalized)

    return jsonify(
        {
            "prediction": result["prediction"],
            "confidence": result["confidence"],
            "attack_type": result["attack_type"],
            "risk_score": result["risk_score"],
            "timestamp": result["timestamp"],
        }
    )
