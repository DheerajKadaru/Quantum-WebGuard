from datetime import datetime, timezone
from functools import wraps

from flask import Blueprint, current_app, jsonify, redirect, render_template, request, session, url_for

from app.models.scan import Scan
from app.services.validators import is_valid_url, normalize_url


main_routes = Blueprint("main_routes", __name__)


def admin_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if session.get("role") != "admin":
            return redirect(url_for("admin_routes.login"))
        return view_func(*args, **kwargs)

    return wrapper


@main_routes.route("/")
def home():
    page = request.args.get("page", 1, type=int)
    per_page = current_app.config.get("SCANS_PER_PAGE", 20)

    total_scans = Scan.query.count()
    malicious = Scan.query.filter_by(final_prediction="Malicious").count()
    safe = Scan.query.filter_by(final_prediction="Safe").count()

    pagination = Scan.query.order_by(Scan.timestamp.desc()).paginate(
        page=page,
        per_page=per_page,
        error_out=False,
    )

    download_endpoint = "download" if "download" in current_app.view_functions else None

    stats = {
        "total_scans": total_scans,
        "malicious_scans": malicious,
        "safe_scans": safe,
    }
    return render_template(
        "index.html",
        stats=stats,
        scans=pagination.items,
        pagination=pagination,
        page_endpoint="main_routes.home",
        download_endpoint=download_endpoint,
        current_year=datetime.now(timezone.utc).year,
    )


@main_routes.route("/scan", methods=["POST"])
def scan_url():
    payload = request.get_json(silent=True) or {}
    raw_url = str(payload.get("url", "")).strip() or request.form.get("url", "").strip()

    normalized = normalize_url(raw_url)
    if not normalized:
        return jsonify({"error": "URL input cannot be empty."}), 400
    if not is_valid_url(normalized):
        return jsonify({"error": "Please provide a valid URL."}), 422

    detector = current_app.extensions["detector_service"]
    result = detector.scan_url(normalized)
    return jsonify(result), 200


@main_routes.route("/dashboard")
@admin_required
def dashboard():
    return redirect(url_for("main_routes.home"))


@main_routes.route("/history")
@admin_required
def history():
    return redirect(url_for("main_routes.home"))


@main_routes.route("/analytics")
@admin_required
def analytics():
    return redirect(url_for("main_routes.home"))
