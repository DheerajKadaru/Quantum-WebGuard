import os
import json
from dotenv import load_dotenv
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path

from flask import Flask, abort, redirect, render_template, request, send_file, url_for
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

from detector import URLDetector
from models import Scan, db


load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
METRICS_PATH = BASE_DIR / "artifacts" / "model_metrics.json"


def _load_metrics() -> dict | None:
    try:
        with open(METRICS_PATH) as f:
            return json.load(f)
    except Exception:
        return None


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    
    # Environment variable configuration for production
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-key-for-local-use")
    
    # Connect to external Database if provided (e.g., Neon Postgres), else use local SQLite
    database_url = os.environ.get("DATABASE_URL")
    if database_url and database_url.startswith("postgres://"):
        # Fix for SQLAlchemy requiring 'postgresql://' instead of 'postgres://'
        database_url = database_url.replace("postgres://", "postgresql://", 1)
        
    app.config["SQLALCHEMY_DATABASE_URI"] = database_url or f"sqlite:///{BASE_DIR / 'database.db'}"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SCANS_PER_PAGE"] = 20

    db.init_app(app)

    detector = URLDetector(
        vectorizer_path=str(BASE_DIR / "artifacts" / "tfidf_vectorizer.joblib"),
        model_path=str(BASE_DIR / "artifacts" / "best_model.joblib"),
    )
    app.extensions["detector"] = detector

    with app.app_context():
        db.create_all()

    register_routes(app)
    register_error_handlers(app)
    return app


def register_routes(app: Flask) -> None:
    def _get_stats() -> dict:
        total = Scan.query.count()
        malicious = Scan.query.filter_by(final_prediction="Malicious").count()
        safe = Scan.query.filter_by(final_prediction="Safe").count()
        return {
            "total_scans": total,
            "malicious_scans": malicious,
            "safe_scans": safe,
        }

    @app.get("/")
    def home():
        stats = _get_stats()
        metrics = _load_metrics()
        return render_template(
            "index.html",
            active_page="home",
            stats=stats,
            metrics=metrics,
            current_year=datetime.now(timezone.utc).year,
        )

    @app.post("/scan")
    def scan_url():
        payload = request.get_json(silent=True) or {}
        raw_url = str(payload.get("url", "")).strip()
        detector: URLDetector = app.extensions["detector"]

        if not raw_url:
            return {"error": "Please enter a URL."}, 400

        try:
            result = detector.analyze(raw_url)
            scan = Scan(
                url=result["url"],
                final_prediction=result["final_prediction"],
                confidence=result["confidence"],
                attack_type=result["attack_type"],
                risk_score=result["risk_score"],
                source=result["source"],
                reasoning=result["reasoning"]
            )
            db.session.add(scan)
            db.session.commit()
            return {
                "scan_id": scan.id,
                "url": result["url"],
                "prediction": result["prediction"],
                "confidence": f"{result['confidence']:.2f}%",
                "attack_type": result["attack_type"],
                "risk_score": result["risk_score"],
                "source": result["source"],
                "reasoning": result["reasoning"],
                "timestamp": scan.timestamp.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            }, 200
        except ValueError as exc:
            return {"error": str(exc)}, 422
        except Exception:
            db.session.rollback()
            return {"error": "Unexpected error during analysis. Please try again."}, 500

    @app.route("/analyze", methods=["GET", "POST"])
    def analyze():
        return render_template(
            "analyze.html",
            active_page="analyze",
            current_year=datetime.now(timezone.utc).year,
        )

    @app.get("/results")
    def results():
        page = request.args.get("page", default=1, type=int)
        per_page = app.config["SCANS_PER_PAGE"]
        stats = _get_stats()
        pagination = Scan.query.order_by(Scan.timestamp.desc()).paginate(
            page=page, per_page=per_page, error_out=False,
        )
        return render_template(
            "results.html",
            active_page="results",
            stats=stats,
            scans=pagination.items,
            pagination=pagination,
            download_endpoint="download",
            current_year=datetime.now(timezone.utc).year,
        )

    @app.get("/about")
    def about():
        metrics = _load_metrics()
        return render_template(
            "about.html",
            active_page="about",
            metrics=metrics,
            current_year=datetime.now(timezone.utc).year,
        )

    @app.get("/download/<int:scan_id>")
    def download(scan_id: int):
        scan = Scan.query.get(scan_id)
        if scan is None:
            abort(404)

        pdf_buffer = BytesIO()
        pdf = canvas.Canvas(pdf_buffer, pagesize=A4)
        width, height = A4
        y = height - 60

        pdf.setTitle(f"scan_report_{scan_id}")
        pdf.setFont("Helvetica-Bold", 18)
        pdf.drawString(48, y, "Malicious URL Detection Report")
        y -= 34

        pdf.setFont("Helvetica", 12)
        lines = [
            "System Name: Hybrid URL Detection System",
            f"URL: {scan.url}",
            f"Final Prediction: {scan.final_prediction}",
            f"Confidence: {scan.confidence:.2f}%",
            f"Attack Type: {scan.attack_type}",
            f"Risk Score: {scan.risk_score:.2f}",
            f"Timestamp: {scan.timestamp.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        ]

        for line in lines:
            pdf.drawString(48, y, line)
            y -= 24

        pdf.showPage()
        pdf.save()
        pdf_buffer.seek(0)

        return send_file(
            pdf_buffer,
            as_attachment=True,
            download_name=f"scan_report_{scan.id}.pdf",
            mimetype="application/pdf",
        )

    @app.get("/admin")
    @app.get("/admin/login")
    def removed_admin_redirect():
        return redirect(url_for("home"))


def register_error_handlers(app: Flask) -> None:
    @app.errorhandler(404)
    def not_found(_):
        return render_template("error.html", message="Page not found.", status_code=404, active_page=""), 404

    @app.errorhandler(500)
    def internal_error(_):
        return (
            render_template(
                "error.html",
                message="Internal server error. Please try again later.",
                status_code=500,
                active_page="",
            ),
            500,
        )


app = create_app()


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
