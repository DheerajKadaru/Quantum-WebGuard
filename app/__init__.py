from pathlib import Path

from flask import Flask, jsonify, render_template, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from app.blueprints import admin_routes, api_routes, main_routes
from app.config import Config
from app.extensions import db
from app.models.user import User
from app.services.detection_service import DetectionService
from app.services.model_loader import ModelLoader


def create_app() -> Flask:
    project_root = Path(__file__).resolve().parent.parent
    app = Flask(
        __name__,
        template_folder=str(project_root / "templates"),
        static_folder=str(project_root / "static"),
    )
    app.config.from_object(Config)

    db.init_app(app)

    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["120 per hour", "30 per minute"],
    )
    app.extensions["limiter"] = limiter

    model_loader = ModelLoader(
        app.config["VECTORIZER_PATH"],
        app.config["MODEL_PATH"],
    )
    detector_service = DetectionService(model_loader=model_loader, db=db)
    app.extensions["detector_service"] = detector_service

    with app.app_context():
        db.create_all()
        _seed_default_admin(app)

    app.register_blueprint(main_routes)
    app.register_blueprint(admin_routes)
    app.register_blueprint(api_routes)

    register_error_handlers(app)
    return app


def _seed_default_admin(app: Flask) -> None:
    admin = User.query.filter_by(username=app.config["ADMIN_DEFAULT_USERNAME"]).first()
    if admin:
        return

    admin = User(username=app.config["ADMIN_DEFAULT_USERNAME"], role="admin")
    admin.set_password(app.config["ADMIN_DEFAULT_PASSWORD"])
    db.session.add(admin)
    db.session.commit()


def register_error_handlers(app: Flask) -> None:
    @app.errorhandler(400)
    def bad_request(error):
        return _error_response(400, "Bad request.")

    @app.errorhandler(404)
    def not_found(error):
        return _error_response(404, "Page not found.")

    @app.errorhandler(429)
    def rate_limited(error):
        return jsonify({"error": "Rate limit exceeded. Try again later."}), 429

    @app.errorhandler(500)
    def server_error(error):
        return _error_response(500, "Internal server error.")



def _error_response(code: int, message: str):
    if request.path.startswith("/api"):
        return jsonify({"error": message}), code
    return render_template("error.html", message=message, status_code=code), code
