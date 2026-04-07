import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent


class Config:
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "change-this-secret")
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{BASE_DIR / 'scan_history.db'}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    ADMIN_DEFAULT_USERNAME = os.getenv("ADMIN_DEFAULT_USERNAME", "admin")
    ADMIN_DEFAULT_PASSWORD = os.getenv("ADMIN_DEFAULT_PASSWORD", "admin123")
    VECTORIZER_PATH = str(BASE_DIR / "tfidf_vectorizer.joblib")
    MODEL_PATH = str(BASE_DIR / "best_model.joblib")
    SCANS_PER_PAGE = 20
