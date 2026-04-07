import os
import json
from datetime import datetime
from typing import Dict, Tuple

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.svm import SVC


# =========================
# Configuration
# =========================

ARTIFACT_DIR = "artifacts"
VECTORIZER_PATH = os.path.join(ARTIFACT_DIR, "tfidf_vectorizer.joblib")
BEST_MODEL_PATH = os.path.join(ARTIFACT_DIR, "best_model.joblib")
METRICS_PATH = os.path.join(ARTIFACT_DIR, "model_metrics.json")
DATA_PATH = "dataset.xlsx"


# =========================
# Data Loading
# =========================

def load_dataset(path: str) -> Tuple[pd.Series, pd.Series]:
    if path.endswith(".xlsx"):
        df = pd.read_excel(path)
    else:
        df = pd.read_csv(path)
    
    col_map = {"URLs": "URLs", "Labels": "Labels", "url": "URLs", "label": "Labels"}
    for k, v in col_map.items():
        if k in df.columns and v not in df.columns:
            df = df.rename(columns={k: v})

    df = df.dropna(subset=["Labels", "URLs"])
    return df["URLs"].astype(str), df["Labels"].astype(int)


def split_dataset(urls: pd.Series, labels: pd.Series):
    return train_test_split(
        urls,
        labels,
        test_size=0.2,
        random_state=42,
        stratify=labels,
    )


# =========================
# Feature Engineering (SVC Core)
# =========================

def build_vectorizer() -> TfidfVectorizer:
    """Original TF-IDF character n-gram vectorizer."""
    return TfidfVectorizer(
        analyzer="char",
        ngram_range=(3, 6),
        max_features=50000,
    )


# =========================
# Model Training
# =========================

def train_svc(X_train, y_train) -> SVC:
    """Original Linear SVC model with probability enabled."""
    print("Training Linear SVC (Primary Prediction Engine)...")
    model = SVC(kernel="linear", probability=True, random_state=42)
    model.fit(X_train, y_train)
    return model


# =========================
# Evaluation
# =========================

def evaluate_model(model, X, y) -> Dict[str, float]:
    y_pred = model.predict(X)

    return {
        "accuracy": accuracy_score(y, y_pred),
        "precision": precision_score(y, y_pred, zero_division=0),
        "recall": recall_score(y, y_pred, zero_division=0),
        "f1": f1_score(y, y_pred, zero_division=0),
    }


# =========================
# Artifact Management
# =========================

def save_artifacts(vectorizer, model):
    os.makedirs(ARTIFACT_DIR, exist_ok=True)
    joblib.dump(vectorizer, VECTORIZER_PATH)
    joblib.dump(model, BEST_MODEL_PATH)


def save_metrics(metrics: Dict[str, float], model_name: str):
    os.makedirs(ARTIFACT_DIR, exist_ok=True)
    data = {
        "model": model_name,
        "accuracy": metrics["accuracy"],
        "precision": metrics["precision"],
        "recall": metrics["recall"],
        "f1": metrics["f1"],
        "trained_at": datetime.now().isoformat(),
    }
    with open(METRICS_PATH, "w") as f:
        json.dump(data, f, indent=4)


# =========================
# Main Training Pipeline
# =========================

def main():
    print("Loading dataset...")
    urls, labels = load_dataset(DATA_PATH)

    X_train_raw, X_test_raw, y_train, y_test = split_dataset(urls, labels)

    print("Fitting Vectorizer...")
    vectorizer = build_vectorizer()
    X_train = vectorizer.fit_transform(X_train_raw)
    X_test = vectorizer.transform(X_test_raw)

    model = train_svc(X_train, y_train)

    print("Evaluating SVC...")
    metrics = evaluate_model(model, X_test, y_test)
    print(f"SVC Metrics: Accuracy={metrics['accuracy']:.4f}, F1={metrics['f1']:.4f}")

    save_artifacts(vectorizer, model)
    save_metrics(metrics, "Linear SVC")

    print("SVC Model artifacts saved successfully.")


if __name__ == "__main__":
    main()