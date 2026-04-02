"""
ML Model Training Script
Trains Sentence-BERT + calibrated ensemble (LR + XGBoost + LightGBM)
for phishing email detection.

Usage:
    python ml/train_model.py
    python ml/train_model.py phishing_email.csv
"""
import os
import sys
import pickle

import numpy as np
import pandas as pd
import shap
from imblearn.under_sampling import RandomUnderSampler
from sentence_transformers import SentenceTransformer
from sklearn.calibration import CalibratedClassifierCV
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, classification_report
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier


def train_model(dataset_path: str = "phishing_email.csv"):
    if not os.path.exists(dataset_path):
        print(f"Error: dataset not found at {dataset_path}")
        return

    print("Loading dataset...")
    df = pd.read_csv(dataset_path)

    # Support both column-name conventions
    if "text_combined" in df.columns and "label" in df.columns:
        text_col, label_col = "text_combined", "label"
    elif "Body" in df.columns and "Label" in df.columns:
        text_col, label_col = "Body", "Label"
    else:
        print(
            f"Error: expected 'text_combined'/'label' or 'Body'/'Label' columns, "
            f"got: {df.columns.tolist()}"
        )
        return

    df = df[[text_col, label_col]].dropna()
    df[label_col] = df[label_col].astype(int)

    print(f"Loaded {len(df)} samples")
    print(df[label_col].value_counts().to_string())

    # Balance classes
    print("\nApplying RandomUnderSampler...")
    indices = np.arange(len(df)).reshape(-1, 1)
    rus = RandomUnderSampler(random_state=42)
    indices_resampled, y_resampled = rus.fit_resample(indices, df[label_col].values)
    df_resampled = df.iloc[indices_resampled.flatten()].copy()
    df_resampled[label_col] = y_resampled
    print(f"After undersampling: {len(df_resampled)} samples")

    X = df_resampled[text_col].tolist()
    y = df_resampled[label_col].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\nTrain: {len(X_train)}  Test: {len(X_test)}")

    # ── Encode with Sentence-BERT ─────────────────────────────────────────
    print("\nLoading SentenceTransformer (all-MiniLM-L6-v2)...")
    encoder = SentenceTransformer("all-MiniLM-L6-v2")

    print("Encoding training set...")
    X_train_emb = encoder.encode(X_train, batch_size=64, show_progress_bar=True)

    print("Encoding test set...")
    X_test_emb = encoder.encode(X_test, batch_size=64, show_progress_bar=True)

    # ── Calibrated classifiers ────────────────────────────────────────────
    clf_lr = CalibratedClassifierCV(
        LogisticRegression(max_iter=1000, C=1.0, random_state=42),
        cv=3,
        method="isotonic",
    )
    clf_xgb = CalibratedClassifierCV(
        XGBClassifier(
            n_estimators=200,
            max_depth=6,
            learning_rate=0.1,
            eval_metric="logloss",
            n_jobs=-1,
            random_state=42,
        ),
        cv=3,
        method="isotonic",
    )
    clf_lgbm = CalibratedClassifierCV(
        LGBMClassifier(
            n_estimators=200,
            max_depth=6,
            learning_rate=0.1,
            n_jobs=-1,
            verbose=-1,
            random_state=42,
        ),
        cv=3,
        method="isotonic",
    )

    print("\nTraining LogisticRegression (calibrated)...")
    clf_lr.fit(X_train_emb, y_train)
    pred_lr = clf_lr.predict(X_test_emb)
    f1_lr = f1_score(y_test, pred_lr)
    print(f"  LR F1: {f1_lr:.4f}")

    print("\nTraining XGBoost (calibrated)...")
    clf_xgb.fit(X_train_emb, y_train)
    pred_xgb = clf_xgb.predict(X_test_emb)
    f1_xgb = f1_score(y_test, pred_xgb)
    print(f"  XGB F1: {f1_xgb:.4f}")

    print("\nTraining LightGBM (calibrated)...")
    clf_lgbm.fit(X_train_emb, y_train)
    pred_lgbm = clf_lgbm.predict(X_test_emb)
    f1_lgbm = f1_score(y_test, pred_lgbm)
    print(f"  LGBM F1: {f1_lgbm:.4f}")

    # ── Soft voting ensemble ──────────────────────────────────────────────
    proba_lr = clf_lr.predict_proba(X_test_emb)
    proba_xgb = clf_xgb.predict_proba(X_test_emb)
    proba_lgbm = clf_lgbm.predict_proba(X_test_emb)
    avg_proba = (proba_lr + proba_xgb + proba_lgbm) / 3.0
    pred_ensemble = (avg_proba[:, 1] >= 0.5).astype(int)
    f1_ensemble = f1_score(y_test, pred_ensemble)

    print(f"\nEnsemble F1: {f1_ensemble:.4f}")
    print("\nEnsemble Classification Report (0=safe, 1=phishing):")
    print(classification_report(y_test, pred_ensemble, target_names=["safe", "phishing"]))

    # ── SHAP explainer (LR is fastest; use estimator from first CV fold) ──
    print("Fitting SHAP LinearExplainer on LR...")
    lr_estimator = clf_lr.calibrated_classifiers_[0].estimator
    explainer = shap.LinearExplainer(lr_estimator, X_train_emb)

    # ── Save ──────────────────────────────────────────────────────────────
    os.makedirs("ml/models", exist_ok=True)

    with open("ml/models/encoder_name.txt", "w") as f:
        f.write("all-MiniLM-L6-v2")

    with open("ml/models/classifier_lr.pkl", "wb") as f:
        pickle.dump(clf_lr, f)

    with open("ml/models/classifier_xgb.pkl", "wb") as f:
        pickle.dump(clf_xgb, f)

    with open("ml/models/classifier_lgbm.pkl", "wb") as f:
        pickle.dump(clf_lgbm, f)

    with open("ml/models/shap_explainer.pkl", "wb") as f:
        pickle.dump(explainer, f)

    print("\nSaved:")
    print("  ml/models/encoder_name.txt")
    print("  ml/models/classifier_lr.pkl")
    print("  ml/models/classifier_xgb.pkl")
    print("  ml/models/classifier_lgbm.pkl")
    print("  ml/models/shap_explainer.pkl")


if __name__ == "__main__":
    dataset_path = sys.argv[1] if len(sys.argv) > 1 else "phishing_email.csv"
    train_model(dataset_path)
