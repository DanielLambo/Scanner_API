"""
TF-IDF based model training (replaces Sentence-BERT to eliminate PyTorch dependency).
Trains TF-IDF vectorizer + calibrated ensemble (LR + XGBoost + LightGBM).

Usage:
    python ml/train_tfidf_model.py
    python ml/train_tfidf_model.py phishing_train.csv
"""
import os
import sys
import pickle

import numpy as np
import pandas as pd
import shap
from imblearn.under_sampling import RandomUnderSampler
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, classification_report
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier


def train_model(dataset_path: str = "phishing_train.csv"):
    if not os.path.exists(dataset_path):
        print(f"Error: dataset not found at {dataset_path}")
        return

    print("Loading dataset...")
    df = pd.read_csv(dataset_path)

    if "text_combined" in df.columns and "label" in df.columns:
        text_col, label_col = "text_combined", "label"
    elif "Body" in df.columns and "Label" in df.columns:
        text_col, label_col = "Body", "Label"
    else:
        print(f"Error: expected columns not found, got: {df.columns.tolist()}")
        return

    df = df[[text_col, label_col]].dropna()
    df[label_col] = df[label_col].astype(int)

    print(f"Loaded {len(df)} samples")
    print(df[label_col].value_counts().to_string())

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

    # TF-IDF vectorizer (replaces Sentence-BERT — no PyTorch needed)
    print("\nFitting TF-IDF vectorizer...")
    vectorizer = TfidfVectorizer(
        max_features=5000,
        ngram_range=(1, 2),
        sublinear_tf=True,
        strip_accents="unicode",
        analyzer="word",
        min_df=2,
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)
    print(f"Vocabulary size: {len(vectorizer.vocabulary_)}")

    # Calibrated classifiers
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
    clf_lr.fit(X_train_vec, y_train)
    f1_lr = f1_score(y_test, clf_lr.predict(X_test_vec))
    print(f"  LR F1: {f1_lr:.4f}")

    print("\nTraining XGBoost (calibrated)...")
    clf_xgb.fit(X_train_vec.toarray(), y_train)
    f1_xgb = f1_score(y_test, clf_xgb.predict(X_test_vec.toarray()))
    print(f"  XGB F1: {f1_xgb:.4f}")

    print("\nTraining LightGBM (calibrated)...")
    clf_lgbm.fit(X_train_vec, y_train)
    f1_lgbm = f1_score(y_test, clf_lgbm.predict(X_test_vec))
    print(f"  LGBM F1: {f1_lgbm:.4f}")

    # Ensemble
    avg_proba = (
        clf_lr.predict_proba(X_test_vec)
        + clf_xgb.predict_proba(X_test_vec.toarray())
        + clf_lgbm.predict_proba(X_test_vec)
    ) / 3.0
    pred_ensemble = (avg_proba[:, 1] >= 0.5).astype(int)
    print(f"\nEnsemble F1: {f1_score(y_test, pred_ensemble):.4f}")
    print(classification_report(y_test, pred_ensemble, target_names=["safe", "phishing"]))

    # SHAP explainer on LR
    print("Fitting SHAP LinearExplainer on LR...")
    lr_estimator = clf_lr.calibrated_classifiers_[0].estimator
    # Use a sample for background to keep memory low
    bg_size = min(500, X_train_vec.shape[0])
    bg = X_train_vec[:bg_size]
    explainer = shap.LinearExplainer(lr_estimator, bg)

    # Save
    os.makedirs("ml/models", exist_ok=True)

    with open("ml/models/vectorizer.pkl", "wb") as f:
        pickle.dump(vectorizer, f)
    with open("ml/models/classifier_lr.pkl", "wb") as f:
        pickle.dump(clf_lr, f)
    with open("ml/models/classifier_xgb.pkl", "wb") as f:
        pickle.dump(clf_xgb, f)
    with open("ml/models/classifier_lgbm.pkl", "wb") as f:
        pickle.dump(clf_lgbm, f)
    with open("ml/models/shap_explainer.pkl", "wb") as f:
        pickle.dump(explainer, f)

    print("\nSaved:")
    for name in ["vectorizer.pkl", "classifier_lr.pkl", "classifier_xgb.pkl",
                 "classifier_lgbm.pkl", "shap_explainer.pkl"]:
        print(f"  ml/models/{name}")


if __name__ == "__main__":
    dataset_path = sys.argv[1] if len(sys.argv) > 1 else "phishing_train.csv"
    train_model(dataset_path)
