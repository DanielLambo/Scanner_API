"""
ML Model Training Script
Trains a Logistic Regression classifier on Sentence-BERT embeddings
for phishing email detection.

Usage:
    python ml/train_model.py
    python ml/train_model.py dataset/phishing_email.csv
"""
import os
import sys
import pickle

import numpy as np
import pandas as pd
from imblearn.under_sampling import RandomUnderSampler
from sentence_transformers import SentenceTransformer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split


def train_model(dataset_path: str = "dataset/phishing_email.csv"):
    if not os.path.exists(dataset_path):
        print(f"Error: dataset not found at {dataset_path}")
        return

    print("Loading dataset...")
    df = pd.read_csv(dataset_path)

    if "text_combined" not in df.columns or "label" not in df.columns:
        print(f"Error: expected 'text_combined' and 'label' columns, got: {df.columns.tolist()}")
        return

    df = df[["text_combined", "label"]].dropna()
    df["label"] = df["label"].astype(int)

    print(f"Loaded {len(df)} samples")
    print(df["label"].value_counts().to_string())

    # Balance classes
    print("\nApplying RandomUnderSampler...")
    indices = np.arange(len(df)).reshape(-1, 1)
    rus = RandomUnderSampler(random_state=42)
    indices_resampled, y_resampled = rus.fit_resample(indices, df["label"].values)
    df_resampled = df.iloc[indices_resampled.flatten()].copy()
    df_resampled["label"] = y_resampled
    print(f"After undersampling: {len(df_resampled)} samples")

    X = df_resampled["text_combined"].tolist()
    y = df_resampled["label"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\nTrain: {len(X_train)}  Test: {len(X_test)}")

    # Encode with Sentence-BERT
    print("\nLoading SentenceTransformer (all-MiniLM-L6-v2)...")
    encoder = SentenceTransformer("all-MiniLM-L6-v2")

    print("Encoding training set...")
    X_train_emb = encoder.encode(X_train, batch_size=64, show_progress_bar=True)

    print("Encoding test set...")
    X_test_emb = encoder.encode(X_test, batch_size=64, show_progress_bar=True)

    # Train Logistic Regression
    print("\nTraining LogisticRegression...")
    clf = LogisticRegression(max_iter=1000, C=1.0, random_state=42)
    clf.fit(X_train_emb, y_train)

    # Evaluate
    y_pred = clf.predict(X_test_emb)
    print("\nClassification Report (0=safe, 1=phishing):")
    print(classification_report(y_test, y_pred, target_names=["safe", "phishing"]))

    # Save
    os.makedirs("ml/models", exist_ok=True)
    with open("ml/models/classifier.pkl", "wb") as f:
        pickle.dump(clf, f)
    with open("ml/models/encoder.pkl", "wb") as f:
        pickle.dump(encoder, f)

    print("Saved ml/models/classifier.pkl")
    print("Saved ml/models/encoder.pkl")


if __name__ == "__main__":
    dataset_path = sys.argv[1] if len(sys.argv) > 1 else "dataset/phishing_email.csv"
    train_model(dataset_path)
