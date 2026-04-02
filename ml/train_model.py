"""
ML Model Training Script
Trains a Logistic Regression classifier on Sentence-BERT embeddings for phishing email detection
"""
import pandas as pd
import pickle
import os
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from imblearn.under_sampling import RandomUnderSampler
from sentence_transformers import SentenceTransformer


def train_model(dataset_path: str = "phishing_email.csv"):
    """
    Train the phishing detection model

    Args:
        dataset_path: Path to the CSV dataset with columns: Body, Label
                      Label: 0 = safe, 1 = phishing
    """
    print("Loading dataset...")

    if not os.path.exists(dataset_path):
        print(f"Error: Dataset not found at {dataset_path}")
        print("Please provide a CSV with columns: 'Body', 'Label' (0=safe, 1=phishing)")
        return

    df = pd.read_csv(dataset_path)
    print(f"Dataset loaded: {len(df)} samples")

    if 'Body' not in df.columns or 'Label' not in df.columns:
        print("Error: Dataset must have 'Body' and 'Label' columns")
        return

    df = df.dropna(subset=['Body', 'Label'])
    X = df['Body'].astype(str)
    y = df['Label'].astype(int)

    print(f"\nClass distribution:")
    print(y.value_counts())

    # Apply undersampling for class balance
    print("\nApplying undersampling...")
    rus = RandomUnderSampler(random_state=42)
    X_indices = [[i] for i in range(len(X))]
    X_indices_resampled, y_resampled = rus.fit_resample(X_indices, y)

    X_resampled = X.iloc[[i[0] for i in X_indices_resampled]].reset_index(drop=True)
    y_resampled = list(y_resampled)

    print(f"After undersampling: {len(X_resampled)} samples")
    print(pd.Series(y_resampled).value_counts())

    # Split data
    print("\nSplitting data (80% train, 20% test)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X_resampled,
        y_resampled,
        test_size=0.2,
        random_state=42,
        stratify=y_resampled
    )

    # Encode with Sentence-BERT
    print("\nLoading Sentence-BERT encoder (all-MiniLM-L6-v2)...")
    encoder = SentenceTransformer("all-MiniLM-L6-v2")

    print("Encoding training set...")
    X_train_emb = encoder.encode(list(X_train), batch_size=64, show_progress_bar=True)

    print("Encoding test set...")
    X_test_emb = encoder.encode(list(X_test), batch_size=64, show_progress_bar=True)

    # Train Logistic Regression
    print("\nTraining Logistic Regression classifier...")
    clf = LogisticRegression(max_iter=1000, C=1.0)
    clf.fit(X_train_emb, y_train)

    # Evaluate
    print("\nEvaluating model...")
    y_pred = clf.predict(X_test_emb)

    print("\nClassification Report:")
    print(classification_report(
        y_test,
        y_pred,
        target_names=["safe (0)", "phishing (1)"]
    ))

    # Save model and encoder
    print("\nSaving model and encoder...")
    os.makedirs("ml/models", exist_ok=True)

    with open("ml/models/classifier.pkl", "wb") as f:
        pickle.dump(clf, f)

    with open("ml/models/encoder.pkl", "wb") as f:
        pickle.dump(encoder, f)

    print("\nModel training complete!")
    print("Classifier saved to: ml/models/classifier.pkl")
    print("Encoder saved to:    ml/models/encoder.pkl")


if __name__ == "__main__":
    import sys

    dataset_path = sys.argv[1] if len(sys.argv) > 1 else "phishing_email.csv"
    train_model(dataset_path)
