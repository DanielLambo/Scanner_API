"""
ML Model Training Script
Trains a Random Forest classifier for phishing email detection
"""
import pandas as pd
import pickle
import os
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from imblearn.under_sampling import RandomUnderSampler


def train_model(dataset_path: str = "phishing_email.csv"):
    """
    Train the phishing detection model
    
    Args:
        dataset_path: Path to the CSV dataset with columns: Email Text, Email Type
    """
    print("Loading dataset...")
    
    # Check if dataset exists
    if not os.path.exists(dataset_path):
        print(f"Error: Dataset not found at {dataset_path}")
        print("Please download the dataset from:")
        print("https://drive.google.com/file/d/1f-qsFeoXt0i0H4yUbQuX5-oLcD_swzIY/view")
        print("Or provide your own dataset with columns: 'Email Text', 'Email Type'")
        return
    
    # Load dataset
    df = pd.read_csv(dataset_path)
    print(f"Dataset loaded: {len(df)} samples")
    
    # Check required columns
    if 'Email Text' not in df.columns or 'Email Type' not in df.columns:
        print("Error: Dataset must have 'Email Text' and 'Email Type' columns")
        return
    
    # Prepare features and labels
    X = df['Email Text']
    y = df['Email Type']
    
    print(f"\nClass distribution:")
    print(y.value_counts())
    
    # Apply undersampling for class balance
    print("\nApplying undersampling...")
    rus = RandomUnderSampler(random_state=42)
    X_indices = [[i] for i in range(len(X))]
    X_indices_resampled, y_resampled = rus.fit_resample(X_indices, y)
    
    # Get resampled data
    X_resampled = X.iloc[[i[0] for i in X_indices_resampled]]
    
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
    
    # Create TF-IDF vectorizer
    print("\nVectorizing text with TF-IDF...")
    vectorizer = TfidfVectorizer(max_features=5000, stop_words='english')
    X_train_tfidf = vectorizer.fit_transform(X_train)
    X_test_tfidf = vectorizer.transform(X_test)
    
    # Train Random Forest classifier
    print("\nTraining Random Forest classifier...")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        random_state=42,
        n_jobs=-1,
        verbose=1
    )
    clf.fit(X_train_tfidf, y_train)
    
    # Evaluate model
    print("\nEvaluating model...")
    y_pred = clf.predict(X_test_tfidf)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"\nAccuracy: {accuracy:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    # Save model and vectorizer
    print("\nSaving model and vectorizer...")
    os.makedirs("ml/models", exist_ok=True)
    
    with open("ml/models/classifier.pkl", "wb") as f:
        pickle.dump(clf, f)
    
    with open("ml/models/vectorizer.pkl", "wb") as f:
        pickle.dump(vectorizer, f)
    
    print("\n✅ Model training complete!")
    print("Model saved to: ml/models/classifier.pkl")
    print("Vectorizer saved to: ml/models/vectorizer.pkl")


if __name__ == "__main__":
    import sys
    
    # Get dataset path from command line or use default
    dataset_path = sys.argv[1] if len(sys.argv) > 1 else "phishing_email.csv"
    
    train_model(dataset_path)
