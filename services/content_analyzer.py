"""
Content analysis service using TF-IDF + Logistic Regression.
Classifies email content as phishing or safe.
"""
import os

from models.schemas import ContentAnalysisResult
from ml.model_loader import model_loader
from config import settings


class ContentAnalyzer:
    """TF-IDF based phishing content classifier"""

    def is_model_available(self) -> bool:
        return (
            os.path.exists(settings.model_path)
            and os.path.exists(settings.vectorizer_path)
        )

    def analyze_content(self, email_text: str) -> ContentAnalysisResult:
        """
        Classify email text as phishing or safe.

        Returns:
            ContentAnalysisResult with prediction, confidence, risk_score, is_phishing
        """
        if not self.is_model_available():
            return ContentAnalysisResult(
                prediction="Model Not Available",
                confidence=0.0,
                risk_score=0.0,
                is_phishing=False,
            )

        model, vectorizer = model_loader.load_model(
            settings.model_path, settings.vectorizer_path
        )
        if model is None or vectorizer is None:
            return ContentAnalysisResult(
                prediction="Model Not Available",
                confidence=0.0,
                risk_score=0.0,
                is_phishing=False,
            )

        try:
            # TF-IDF transform → predict_proba
            features = vectorizer.transform([email_text])
            proba = model.predict_proba(features)[0]

            # index 1 = phishing class
            phishing_probability = float(proba[1])
            risk_score = phishing_probability * 100.0
            is_phishing = phishing_probability >= 0.5

            return ContentAnalysisResult(
                prediction="Phishing Email" if is_phishing else "Safe Email",
                confidence=phishing_probability if is_phishing else float(proba[0]),
                risk_score=risk_score,
                is_phishing=is_phishing,
            )

        except Exception as e:
            return ContentAnalysisResult(
                prediction=f"Error: {str(e)}",
                confidence=0.0,
                risk_score=50.0,
                is_phishing=False,
            )


# Singleton instance
content_analyzer = ContentAnalyzer()
