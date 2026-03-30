"""
Content analysis service using Sentence-BERT + Logistic Regression.
Classifies email content as phishing or safe.
"""
from models.schemas import ContentAnalysisResult
from ml.model_loader import model_loader
from config import settings


class ContentAnalyzer:
    """Sentence-BERT based phishing content classifier"""

    def __init__(self):
        self.model_path = settings.model_path
        self.encoder_path = settings.encoder_path
        self.model = None
        self.encoder = None
        self._load_model()

    def _load_model(self):
        self.model, self.encoder = model_loader.load_model(
            self.model_path, self.encoder_path
        )

    def is_model_available(self) -> bool:
        return self.model is not None and self.encoder is not None

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

        try:
            # 384-dim embedding → predict_proba
            embedding = self.encoder.encode([email_text])
            proba = self.model.predict_proba(embedding)[0]

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
