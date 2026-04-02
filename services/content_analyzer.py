"""
Content analysis service using ML model
Classifies email content as phishing or safe
"""
from models.schemas import ContentAnalysisResult
from ml.model_loader import model_loader
from config import settings


class ContentAnalyzer:
    """ML-based content analysis service"""

    def __init__(self):
        self.model_path = settings.model_path
        self.encoder_path = settings.encoder_path
        self.model = None
        self.encoder = None
        self._load_model()

    def _load_model(self):
        """Load the trained classifier and encoder"""
        self.model, self.encoder = model_loader.load_model(
            self.model_path,
            self.encoder_path
        )

    def is_model_available(self) -> bool:
        """Check if model is loaded and available"""
        return self.model is not None and self.encoder is not None

    def analyze_content(self, email_text: str) -> ContentAnalysisResult:
        """
        Analyze email content for phishing indicators

        Args:
            email_text: Email content to analyze

        Returns:
            ContentAnalysisResult with classification
        """
        if not self.is_model_available():
            return ContentAnalysisResult(
                prediction="Model Not Available",
                confidence=0.0,
                risk_score=0.0,
                is_phishing=False
            )

        try:
            # Encode text to 384-dim Sentence-BERT embedding
            embedding = self.encoder.encode([email_text])

            # Get class probabilities; index 1 = phishing class
            prediction_proba = self.model.predict_proba(embedding)[0]
            phishing_probability = float(prediction_proba[1])

            is_phishing = phishing_probability >= 0.5
            confidence = phishing_probability if is_phishing else float(prediction_proba[0])
            risk_score = phishing_probability * 100.0
            prediction = "Phishing Email" if is_phishing else "Safe Email"

            return ContentAnalysisResult(
                prediction=prediction,
                confidence=confidence,
                risk_score=risk_score,
                is_phishing=is_phishing
            )

        except Exception as e:
            return ContentAnalysisResult(
                prediction=f"Error: {str(e)}",
                confidence=0.0,
                risk_score=50.0,
                is_phishing=False
            )


# Singleton instance
content_analyzer = ContentAnalyzer()
