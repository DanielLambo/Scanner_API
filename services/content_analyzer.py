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
        self.vectorizer_path = settings.vectorizer_path
        self.model = None
        self.vectorizer = None
        self._load_model()
    
    def _load_model(self):
        """Load the trained model and vectorizer"""
        self.model, self.vectorizer = model_loader.load_model(
            self.model_path,
            self.vectorizer_path
        )
    
    def is_model_available(self) -> bool:
        """Check if model is loaded and available"""
        return self.model is not None and self.vectorizer is not None
    
    def analyze_content(self, email_text: str) -> ContentAnalysisResult:
        """
        Analyze email content for phishing indicators
        
        Args:
            email_text: Email content to analyze
            
        Returns:
            ContentAnalysisResult with classification
        """
        if not self.is_model_available():
            # Return safe result if model not available
            return ContentAnalysisResult(
                prediction="Model Not Available",
                confidence=0.0,
                risk_score=0.0,
                is_phishing=False
            )
        
        try:
            # Vectorize the text
            text_vectorized = self.vectorizer.transform([email_text])
            
            # Get prediction
            prediction = self.model.predict(text_vectorized)[0]
            
            # Get confidence scores
            prediction_proba = self.model.predict_proba(text_vectorized)[0]
            
            # Determine confidence (max probability)
            confidence = float(max(prediction_proba))
            
            # Check if phishing
            is_phishing = prediction == "Phishing Email"
            
            # Calculate risk score
            risk_score = self._calculate_risk_score(is_phishing, confidence)
            
            return ContentAnalysisResult(
                prediction=prediction,
                confidence=confidence,
                risk_score=risk_score,
                is_phishing=is_phishing
            )
            
        except Exception as e:
            # Return error result
            return ContentAnalysisResult(
                prediction=f"Error: {str(e)}",
                confidence=0.0,
                risk_score=50.0,
                is_phishing=False
            )
    
    def _calculate_risk_score(self, is_phishing: bool, confidence: float) -> float:
        """
        Calculate risk score from prediction
        
        Args:
            is_phishing: Whether classified as phishing
            confidence: Model confidence (0-1)
            
        Returns:
            Risk score (0-100)
        """
        if is_phishing:
            # Higher confidence = higher risk
            return confidence * 100.0
        else:
            # Lower confidence in "safe" = higher risk
            return (1 - confidence) * 100.0


# Singleton instance
content_analyzer = ContentAnalyzer()
