"""
Configuration management for Email Scanner API
Loads environment variables and provides centralized settings
"""
from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""

    # Testing mode (set to True to bypass API key authentication)
    testing_mode: bool = True  # Set to False in production

    # API Keys
    hunter_api_key: str = "##"
    virustotal_api_key: str = "##"
    api_key: str = "##"
    google_safe_browsing_key: str = "##"

    # Scoring weights (should sum to 1.0)
    scoring_weights_email: float = 0.3
    scoring_weights_url: float = 0.4
    scoring_weights_content: float = 0.3

    # API Configuration
    api_host: str = "0.0.0.0"
    api_port: int = 8000

    # Service Endpoints
    hunter_api_url: str = "https://api.hunter.io/v2/email-verifier"
    virustotal_api_url: str = "https://www.virustotal.com/api/v3/urls"

    # Timeouts (seconds)
    external_api_timeout: int = 30

    # ML Model paths (ensemble)
    encoder_name_path: str = "ml/models/encoder_name.txt"
    classifier_lr_path: str = "ml/models/classifier_lr.pkl"
    classifier_xgb_path: str = "ml/models/classifier_xgb.pkl"
    classifier_lgbm_path: str = "ml/models/classifier_lgbm.pkl"
    shap_explainer_path: str = "ml/models/shap_explainer.pkl"

    # If true, load all 3 classifiers (LR+XGB+LGBM). If false, LR only (~50MB).
    full_ensemble: bool = False

    # Database
    database_url: str = "sqlite+aiosqlite:///./scanner_feedback.db"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


# Singleton instance
settings = Settings()
