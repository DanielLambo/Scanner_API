"""
ML model loader with singleton pattern
"""
import pickle
import os
from typing import Optional, Tuple


class ModelLoader:
    """Singleton class for loading and caching ML models"""

    _instance = None
    _model = None
    _encoder = None
    _loaded = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ModelLoader, cls).__new__(cls)
        return cls._instance

    def load_model(self, model_path: str, encoder_path: str) -> Tuple[Optional[object], Optional[object]]:
        """
        Load the trained classifier and encoder

        Args:
            model_path: Path to the trained classifier pickle file
            encoder_path: Path to the encoder pickle file

        Returns:
            Tuple of (model, encoder) or (None, None) if not available
        """
        if self._loaded:
            return self._model, self._encoder

        try:
            if os.path.exists(model_path) and os.path.exists(encoder_path):
                with open(model_path, 'rb') as f:
                    self._model = pickle.load(f)

                with open(encoder_path, 'rb') as f:
                    self._encoder = pickle.load(f)

                self._loaded = True
                return self._model, self._encoder
            else:
                return None, None

        except Exception as e:
            print(f"Error loading model: {e}")
            return None, None

    def is_loaded(self) -> bool:
        """Check if model is loaded"""
        return self._loaded


# Singleton instance
model_loader = ModelLoader()
