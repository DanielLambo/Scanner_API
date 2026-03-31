"""
ML model loader with singleton pattern.
Loads TF-IDF vectorizer and Logistic Regression classifier from pickle files.
"""
import os
import pickle
from typing import Optional, Tuple


class ModelLoader:
    """Singleton loader for classifier.pkl and vectorizer.pkl"""

    _instance = None
    _model = None
    _vectorizer = None
    _loaded = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def load_model(
        self, model_path: str, vectorizer_path: str
    ) -> Tuple[Optional[object], Optional[object]]:
        """
        Load classifier and vectorizer from pickle files.

        Returns:
            (classifier, vectorizer) or (None, None) if files are missing
        """
        if self._loaded:
            return self._model, self._vectorizer

        try:
            if not os.path.exists(model_path):
                print(f"Model not found: {model_path}")
                return None, None
            if not os.path.exists(vectorizer_path):
                print(f"Vectorizer not found: {vectorizer_path}")
                return None, None

            with open(model_path, "rb") as f:
                self._model = pickle.load(f)

            with open(vectorizer_path, "rb") as f:
                self._vectorizer = pickle.load(f)

            self._loaded = True
            return self._model, self._vectorizer

        except Exception as e:
            print(f"Error loading model: {e}")
            return None, None

    def is_loaded(self) -> bool:
        return self._loaded


# Singleton instance
model_loader = ModelLoader()
