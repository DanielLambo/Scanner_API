"""
ML model loader with singleton pattern.
Loads Sentence-BERT encoder + calibrated ensemble classifiers.

SentenceTransformer is imported ONLY inside load_model() to prevent
tokenizer mutex deadlock in multi-threaded FastAPI contexts.
"""
import os
import pickle
from typing import List

import numpy as np


class ModelLoader:
    """Singleton loader for ensemble classifiers + SentenceTransformer."""

    _instance = None
    _encoder = None
    _clf_lr = None
    _clf_xgb = None
    _clf_lgbm = None
    _loaded = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def load_model(
        self,
        encoder_name_path: str,
        clf_lr_path: str,
        clf_xgb_path: str,
        clf_lgbm_path: str,
    ) -> bool:
        """
        Load SentenceTransformer and all three classifiers.

        SentenceTransformer is imported here (never at module level) to
        prevent tokenizer mutex deadlock.

        Returns True on success, False on failure.
        """
        if self._loaded:
            return True

        try:
            if not os.path.exists(encoder_name_path):
                print(f"Encoder name file not found: {encoder_name_path}")
                return False

            with open(encoder_name_path, "r") as f:
                encoder_name = f.read().strip()

            # Import inside function — prevents mutex deadlock
            from sentence_transformers import SentenceTransformer
            self._encoder = SentenceTransformer(encoder_name)

            for path, attr in [
                (clf_lr_path, "_clf_lr"),
                (clf_xgb_path, "_clf_xgb"),
                (clf_lgbm_path, "_clf_lgbm"),
            ]:
                if not os.path.exists(path):
                    print(f"Classifier not found: {path}")
                    return False
                with open(path, "rb") as f:
                    setattr(self, attr, pickle.load(f))

            self._loaded = True
            return True

        except Exception as e:
            print(f"Error loading model: {e}")
            return False

    def encode(self, text: str) -> np.ndarray:
        """Encode a single text into a 384-dim embedding (shape: (1, 384))."""
        return self._encoder.encode([text])

    def individual_probas(self, embedding: np.ndarray) -> List[np.ndarray]:
        """Return predict_proba from each of the 3 classifiers."""
        return [
            self._clf_lr.predict_proba(embedding),
            self._clf_xgb.predict_proba(embedding),
            self._clf_lgbm.predict_proba(embedding),
        ]

    def ensemble_predict_proba(self, embedding: np.ndarray) -> np.ndarray:
        """Soft-voting: average predict_proba across all three models."""
        probas = self.individual_probas(embedding)
        return np.mean(probas, axis=0)

    def is_loaded(self) -> bool:
        return self._loaded


# Singleton instance
model_loader = ModelLoader()
