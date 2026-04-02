"""
ML model loader with singleton pattern.
Loads Sentence-BERT encoder + calibrated classifiers.

By default only loads LR (low memory). Set FULL_ENSEMBLE=true to load all three.
SentenceTransformer is imported ONLY inside load_model() to prevent
tokenizer mutex deadlock in multi-threaded FastAPI contexts.
"""
import os
import pickle
from typing import List

import numpy as np


class ModelLoader:
    """Singleton loader for classifiers + SentenceTransformer."""

    _instance = None
    _encoder = None
    _clf_lr = None
    _clf_xgb = None
    _clf_lgbm = None
    _loaded = False
    _full_ensemble = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def load_model(
        self,
        encoder_name_path: str,
        clf_lr_path: str,
        clf_xgb_path: str = "",
        clf_lgbm_path: str = "",
        full_ensemble: bool = False,
    ) -> bool:
        """
        Load SentenceTransformer and classifiers.

        If full_ensemble is False (default), only LR is loaded (~50MB RAM).
        If full_ensemble is True, all three classifiers are loaded.

        Returns True on success, False on failure.
        """
        if self._loaded:
            return True

        self._full_ensemble = full_ensemble

        try:
            if not os.path.exists(encoder_name_path):
                print(f"Encoder name file not found: {encoder_name_path}")
                return False

            with open(encoder_name_path, "r") as f:
                encoder_name = f.read().strip()

            # Import inside function — prevents mutex deadlock
            from sentence_transformers import SentenceTransformer
            self._encoder = SentenceTransformer(encoder_name)

            # Always load LR
            if not os.path.exists(clf_lr_path):
                print(f"Classifier not found: {clf_lr_path}")
                return False
            with open(clf_lr_path, "rb") as f:
                self._clf_lr = pickle.load(f)

            # Optionally load XGB + LGBM
            if full_ensemble:
                for path, attr in [
                    (clf_xgb_path, "_clf_xgb"),
                    (clf_lgbm_path, "_clf_lgbm"),
                ]:
                    if not os.path.exists(path):
                        print(f"Classifier not found: {path}")
                        return False
                    with open(path, "rb") as f:
                        setattr(self, attr, pickle.load(f))
                print("Loaded full ensemble (LR + XGB + LGBM)")
            else:
                print("Loaded single model (LR only — low memory mode)")

            self._loaded = True
            return True

        except Exception as e:
            print(f"Error loading model: {e}")
            return False

    @property
    def is_full_ensemble(self) -> bool:
        return self._full_ensemble

    def encode(self, text: str) -> np.ndarray:
        """Encode a single text into a 384-dim embedding (shape: (1, 384))."""
        return self._encoder.encode([text])

    def individual_probas(self, embedding: np.ndarray) -> List[np.ndarray]:
        """Return predict_proba from each loaded classifier."""
        if self._full_ensemble:
            return [
                self._clf_lr.predict_proba(embedding),
                self._clf_xgb.predict_proba(embedding),
                self._clf_lgbm.predict_proba(embedding),
            ]
        return [self._clf_lr.predict_proba(embedding)]

    def ensemble_predict_proba(self, embedding: np.ndarray) -> np.ndarray:
        """Soft-voting: average predict_proba across loaded models."""
        probas = self.individual_probas(embedding)
        return np.mean(probas, axis=0)

    def is_loaded(self) -> bool:
        return self._loaded


# Singleton instance
model_loader = ModelLoader()
