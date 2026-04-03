"""
ML model loader with singleton pattern.
Loads TF-IDF vectorizer + calibrated classifiers (no PyTorch/sentence-transformers).

By default only loads LR (low memory). Set FULL_ENSEMBLE=true to load all three.
"""
import os
import pickle
from typing import List

import numpy as np
from scipy.sparse import issparse


class ModelLoader:
    """Singleton loader for TF-IDF vectorizer + classifiers."""

    _instance = None
    _vectorizer = None
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
        vectorizer_path: str,
        clf_lr_path: str,
        clf_xgb_path: str = "",
        clf_lgbm_path: str = "",
        full_ensemble: bool = False,
    ) -> bool:
        """
        Load TF-IDF vectorizer and classifiers.

        If full_ensemble is False (default), only LR is loaded (~low RAM).
        If full_ensemble is True, all three classifiers are loaded.

        Returns True on success, False on failure.
        """
        if self._loaded:
            return True

        self._full_ensemble = full_ensemble

        try:
            if not os.path.exists(vectorizer_path):
                print(f"Vectorizer not found: {vectorizer_path}")
                return False
            with open(vectorizer_path, "rb") as f:
                self._vectorizer = pickle.load(f)

            if not os.path.exists(clf_lr_path):
                print(f"Classifier not found: {clf_lr_path}")
                return False
            with open(clf_lr_path, "rb") as f:
                self._clf_lr = pickle.load(f)

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
        """Vectorize a single text via TF-IDF. Returns dense array."""
        vec = self._vectorizer.transform([text])
        # XGB needs dense; LR/LGBM handle sparse — return dense for compatibility
        if issparse(vec):
            return vec.toarray()
        return vec

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
