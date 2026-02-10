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
    _vectorizer = None
    _loaded = False
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ModelLoader, cls).__new__(cls)
        return cls._instance
    
    def load_model(self, model_path: str, vectorizer_path: str) -> Tuple[Optional[object], Optional[object]]:
        """
        Load the trained model and vectorizer
        
        Args:
            model_path: Path to the trained model pickle file
            vectorizer_path: Path to the vectorizer pickle file
            
        Returns:
            Tuple of (model, vectorizer) or (None, None) if not available
        """
        if self._loaded:
            return self._model, self._vectorizer
        
        try:
            if os.path.exists(model_path) and os.path.exists(vectorizer_path):
                with open(model_path, 'rb') as f:
                    self._model = pickle.load(f)
                
                with open(vectorizer_path, 'rb') as f:
                    self._vectorizer = pickle.load(f)
                
                self._loaded = True
                return self._model, self._vectorizer
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
