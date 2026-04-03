"""
Content analysis service using TF-IDF + calibrated ensemble.
Classifies email content as phishing or safe.
Includes evasion detection (base64, CSS-hidden text, HTML comment injection).
"""
import os
import re
import base64
import pickle
from typing import Tuple, List, Optional

import numpy as np

from models.schemas import ContentAnalysisResult
from ml.model_loader import model_loader
from config import settings

try:
    from bs4 import BeautifulSoup
    _BS4_AVAILABLE = True
except ImportError:
    _BS4_AVAILABLE = False


# Phishing keywords used to flag suspicious HTML comment content
_PHISHING_KEYWORDS = {"verify", "account", "click", "suspend", "login", "password"}

# CSS property patterns that hide text from users
_HIDDEN_CSS_PATTERNS = [
    re.compile(r'display\s*:\s*none', re.IGNORECASE),
    re.compile(r'visibility\s*:\s*hidden', re.IGNORECASE),
    re.compile(r'color\s*:\s*white', re.IGNORECASE),
    re.compile(r'font-size\s*:\s*0', re.IGNORECASE),
    re.compile(r'opacity\s*:\s*0', re.IGNORECASE),
]


def _is_valid_utf8_text(data: bytes) -> bool:
    """Return True if data decodes to printable UTF-8 with no null bytes."""
    try:
        text = data.decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        return False
    if "\x00" in text:
        return False
    # Require mostly printable characters
    printable_count = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
    return len(text) > 0 and (printable_count / len(text)) >= 0.8


def preprocess_text(text: str) -> Tuple[str, List[str]]:
    """
    Preprocess email text to detect and neutralise evasion techniques.

    Handles:
    - Attack 1: Base64-encoded body chunks
    - Attack 2: CSS-hidden phishing text
    - Attack 3: HTML comment injection

    Returns:
        (cleaned_text, evasion_labels)
    """
    evasion_labels: List[str] = []
    result = text

    # ------------------------------------------------------------------ #
    # Attack 1 — Base64-encoded body                                       #
    # ------------------------------------------------------------------ #
    decoded_any = False

    # Check for "Content-Transfer-Encoding: base64" header pattern and
    # decode the entire body if present.
    cte_match = re.search(
        r'Content-Transfer-Encoding\s*:\s*base64\s*\n([\s\S]+)', result, re.IGNORECASE
    )
    if cte_match:
        encoded_body = cte_match.group(1).strip().replace("\n", "").replace("\r", "")
        try:
            raw = base64.b64decode(encoded_body + "==")
            if _is_valid_utf8_text(raw):
                decoded_body = raw.decode("utf-8")
                result = result[: cte_match.start(1)] + decoded_body
                decoded_any = True
        except Exception:
            pass

    # Detect and decode individual base64 chunks: [A-Za-z0-9+/]{20,}={0,2}
    b64_chunk_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')

    def _try_decode_chunk(m: re.Match) -> str:
        nonlocal decoded_any
        chunk = m.group(0)
        # Pad to multiple of 4
        padded = chunk + "=" * ((-len(chunk)) % 4)
        try:
            raw = base64.b64decode(padded)
            if _is_valid_utf8_text(raw):
                decoded_any = True
                return raw.decode("utf-8")
        except Exception:
            pass
        return chunk

    result = b64_chunk_pattern.sub(_try_decode_chunk, result)

    if decoded_any:
        evasion_labels.append("BASE64_ENCODED_BODY")

    # ------------------------------------------------------------------ #
    # Attack 3 — HTML comment injection (run BEFORE BS4 strips comments)  #
    # ------------------------------------------------------------------ #
    comment_pattern = re.compile(r'<!--(.*?)-->', re.DOTALL)
    comment_matches = comment_pattern.findall(result)

    suspicious_comments = False
    comment_texts: List[str] = []
    for comment in comment_matches:
        comment_texts.append(comment)
        # Check for URLs in comments
        if re.search(r'https?://', comment):
            suspicious_comments = True
        # Check for phishing keywords (case-insensitive)
        lower = comment.lower()
        if any(kw in lower for kw in _PHISHING_KEYWORDS):
            suspicious_comments = True

    if suspicious_comments:
        evasion_labels.append("HTML_COMMENT_INJECTION")

    # Replace <!--...--> markup with the inner text so BS4 sees it as plain text
    if comment_matches:
        result = comment_pattern.sub(lambda m: m.group(1), result)

    # ------------------------------------------------------------------ #
    # Attack 2 — CSS-hidden phishing text                                  #
    # ------------------------------------------------------------------ #
    if _BS4_AVAILABLE:
        soup = BeautifulSoup(result, "html.parser")
        hidden_texts: List[str] = []

        for tag in soup.find_all(style=True):
            style_value = tag.get("style", "")
            for pattern in _HIDDEN_CSS_PATTERNS:
                if pattern.search(style_value):
                    # Keep the hidden text but strip the hiding CSS property
                    hidden_texts.append(tag.get_text(separator=" "))
                    # Remove the CSS rule that hides the element
                    new_style = re.sub(
                        r'(?:display\s*:\s*none|visibility\s*:\s*hidden|'
                        r'color\s*:\s*white|font-size\s*:\s*0|opacity\s*:\s*0)\s*;?',
                        '',
                        style_value,
                        flags=re.IGNORECASE,
                    ).strip().rstrip(";")
                    if new_style:
                        tag["style"] = new_style
                    else:
                        del tag["style"]
                    break  # one match per tag is enough

        if hidden_texts:
            evasion_labels.append("CSS_HIDDEN_TEXT")

        # Extract all visible text via BeautifulSoup (includes previously hidden text
        # now that CSS rules have been stripped)
        visible_text = soup.get_text(separator=" ")

        # Append hidden text and comment text so the model sees all of it
        combined = visible_text
        extra_parts = []
        if hidden_texts:
            extra_parts.extend(hidden_texts)
        if comment_texts:
            extra_parts.extend(comment_texts)
        if extra_parts:
            combined = visible_text + " " + " ".join(extra_parts)
        result = combined
    else:
        # No BS4 — still append comment text
        if comment_texts:
            result = result + " " + " ".join(comment_texts)

    return result, evasion_labels


class ContentAnalyzer:
    """TF-IDF + LR/XGB/LGBM ensemble phishing classifier."""

    def __init__(self):
        self._shap_explainer = None
        self._load_model()

    def _load_model(self):
        model_loader.load_model(
            vectorizer_path=settings.vectorizer_path,
            clf_lr_path=settings.classifier_lr_path,
            clf_xgb_path=settings.classifier_xgb_path,
            clf_lgbm_path=settings.classifier_lgbm_path,
            full_ensemble=settings.full_ensemble,
        )
        if model_loader.is_loaded() and settings.full_ensemble and os.path.exists(settings.shap_explainer_path):
            try:
                with open(settings.shap_explainer_path, "rb") as f:
                    self._shap_explainer = pickle.load(f)
            except Exception as e:
                print(f"Warning: could not load SHAP explainer: {e}")

    def is_model_available(self) -> bool:
        return model_loader.is_loaded()

    def explain(self, text: str) -> List[dict]:
        """
        Return top-3 SHAP features driving the phishing prediction.

        Returns:
            [{"feature": "dim_42", "weight": 0.34}, ...]
        """
        if not self._shap_explainer or not model_loader.is_loaded():
            return []
        try:
            embedding = model_loader.encode(text)
            shap_vals = self._shap_explainer.shap_values(embedding)
            # LinearExplainer on binary LR: (1, 384) or list[2 x (1, 384)]
            if isinstance(shap_vals, list):
                vals = shap_vals[1][0]  # positive (phishing) class
            else:
                vals = shap_vals[0]
            top_indices = np.argsort(np.abs(vals))[-3:][::-1]
            return [
                {"feature": f"dim_{int(i)}", "weight": float(vals[i])}
                for i in top_indices
            ]
        except Exception:
            return []

    def analyze_content(self, email_text: str) -> Tuple[ContentAnalysisResult, List[str]]:
        """
        Preprocess and classify email text using the calibrated ensemble.

        Runs preprocess_text() first to detect evasion techniques, then feeds
        the cleaned text to the ensemble model.

        Returns:
            (ContentAnalysisResult, evasion_labels)
        """
        # Preprocess to detect evasion and clean text
        cleaned_text, evasion_labels = preprocess_text(email_text)

        if not self.is_model_available():
            return ContentAnalysisResult(
                prediction="Model Not Available",
                confidence=0.0,
                risk_score=0.0,
                is_phishing=False,
            ), evasion_labels

        try:
            embedding = model_loader.encode(cleaned_text)

            # Per-model phishing probabilities
            individual = model_loader.individual_probas(embedding)
            phishing_probs = [float(p[0, 1]) for p in individual]

            # Soft-vote ensemble (or single model)
            avg_proba = model_loader.ensemble_predict_proba(embedding)
            phishing_probability = float(avg_proba[0, 1])
            risk_score = phishing_probability * 100.0
            is_phishing = phishing_probability >= 0.5

            # Disagreement across models (0.0 in single model mode)
            if model_loader.is_full_ensemble:
                disagreement = float(max(phishing_probs) - min(phishing_probs))
                models_agree = disagreement < 0.3
            else:
                disagreement = 0.0
                models_agree = True

            explanation = self.explain(cleaned_text) or None

            return ContentAnalysisResult(
                prediction="Phishing Email" if is_phishing else "Safe Email",
                confidence=phishing_probability if is_phishing else float(avg_proba[0, 0]),
                risk_score=risk_score,
                is_phishing=is_phishing,
                ensemble_disagreement=disagreement,
                models_agree=models_agree,
                explanation=explanation,
                single_model_mode=not model_loader.is_full_ensemble,
            ), evasion_labels

        except Exception as e:
            return ContentAnalysisResult(
                prediction=f"Error: {str(e)}",
                confidence=0.0,
                risk_score=50.0,
                is_phishing=False,
            ), evasion_labels


# Singleton instance
content_analyzer = ContentAnalyzer()
