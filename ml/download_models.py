"""
Download trained model files from HuggingFace Hub if not present locally.
Called during app startup so Render deployments get models automatically.

By default only downloads vectorizer.pkl + classifier_lr.pkl (low memory).
Set FULL_ENSEMBLE=true to download all 5 files.
"""
import os

from huggingface_hub import hf_hub_download

HF_REPO = "daniellambo7/scanner-api-models"
MODEL_DIR = "ml/models"

CORE_FILES = [
    "vectorizer.pkl",
    "classifier_lr.pkl",
]

EXTRA_FILES = [
    "classifier_xgb.pkl",
    "classifier_lgbm.pkl",
    "shap_explainer.pkl",
]


def download_models_if_missing():
    full_ensemble = os.environ.get("FULL_ENSEMBLE", "false").lower() == "true"
    files = CORE_FILES + EXTRA_FILES if full_ensemble else CORE_FILES

    os.makedirs(MODEL_DIR, exist_ok=True)
    missing = [f for f in files if not os.path.exists(f"{MODEL_DIR}/{f}")]
    if not missing:
        print("All models present, skipping download")
        return
    mode = "full ensemble" if full_ensemble else "LR only (low memory)"
    print(f"Downloading {len(missing)} model files from HuggingFace ({mode})...")
    for filename in missing:
        print(f"  Downloading {filename}...")
        hf_hub_download(
            repo_id=HF_REPO,
            filename=filename,
            local_dir=MODEL_DIR,
        )
    print("Models ready")
