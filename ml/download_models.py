"""
Download trained model files from HuggingFace Hub if not present locally.
Called during app startup so Render deployments get models automatically.
"""
import os

from huggingface_hub import hf_hub_download

HF_REPO = "daniellambo7/scanner-api-models"
MODEL_DIR = "ml/models"
FILES = [
    "encoder_name.txt",
    "classifier_lr.pkl",
    "classifier_xgb.pkl",
    "classifier_lgbm.pkl",
    "shap_explainer.pkl",
]


def download_models_if_missing():
    os.makedirs(MODEL_DIR, exist_ok=True)
    missing = [f for f in FILES if not os.path.exists(f"{MODEL_DIR}/{f}")]
    if not missing:
        print("All models present, skipping download")
        return
    print(f"Downloading {len(missing)} model files from HuggingFace...")
    for filename in missing:
        print(f"  Downloading {filename}...")
        hf_hub_download(
            repo_id=HF_REPO,
            filename=filename,
            local_dir=MODEL_DIR,
        )
    print("Models ready")
