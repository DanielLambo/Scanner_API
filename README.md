# Scanner API

> Phishing detection infrastructure built on peer-reviewed research.
> NSF Funded · AAMU Cybersecurity Lab · Published in Springer · DEF CON Las Vegas

## Live API
- Base URL: https://scanner-api-st8w.onrender.com
- Docs: https://scanner-api-st8w.onrender.com/docs

## Quick Start

```bash
curl -X POST https://scanner-api-st8w.onrender.com/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "email_address": "support@paypa1.com",
    "email_text": "Your PayPal account has been compromised. Verify immediately.",
    "email_headers": "Authentication-Results: spf=fail; dkim=fail; dmarc=fail"
  }'
```

## Detection Layers

| Layer | Method | Signal |
|-------|--------|--------|
| 1 | Google Safe Browsing | Known malicious URLs |
| 2 | OpenPhish Feed | Community phishing URLs |
| 3 | DNSBL | IP/domain blocklists (Spamhaus, SURBL, URIBL) |
| 4 | ML Classifier | Sentence-BERT + calibrated ensemble |
| 5 | Header Analysis | SPF/DKIM/DMARC, Reply-To mismatch |
| 6 | URL Signals | Entropy, TLD rarity, homoglyph, digit ratio |
| 7 | Homoglyph Detection | Unicode confusables + Levenshtein |
| 8 | Domain Age | WHOIS registration date |

## Performance

| Metric | Safe | Phishing | Macro Avg |
|--------|------|----------|-----------|
| Precision | 0.93 | 0.99 | 0.96 |
| Recall | 0.99 | 0.93 | 0.96 |
| F1 | 0.96 | 0.96 | 0.96 |

## Architecture

The API receives an email (address + body + headers) and fans out to all 8 detection layers concurrently. Each layer returns a risk score (0–100). A weighted ensemble produces the final `scam_score`. Low-confidence scans are automatically queued for human review via the active learning loop.

## Local Setup

```bash
git clone https://github.com/DanielLambo/Scanner_API.git
cd Scanner_API
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # add your GOOGLE_SAFE_BROWSING_KEY
uvicorn app:app --reload
```

Train the model:
```bash
TOKENIZERS_PARALLELISM=false python3 ml/train_model.py phishing_train.csv
```

## Research

Developed at the Alabama A&M University Cybersecurity Research Lab with NSF support. Detection methodology peer-reviewed and published in Springer conference proceedings. System architecture presented at DEF CON, Las Vegas.

See [MODEL_CARD.md](MODEL_CARD.md) for full model documentation.

## License

MIT
