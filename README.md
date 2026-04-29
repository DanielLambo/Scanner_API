# PhishNet API

> Phishing detection infrastructure built on peer-reviewed research.
> NSF Funded · AAMU Cybersecurity Lab · Published in Springer · SAM'25 Las Vegas

## Live API
- Base URL: https://scanner-api-st8w.onrender.com
- Docs: https://scanner-api-st8w.onrender.com/docs

## Quick Start

All scan endpoints require an `X-API-Key` header. Request access: daniel.lambo@bulldogs.aamu.edu

```bash
curl -X POST https://scanner-api-st8w.onrender.com/api/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "email_address": "support@paypa1.com",
    "email_text": "Your PayPal account has been compromised. Verify immediately.",
    "email_headers": "Authentication-Results: spf=fail; dkim=fail; dmarc=fail"
  }'
```

## Rate Limits

Limits are enforced **per API key** (not per IP), so researchers behind shared networks don't compete.

| Endpoint | Limit |
|----------|-------|
| `POST /api/scan` | 10 / minute |
| `POST /api/scan/urls` | 20 / minute |
| `POST /api/scan/content` | 20 / minute |
| `POST /api/scan/email-address` | 20 / minute |
| `GET /health`, `/docs` | unlimited |
| `POST /admin/*` | 30 / minute |

A `429` response returns:
```json
{"error":"Rate limit exceeded","message":"...","retry_after":"60 seconds"}
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

## Production Deployment

The API runs on Render. Two environment variables control persistence:

| Variable | Required | Purpose |
|----------|----------|---------|
| `DATABASE_URL` | Recommended | Postgres connection string. Defaults to local SQLite (wiped on every Render redeploy). Set to a managed Postgres (Neon, Supabase, Render PG) for durable storage. The app auto-converts `postgresql://` to the asyncpg driver and strips `?sslmode`. |
| `BOOTSTRAP_API_KEYS` | Recommended | JSON array of keys to ensure exist on every startup. Idempotent. Used to restore handed-out keys after a SQLite wipe and to provision research keys without admin calls. |
| `ADMIN_KEY` | Required for `/admin/*` | Header-validated key for admin endpoints. |
| `GOOGLE_SAFE_BROWSING_KEY` | Optional | Enables GSB lookups. Without it, that layer no-ops. |

**`BOOTSTRAP_API_KEYS` format:**
```json
[
  {"key":"phishnet_xxx","owner_email":"user@example.com","owner_name":"Name","tier":"research"}
]
```

Tiers are advisory metadata; rate limits are enforced uniformly per-key.

## Research

Developed at the **Alabama A&M University Cybersecurity Research Lab** with **NSF funding**. Detection methodology peer-reviewed and published in Springer conference proceedings. System architecture presented at SAM'25 — The 2025 International Conference on Security and Management, Las Vegas.

See [MODEL_CARD.md](MODEL_CARD.md) for full model documentation.

## License

MIT
