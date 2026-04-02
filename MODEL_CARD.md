# Scanner API — Phishing Detection Model Card

## Model Overview
- Architecture: Sentence-BERT (all-MiniLM-L6-v2) embeddings + calibrated ensemble (Logistic Regression, XGBoost, LightGBM)
- Ensemble method: Soft voting (averaged predict_proba)
- Calibration: Isotonic regression via CalibratedClassifierCV
- Task: Binary classification — Phishing Email vs Safe Email

## Training Data
- Dataset: 82,486 emails (42,891 phishing, 39,595 safe)
- Balancing: RandomUnderSampler to 79,190 samples
- Split: 80% train, 20% test
- Source: Kaggle phishing email dataset

## Performance
| Metric | Safe | Phishing | Macro Avg |
|--------|------|----------|-----------|
| Precision | 0.93 | 0.99 | 0.96 |
| Recall | 0.99 | 0.93 | 0.96 |
| F1 | 0.96 | 0.96 | 0.96 |
| Ensemble F1 | — | — | 0.9583 |

## Detection Pipeline
This model is one of 8 detection layers in the Scanner API:
1. Google Safe Browsing
2. OpenPhish community feed
3. DNSBL (Spamhaus, SURBL, URIBL)
4. This ML classifier
5. Email header analysis (SPF/DKIM/DMARC)
6. URL structural signals
7. Homoglyph detection
8. Domain age (WHOIS)

## Known Limitations
- Short email bodies (<10 words) may produce uncertain predictions
- Model was trained on English-language emails only
- Novel phishing techniques not in training data may be missed (mitigated by non-ML layers: GSB, DNSBL, header analysis)
- SentenceTransformer has known threading issues on macOS Python 3.12 — deploy on Linux

## Adversarial Robustness
Tested against:
- Base64-encoded body — DETECTED (preprocessing layer)
- CSS-hidden text — DETECTED (HTML parser)
- HTML comment injection — DETECTED (comment extractor)
- URL fragment tricks — DETECTED (URL parser)
- Punycode homoglyph domains — DETECTED (canonicalizer)
- Zero-width character injection — DETECTED (canonicalizer)

## Research Background
Developed at Alabama A&M University Cybersecurity Research Lab.
Supported by NSF funding.
Findings published in Springer proceedings.
Presented at DEF CON, Las Vegas.

## Intended Use
- Email security scanning APIs
- Phishing detection research
- Security awareness training systems

## Out of Scope
- Real-time email gateway filtering at scale (use commercial solutions)
- Non-English email classification
- SMS or social media phishing (smishing/vishing)

## Ethical Considerations
- Model trained on publicly available datasets
- No personally identifiable information in training data (emails hashed before storage)
- False positive rate ~5% — human review recommended for borderline cases (handled by active learning queue)
