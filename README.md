# Email Scanner Backend API

A production-ready FastAPI backend service for detecting phishing and scam emails using multiple analysis methods.

## 🎯 Features

- **Email Address Verification** - Validates email addresses using Hunter.io API
- **URL Scanning** - Detects malicious links using VirusTotal API
- **Content Analysis** - ML-based phishing classification using Random Forest
- **Unified Scoring** - Combines all methods into a single scam score (0-100)
- **RESTful API** - Clean, well-documented endpoints
- **API Authentication** - Secure API key-based authentication
- **CORS Support** - Ready for frontend integration
- **Auto-generated Docs** - OpenAPI/Swagger documentation

## 📋 Requirements

- Python 3.8+
- Hunter.io API key (for email verification)
- VirusTotal API key (for URL scanning)
- Phishing email dataset (for ML model training)

## 🚀 Quick Start

### 1. Installation

```bash
# Clone or navigate to the project directory
cd /Users/daniellambo/Downloads/Scanner_API

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configuration

```bash
# Copy environment template
cp .env.template .env

# Edit .env and add your API keys
# Replace ## placeholders with actual values
```

**Required environment variables:**
- `HUNTER_API_KEY` - Get from [hunter.io](https://hunter.io/api)
- `VIRUSTOTAL_API_KEY` - Get from [virustotal.com](https://www.virustotal.com/)
- `API_KEY` - Generate a secure random string for API authentication

### 3. Train ML Model (Optional but Recommended)

Download the phishing email dataset:
- [Google Drive Link](https://drive.google.com/file/d/1f-qsFeoXt0i0H4yUbQuX5-oLcD_swzIY/view)
- Or use your own CSV with columns: `Email Text`, `Email Type`

```bash
# Train the model
python ml/train_model.py phishing_email.csv
```

This will create trained models in `ml/models/`:
- `classifier.pkl` - Random Forest classifier
- `vectorizer.pkl` - TF-IDF vectorizer

### 4. Start the API Server

```bash
# Start with auto-reload (development)
uvicorn app:app --reload

# Or run directly
python app.py
```

The API will be available at: `http://localhost:8000`

## 📚 API Documentation

### Interactive Docs

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### Endpoints

#### Health Check
```http
GET /health
```
Returns service status and ML model availability.

#### Complete Scan
```http
POST /api/scan
Headers: X-API-Key: your_api_key
Content-Type: application/json

{
  "email_address": "suspicious@example.com",
  "email_text": "Click here to claim your prize: http://phishing-site.com"
}
```

Returns comprehensive analysis with scam score (0-100) and risk level.

#### Email Address Verification Only
```http
POST /api/scan/email-address
Headers: X-API-Key: your_api_key
Content-Type: application/json

{
  "email_address": "test@example.com"
}
```

#### URL Scanning Only
```http
POST /api/scan/urls
Headers: X-API-Key: your_api_key
Content-Type: application/json

{
  "email_text": "Visit our site: http://example.com"
}
```

#### Content Analysis Only
```http
POST /api/scan/content
Headers: X-API-Key: your_api_key
Content-Type: application/json

{
  "email_text": "Your account has been compromised. Click here immediately."
}
```

## 📊 Example Response

```json
{
  "scam_score": 78.5,
  "risk_level": "HIGH",
  "email_verification": {
    "valid": false,
    "score": 20,
    "disposable": true,
    "webmail": false,
    "accept_all": false,
    "gibberish": false,
    "risk_score": 80.0
  },
  "url_scan": {
    "urls_found": ["http://phishing-site.com"],
    "malicious_count": 1,
    "suspicious_count": 0,
    "risk_score": 95.0
  },
  "content_analysis": {
    "prediction": "Phishing Email",
    "confidence": 0.92,
    "risk_score": 92.0,
    "is_phishing": true
  }
}
```

## 🔧 Configuration

### Scoring Weights

Adjust the weights for each analysis method in `.env`:

```env
SCORING_WEIGHTS_EMAIL=0.3    # Email verification weight
SCORING_WEIGHTS_URL=0.4      # URL scanning weight
SCORING_WEIGHTS_CONTENT=0.3  # Content analysis weight
```

Weights should sum to 1.0 for proper averaging.

### Risk Levels

Scam scores are categorized into risk levels:
- **0-24**: LOW
- **25-49**: MEDIUM
- **50-74**: HIGH
- **75-100**: CRITICAL

## 🏗️ Project Structure

```
Scanner_API/
├── app.py                      # Main FastAPI application
├── config.py                   # Configuration management
├── requirements.txt            # Python dependencies
├── .env.template              # Environment variables template
├── .gitignore                 # Git ignore patterns
├── models/
│   └── schemas.py             # Pydantic data models
├── services/
│   ├── email_verifier.py      # Hunter.io integration
│   ├── url_scanner.py         # VirusTotal integration
│   ├── content_analyzer.py    # ML classification
│   └── score_calculator.py    # Unified scoring
├── ml/
│   ├── train_model.py         # Model training script
│   └── model_loader.py        # Model loading utilities
├── middleware/
│   └── auth.py                # API key authentication
└── utils/
    └── url_extractor.py       # URL extraction utility
```

## 🧪 Testing

### Using cURL

```bash
# Health check
curl http://localhost:8000/health

# Complete scan
curl -X POST http://localhost:8000/api/scan \
  -H "X-API-Key: your_api_key" \
  -H "Content-Type: application/json" \
  -d '{
    "email_address": "test@example.com",
    "email_text": "Click here: http://example.com"
  }'
```

### Using Python

```python
import requests

API_URL = "http://localhost:8000/api/scan"
API_KEY = "your_api_key"

response = requests.post(
    API_URL,
    headers={"X-API-Key": API_KEY},
    json={
        "email_address": "suspicious@example.com",
        "email_text": "Congratulations! You won $1,000,000!"
    }
)

print(response.json())
```

## 🚦 Deployment Considerations

### Production Checklist

- [ ] Set strong API keys in production `.env`
- [ ] Configure CORS to allow only specific origins
- [ ] Use HTTPS for all endpoints
- [ ] Set up rate limiting (consider using `slowapi`)
- [ ] Add logging and monitoring
- [ ] Use a production ASGI server (Gunicorn + Uvicorn workers)
- [ ] Consider caching for repeated scans
- [ ] Set up error tracking (e.g., Sentry)

### Production Server

```bash
# Install Gunicorn
pip install gunicorn

# Run with multiple workers
gunicorn app:app -w 4 -k uvicorn.workers.UvicornWorker -b 0.0.0.0:8000
```

## 🤝 Frontend & Web Extension Integration

This API is optimized for easy integration with frontend applications and browser extensions (Chrome, Firefox, Edge).

### 🚀 Quick Start with SDK

We provide a lightweight TypeScript client in the `frontend/` directory.

1. **Copy types and client**: Copy `frontend/types.ts` and `frontend/client.ts` to your project.
2. **Usage**:

```typescript
import { EmailScannerClient } from './client';

const client = new EmailScannerClient('http://localhost:8000', 'your_api_key');

const result = await client.scanEmail({
  email_address: 'suspicious@example.com',
  email_text: 'Urgent: Reset your password now!'
});

console.log(`Risk: ${result.risk_level} (${result.scam_score}/100)`);
```

### 🏷️ Using Labels & Recommendations

The API provides pre-processed `labels` and `recommendations` specifically for UI display:

- **`labels`**: Short strings (e.g., "Malicious Link", "High Risk Sender") perfect for badges or tags.
- **`recommendations`**: Human-readable advice for the end-user.

```javascript
// Example UI mapping
const riskColors = {
  'LOW': '#4CAF50',      // Green
  'MEDIUM': '#FFC107',   // Yellow
  'HIGH': '#FF9800',     // Orange
  'CRITICAL': '#F44336'  // Red
};

// Use result.labels.map() to render badges
// Use result.recommendations.map() to render an advice list
```

### 🌐 Web Extension Configuration

When using this API in a web extension:

#### 1. Permissions (`manifest.json`)
Ensure your API host is allowed in your manifest:

```json
{
  "permissions": [
    "host_permissions": [
      "http://localhost:8000/*"
    ]
  ]
}
```

#### 2. CORS
The API is configured with CORS support. In development, it allows all origins. For production, update `app.py` to include your extension's ID:

```python
# app.py
app.add_middleware(
    CORSMiddleware,
    allow_origins=["chrome-extension://your-extension-id"],
    ...
)
```

### 🛠️ Local Development

If you are developing your frontend locally (e.g., React on localhost:3000), the API will work out of the box due to the current CORS settings.

## 📝 License

This project is open source and available for educational and commercial use.

## 🐛 Troubleshooting

### ML Model Not Available

If you get "ML model not available" errors:
1. Ensure you've trained the model: `python ml/train_model.py`
2. Check that `ml/models/` directory contains the `.pkl` files
3. Verify the dataset path is correct

### API Key Errors

- Ensure `.env` file exists and contains your API keys
- Check that API keys are valid and not rate-limited
- Verify `X-API-Key` header is included in requests

### Import Errors

- Make sure virtual environment is activated
- Reinstall dependencies: `pip install -r requirements.txt`

## 📧 Support

For issues or questions, please check:
- API documentation at `/docs`
- Configuration in `.env.template`
- Model training output for ML issues
