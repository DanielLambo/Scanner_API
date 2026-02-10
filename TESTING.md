# Testing the API Without API Keys

## Quick Start (No Authentication Required)

The API is configured with `testing_mode = True` by default, which means **you don't need any API keys** to test it!

### 1. Start the Server

```bash
cd /Users/daniellambo/Downloads/Scanner_API
source venv/bin/activate  # If you have a virtual environment
uvicorn app:app --reload
```

The server will start at: `http://localhost:8000`

### 2. View API Documentation

Open your browser and go to: **http://localhost:8000/docs**

This gives you an interactive Swagger UI where you can test all endpoints directly in your browser!

### 3. Test with cURL (No API Key Needed)

#### Health Check
```bash
curl http://localhost:8000/health
```

#### Complete Email Scan
```bash
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "email_address": "test@example.com",
    "email_text": "Click here to claim your prize: http://suspicious-link.com"
  }'
```

#### Content Analysis Only
```bash
curl -X POST http://localhost:8000/api/scan/content \
  -H "Content-Type: application/json" \
  -d '{
    "email_text": "Urgent! Your account will be suspended. Click here immediately!"
  }'
```

### 4. Example Response

```json
{
  "scam_score": 75,
  "risk_level": "high",
  "confidence": 0.85,
  "breakdown": {
    "email_verification": {
      "score": 60,
      "is_risky": true
    },
    "url_scan": {
      "score": 85,
      "urls_found": 1,
      "malicious_count": 1
    },
    "content_analysis": {
      "score": 80,
      "classification": "Phishing Email",
      "confidence": 0.92
    }
  },
  "recommendations": [
    "Do not click any links",
    "Mark as spam",
    "Verify sender through official channels"
  ]
}
```

## Limitations in Testing Mode

**Note:** In testing mode, external API calls (Hunter.io and VirusTotal) will return mock/error responses since you don't have real API keys configured. However:

- ✅ **Content Analysis** works fully (if ML model is trained)
- ❌ **Email Verification** will return errors
- ❌ **URL Scanning** will return errors

The API will still return a combined scam score based on available data.

## Training the ML Model

To enable content analysis, you need to train the model first:

```bash
# Download the dataset from the link in README.md
# Place it as: Phishing_Email.csv

python ml/train_model.py
```

## Switching to Production Mode

When you have real API keys, update your `.env` file:

```env
TESTING_MODE=false
API_KEY=your_secure_api_key_here
HUNTER_API_KEY=your_hunter_api_key
VIRUSTOTAL_API_KEY=your_virustotal_api_key
```

Then requests must include the `X-API-Key` header:

```bash
curl -X POST http://localhost:8000/api/scan \
  -H "X-API-Key: your_secure_api_key_here" \
  -H "Content-Type: application/json" \
  -d '{"email_text": "Test email"}'
```

## Testing with Postman

1. Import the API by using the OpenAPI/Swagger URL: `http://localhost:8000/openapi.json`
2. Create requests without any authentication headers (in testing mode)
3. Send JSON payloads with `email_address` and/or `email_text`

## Common Issues

**Q: I get "ML model not available" error**  
A: Train the model first using `python ml/train_model.py`

**Q: Email verification returns errors**  
A: Normal in testing mode - you need real Hunter.io API key for this to work

**Q: Port 8000 is already in use**  
A: Change the port: `uvicorn app:app --port 8001`
