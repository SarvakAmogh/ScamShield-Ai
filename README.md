# ScamShield AI 🛡️

AI-powered scam detection platform designed to protect users from SMS phishing, credential harvesting, and malicious URLs.

## Features
- **SMS Scanning**: Rule-based analysis of text messages to detect financial lures, credential harvesting, and threats.
- **URL Checker**: Identifies typosquatting, suspicious paths, shortened URLs, and IP-based links.
- **Dashboard**: Real-time monitoring of scan history and risk scores (Planned).
- **RESTful API**: Fast and scalable endpoints using FastAPI.

## Tech Stack
- **Backend**: Python 3.11, FastAPI, Motor (Async MongoDB), Pytest
- **Frontend**: React (Planned)
- **Database**: MongoDB
- **CI/CD**: GitHub Actions

## Quick Start

### Prerequisites
- Python 3.11+
- MongoDB (running locally or Atlas URI)

### Installation & Running the Server
```bash
cd backend
pip install -e ".[dev]"
# Ensure MongoDB is running locally or MONGO_URI is set
uvicorn app.main:app --reload
```
The API documentation will be available interactively at `http://localhost:8000/docs`.

## API Endpoints
- `POST /api/v1/scan/message` - Scan a text message for potential scams.
- `POST /api/v1/scan/url` - Scan a URL for phishing or malicious indicators.
- `GET /api/v1/scan/history` - Retrieve recently performed scans.
- `GET /health` - Service health check.

## Architecture Overview
ScamShield AI is built with an extensible **Strategy Pattern** for its analyzers. The core engine delegates inputs to the relevant analyzer class (such as `RuleBasedAnalyzer` and `URLChecker`), allowing seamless expansion to include ML-based classification or external intelligence API integrations in future versions.

## Testing
Run the complete test suite using `pytest`:
```bash
cd backend
pytest -v
# To run with coverage reporting:
pytest --cov=app --cov-report=term-missing
```

## Project Structure
```
scamshield-ai/
├── backend/
│   ├── app/
│   │   ├── analyzers/
│   │   ├── api/
│   │   ├── models/
│   │   └── main.py
│   └── tests/
├── .github/
│   └── workflows/
├── .gitignore
└── README.md
```

## License
MIT License
