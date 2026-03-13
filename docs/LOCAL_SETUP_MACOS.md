# Running MoofwdGuard Locally on macOS (VS Code)

## Prerequisites

```bash
# 1. Install Python 3.11+
brew install python@3.12

# 2. Install Docker Desktop (for Redis + Postgres)
brew install --cask docker
# Launch Docker Desktop from Applications
```

## Setup

```bash
# Clone and open in VS Code
git clone <your-repo-url> moofwd-guard
cd moofwd-guard
code .

# Create virtual environment
python3.12 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -e ".[dev]"

# Create your .env file
cp .env.example .env
# Edit .env with your actual keys (IPQS_API_KEY at minimum)
```

## Start the Stack

### Option A — Docker for everything (easiest)

```bash
docker-compose up -d
# API at http://localhost:8000
```

### Option B — Docker for Redis/Postgres only, run API natively (better for debugging)

```bash
# Start just Redis + Postgres
docker-compose up -d redis postgres

# Run the API with uvicorn (hot-reload enabled)
source .venv/bin/activate
uvicorn api.main:app --reload --port 8000
```

## Verify

```bash
# Health check
curl http://localhost:8000/health

# Send a test signal
curl -X POST http://localhost:8000/v1/signals \
  -H "Content-Type: application/json" \
  -d '{
    "transaction_id": "txn_001",
    "ip_address": "8.8.8.8",
    "email": "test@example.com",
    "bin": "411111",
    "billing_country": "US",
    "device_fingerprint": "fp_test",
    "checkout_duration_seconds": 30.0,
    "user_agent": "Mozilla/5.0",
    "amount_usd": 49.99
  }'
```

## Run Tests

```bash
source .venv/bin/activate
pytest tests/unit/ -v          # No Docker needed
pytest tests/integration/ -v   # No Docker needed (uses fakeredis)
pytest --cov=api               # Full coverage report
```

## VS Code Setup

### Extensions

Install these extensions:
- **Python** (ms-python.python)
- **Pylance** (ms-python.vscode-pylance)

### Select Interpreter

`Cmd+Shift+P` → "Python: Select Interpreter" → pick `.venv`

### Debugging

A `launch.json` is included in `.vscode/`. Hit **F5** to launch the API with breakpoints and hot-reload enabled.
