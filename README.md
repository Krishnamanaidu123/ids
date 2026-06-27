# Simple Web IDS Dashboard

This project is an educational, simulation-based Intrusion Detection System (IDS) built with Python and Flask.

It includes:
- A web dashboard UI for easy monitoring
- Synthetic security event generation
- Rule-based alerting
- In-memory storage for recent events and alerts

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

```bash
python app.py
```

Open `http://127.0.0.1:5000`.

## API Endpoints

- `GET /api/status` - monitoring state and counters
- `GET /api/events` - recent events
- `GET /api/alerts` - recent alerts
- `POST /api/control/start` - start simulation
- `POST /api/control/stop` - stop simulation
- `GET /api/rules` - current rules/config
- `POST /api/rules` - update thresholds

## Notes / Limitations

- This is a simulation and **not** a production IDS.
- Data is stored in memory only (resets on restart).
- Rules are intentionally simple for learning and demos.
