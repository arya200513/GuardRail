# GUARD RAIL — AI-Driven Data Leak Prevention

A student hackathon prototype for sensitive-data pattern scanning, risk scoring, alerts, and audit logs.

## Features
- Demo login with admin/user roles
- Scanner for email, phone-like numbers, Aadhaar-like number patterns, and secret strings
- Risk simulator for bulk exports, external destinations, large files, and high record counts
- Explainable 0–100 risk score and Low/Medium/High levels
- SQLite activity log and alert queue
- Admin can mark alerts as reviewed
- Responsive cybersecurity dashboard

## Run locally
Python 3.10+ recommended.

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000

## Demo credentials
- Admin: `admin` / `admin123`
- User: `student` / `student123`

Database is created on first run. Suggested demo: sign in as admin, simulate normal file access, then simulate a bulk export to an external destination with 800000 bytes and 500 records. Show the dashboard and alert queue, then scan fictional text such as `demo.user@example.com; api_key=EXAMPLE_ONLY_123`.

## Important limitations
This is an academic prototype. Risk scoring currently uses transparent heuristics, not a trained AI model. It does not monitor a real device, browser, email, USB drive, or network and does not block actual transfers. Use synthetic data only. Before production use, add CSRF protection, rate limiting, secure cookies, HTTPS, stronger authentication, and security review. Set a strong `GUARDRAIL_SECRET` and disable debug mode in any deployment.

## Future AI work
Create a synthetic labeled event dataset, train an anomaly detector (for example Isolation Forest), evaluate on held-out events, and report precision/recall and false-positive rate. Do not claim accuracy without measurement.
