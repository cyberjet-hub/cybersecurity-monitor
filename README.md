# Cybersecurity Monitor

Cybersecurity Monitor is a Python-based security utility that analyzes login log samples to detect suspicious authentication activity and generate actionable alerts.

## Features

- Parses login event logs in a structured format
- Detects brute-force attempts against a single user
- Flags successful logins following multiple failed attempts
- Identifies credential stuffing from a single IP address
- Detects multi-IP login behavior for a single user
- Exports alerts to JSON
- Serves a simple Flask dashboard and REST API
- Can monitor a log file for newly appended entries in real time

## Log format

Each line should match this format:

```text
2026-10-20T08:00:00Z alice LOGIN FAILURE 203.0.113.25
2026-10-20T08:06:00Z alice LOGIN SUCCESS 198.51.100.9
```

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
python main.py --log sample_logs.txt
```

## Export alerts to JSON

```bash
python main.py --log sample_logs.txt --json security_alerts.json
```

## Run the dashboard

```bash
python app.py
```

Then open:

```text
http://127.0.0.1:5000/
```

## API endpoints

```text
GET /api/alerts
POST /api/analyze
```

- `GET /api/alerts` returns the latest alerts from `sample_logs.txt`
- `POST /api/analyze` accepts either an uploaded file or `log_text` and returns JSON alerts

## Watch a log file live

```bash
python main.py --log sample_logs.txt --watch
```

This tails the file and prints alerts when new entries arrive.

## Project layout

```text
.
├── app.py
├── main.py
├── sample_logs.txt
├── pyproject.toml
├── requirements.txt
├── templates/
│   └── index.html
├── static/
│   └── style.css
├── src/
│   └── cybersecurity_monitor/
│       ├── __init__.py
│       ├── analyzer.py
│       └── api.py
└── README.md
```

## Alert examples

The analyzer can raise alerts such as:

- BRUTE_FORCE
- POSSIBLE_ACCOUNT_TAKEOVER
- CREDENTIAL_STUFFING
- MULTI_IP_LOGIN

## License

MIT
