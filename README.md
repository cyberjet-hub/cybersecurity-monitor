# Cybersecurity Monitor

Cybersecurity Monitor is a Python-based security utility that analyzes login log samples to detect suspicious authentication activity and generate actionable alerts.

## Features

- Parses login event logs in a structured format
- Detects brute-force attempts against a single user
- Flags successful logins following multiple failed attempts
- Identifies credential stuffing from a single IP address
- Detects multi-IP login behavior for a single user
- Exports alerts in a clean, machine-readable structure

## Log format

Each line should match this format:

```text
2026-10-20T08:00:00Z alice LOGIN FAILURE 203.0.113.25
2026-10-20T08:06:00Z alice LOGIN SUCCESS 198.51.100.9
```

## Quick start

```bash
python main.py --log sample_logs.txt
```

## Project layout

```text
.
├── main.py
├── sample_logs.txt
├── pyproject.toml
├── src/
│   └── cybersecurity_monitor/
│       ├── __init__.py
│       └── analyzer.py
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
