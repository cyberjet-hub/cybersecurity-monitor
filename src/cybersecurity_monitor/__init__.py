from __future__ import annotations

import json
import re
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Iterator

LOG_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+"
    r"(?P<user>\S+)\s+LOGIN\s+(?P<status>SUCCESS|FAILURE)\s+(?P<ip>\S+)$"
)

SEVERITY_ORDER = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}


def parse_timestamp(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")


def parse_log_line(line: str) -> dict[str, Any] | None:
    cleaned = line.strip()
    if not cleaned or cleaned.startswith("#"):
        return None

    match = LOG_RE.match(cleaned)
    if not match:
        return None

    return {
        "timestamp": parse_timestamp(match.group("ts")),
        "user": match.group("user"),
        "status": match.group("status"),
        "ip": match.group("ip"),
        "iso": match.group("ts"),
    }


def analyze_logs(lines: Iterable[str]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for raw_line in lines:
        parsed = parse_log_line(raw_line)
        if parsed:
            events.append(parsed)

    alerts: list[dict[str, Any]] = []
    by_user: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for event in events:
        by_user[event["user"]].append(event)
        by_ip[event["ip"]].append(event)

    for user, user_events in by_user.items():
        failed = [event for event in user_events if event["status"] == "FAILURE"]
        if len(failed) >= 5:
            for first in failed:
                window = [
                    event
                    for event in failed
                    if 0 <= (event["timestamp"] - first["timestamp"]).total_seconds() <= 600
                ]
                if len(window) >= 5:
                    alerts.append(
                        {
                            "type": "BRUTE_FORCE",
                            "severity": "HIGH",
                            "user": user,
                            "source_ips": sorted({event["ip"] for event in window}),
                            "count": len(window),
                            "timestamp": first["iso"],
                            "message": f"User {user} had {len(window)} failed login attempts in 10 minutes.",
                        }
                    )
                    break

        successes = [event for event in user_events if event["status"] == "SUCCESS"]
        for success in successes:
            recent_failures = [
                event
                for event in failed
                if 0 <= (success["timestamp"] - event["timestamp"]).total_seconds() <= 900
                and event["ip"] != success["ip"]
            ]
            if len(recent_failures) >= 3:
                alerts.append(
                    {
                        "type": "POSSIBLE_ACCOUNT_TAKEOVER",
                        "severity": "CRITICAL",
                        "user": user,
                        "source_ip": success["ip"],
                        "prior_failed_ips": sorted({event["ip"] for event in recent_failures}),
                        "count": len(recent_failures),
                        "timestamp": success["iso"],
                        "message": (
                            f"Successful login for {user} from {success['ip']} after "
                            f"{len(recent_failures)} failures from other IPs."
                        ),
                    }
                )
                break

    for ip, ip_events in by_ip.items():
        failed = [event for event in ip_events if event["status"] == "FAILURE"]
        if len(failed) >= 10:
            users = sorted({event["user"] for event in failed})
            alerts.append(
                {
                    "type": "CREDENTIAL_STUFFING",
                    "severity": "HIGH",
                    "source_ip": ip,
                    "target_users": users,
                    "count": len(failed),
                    "timestamp": failed[0]["iso"],
                    "message": (
                        f"IP {ip} triggered {len(failed)} failed login attempts across "
                        f"{len(users)} accounts."
                    ),
                }
            )

    for user, user_events in by_user.items():
        successes = [event for event in user_events if event["status"] == "SUCCESS"]
        for success in successes:
            window = [
                event
                for event in successes
                if 0 <= (success["timestamp"] - event["timestamp"]).total_seconds() <= 3600
            ]
            ips = {event["ip"] for event in window}
            if len(ips) >= 3:
                alerts.append(
                    {
                        "type": "MULTI_IP_LOGIN",
                        "severity": "MEDIUM",
                        "user": user,
                        "source_ips": sorted(ips),
                        "count": len(ips),
                        "timestamp": success["iso"],
                        "message": (
                            f"User {user} logged in from {len(ips)} different IPs in one hour."
                        ),
                    }
                )
                break

    alerts.sort(
        key=lambda item: (SEVERITY_ORDER.get(item.get("severity", "LOW"), 0), item.get("timestamp", "")),
        reverse=True,
    )
    return alerts


def write_alerts_json(alerts: list[dict[str, Any]], path: str | Path) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(alerts, indent=2), encoding="utf-8")


def watch_log_file(path: str | Path, poll_interval: float = 1.0) -> Iterator[list[str]]:
    target = Path(path)
    if not target.exists():
        raise FileNotFoundError(f"Log file not found: {target}")

    seen_lines = 0
    while True:
        with target.open("r", encoding="utf-8") as handle:
            lines = handle.readlines()

        if len(lines) > seen_lines:
            new_lines = lines[seen_lines:]
            seen_lines = len(lines)
            yield new_lines

        time.sleep(poll_interval)
