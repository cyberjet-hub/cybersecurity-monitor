from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from cybersecurity_monitor.analyzer import analyze_logs, watch_log_file, write_alerts_json


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze login logs for suspicious patterns.")
    parser.add_argument(
        "--log",
        type=Path,
        default=ROOT / "sample_logs.txt",
        help="Path to the log file to analyze.",
    )
    parser.add_argument(
        "--json",
        type=Path,
        default=None,
        help="Optional path to write the alerts as JSON.",
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="Continuously monitor the log file and print new alerts as entries arrive.",
    )
    args = parser.parse_args()

    if not args.log.exists():
        raise FileNotFoundError(f"Log file not found: {args.log}")

    if args.watch:
        print(f"Watching {args.log} for new entries. Press Ctrl+C to stop.")
        for new_lines in watch_log_file(args.log):
            if not new_lines:
                continue
            alerts = analyze_logs(new_lines)
            if not alerts:
                continue
            for alert in alerts:
                print(f"[{alert['severity']}] {alert['type']} - {alert['message']}")
                if "user" in alert:
                    print(f"  user: {alert['user']}")
                if "source_ip" in alert:
                    print(f"  source_ip: {alert['source_ip']}")
                if "source_ips" in alert:
                    print(f"  source_ips: {', '.join(alert['source_ips'])}")
                if "prior_failed_ips" in alert:
                    print(f"  prior_failed_ips: {', '.join(alert['prior_failed_ips'])}")
                if "target_users" in alert:
                    print(f"  target_users: {', '.join(alert['target_users'])}")
                if "count" in alert:
                    print(f"  count: {alert['count']}")
                print(f"  timestamp: {alert['timestamp']}")
            if args.json:
                prev_alerts = []
                if args.json.exists():
                    try:
                        prev_alerts = json.loads(args.json.read_text(encoding="utf-8"))
                    except json.JSONDecodeError:
                        prev_alerts = []
                prev_alerts.extend(alerts)
                write_alerts_json(prev_alerts, args.json)
        return

    alerts = analyze_logs(args.log.read_text(encoding="utf-8").splitlines())
    if args.json:
        write_alerts_json(alerts, args.json)
        print(f"Alerts written to {args.json}")

    if not alerts:
        print("No suspicious login patterns detected.")
        return

    for alert in alerts:
        print(f"[{alert['severity']}] {alert['type']} - {alert['message']}")
        if "user" in alert:
            print(f"  user: {alert['user']}")
        if "source_ip" in alert:
            print(f"  source_ip: {alert['source_ip']}")
        if "source_ips" in alert:
            print(f"  source_ips: {', '.join(alert['source_ips'])}")
        if "prior_failed_ips" in alert:
            print(f"  prior_failed_ips: {', '.join(alert['prior_failed_ips'])}")
        if "target_users" in alert:
            print(f"  target_users: {', '.join(alert['target_users'])}")
        if "count" in alert:
            print(f"  count: {alert['count']}")
        print(f"  timestamp: {alert['timestamp']}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")
