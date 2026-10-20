from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from cybersecurity_monitor.analyzer import analyze_logs


def read_log_file(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze login logs for suspicious patterns.")
    parser.add_argument("--log", type=Path, default=ROOT / "sample_logs.txt", help="Path to the log file to analyze.")
    args = parser.parse_args()

    if not args.log.exists():
        raise FileNotFoundError(f"Log file not found: {args.log}")

    alerts = analyze_logs(read_log_file(args.log))
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
    main()
