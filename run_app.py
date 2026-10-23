"""
RP4: Protocol-Aware Replay Attack Detection for Modbus/TCP
Dashboard Application Server Runner

Usage:
    py -3.13 run_app.py
    py -3.13 run_app.py --port 5000 --host 127.0.0.1
"""

import argparse
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app import create_app


def main():
    parser = argparse.ArgumentParser(description="Run RP4 Replay Detection Dashboard")
    parser.add_argument("--config", default="config/default.yaml", help="Path to config file")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface")
    parser.add_argument("--port", type=int, default=5000, help="Port to bind")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    args = parser.parse_args()

    app = create_app(config_path=args.config)

    print("=" * 70)
    print("RP4: Protocol-Aware Replay Attack Detection for Modbus/TCP")
    print(f"Web Dashboard running at: http://{args.host}:{args.port}/")
    print("Stage 1 University Research Prototype")
    print("=" * 70)

    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
