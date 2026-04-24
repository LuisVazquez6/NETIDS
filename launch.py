#!/usr/bin/env python3
"""
NetIDS launcher — starts the dashboard and IDS together, then opens the browser.

Usage:
    python launch.py --live --iface eth0
    python launch.py --pcap capture.pcap
"""
from __future__ import annotations

import sys
import time
import threading
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

DASHBOARD_URL = "http://localhost:5000"

BANNER = """
+--------------------------------------------------+
|      NetIDS -- Intrusion Detection System        |
+--------------------------------------------------+
|  Starting dashboard ...                          |
|  Opening browser  ->  http://localhost:5000      |
|                                                  |
|  Press  Ctrl+C  to stop                          |
+--------------------------------------------------+
"""


def _start_dashboard() -> None:
    from dashboard.flask_app import app
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)


def main() -> int:
    print(BANNER)

    # Start Flask in a background daemon thread so it dies when the IDS stops
    flask_thread = threading.Thread(target=_start_dashboard, daemon=True)
    flask_thread.start()

    # Give Flask time to bind before opening the browser
    time.sleep(2)
    webbrowser.open(DASHBOARD_URL)

    # Run the IDS in the main thread — blocks until Ctrl+C
    from ids import main as ids_main
    return ids_main()


if __name__ == "__main__":
    raise SystemExit(main())
