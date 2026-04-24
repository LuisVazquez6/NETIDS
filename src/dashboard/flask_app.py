from __future__ import annotations

import hashlib
import hmac
import json
import sys
import time
import os
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from functools import wraps
from flask import Flask, render_template, jsonify, request, session, redirect, url_for

# Make sure src/ is on the path so we can import shared modules
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from correlation.incident_manager import ALERT_WEIGHTS, SEVERITY_WEIGHT  # noqa: E402
from models.incidents import SEVERITY_ORDER  # noqa: E402

app = Flask(__name__)

# Persist the secret key so sessions survive restarts.
_SECRET_KEY_FILE = Path(__file__).resolve().parents[2] / ".flask_secret"
try:
    if _SECRET_KEY_FILE.exists():
        app.secret_key = _SECRET_KEY_FILE.read_bytes()
    else:
        _key = os.urandom(32)
        _SECRET_KEY_FILE.write_bytes(_key)
        app.secret_key = _key
except Exception:
    app.secret_key = os.urandom(32)

# Login rate limiter: max 5 attempts per IP within 60 seconds.
_login_attempts: dict[str, list[float]] = defaultdict(list)
_LOGIN_MAX = 5
_LOGIN_WINDOW = 60

ROOT = Path(__file__).resolve().parents[2]
ALERTS_PATH = ROOT / "logs" / "alerts.jsonl"
CONFIG_PATH = ROOT / "config.json"


def load_dashboard_config():
    try:
        with CONFIG_PATH.open("r") as f:
            cfg = json.load(f)
        return cfg.get("dashboard", {})
    except Exception:
        return {}


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def read_alerts():
    if not ALERTS_PATH.exists():
        return []
    alerts = []
    with ALERTS_PATH.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return alerts


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        client_ip = request.remote_addr or "unknown"
        now = time.time()
        attempts = _login_attempts[client_ip]
        # Drop attempts outside the window
        _login_attempts[client_ip] = [t for t in attempts if now - t < _LOGIN_WINDOW]
        if len(_login_attempts[client_ip]) >= _LOGIN_MAX:
            error = "Too many attempts. Try again later."
            return render_template("login.html", error=error)

        cfg = load_dashboard_config()
        # Prefer env vars; fall back to config.json values
        expected_user = os.environ.get("NETIDS_USER") or cfg.get("username", "admin")
        expected_hash = os.environ.get("NETIDS_PASSWORD_HASH") or _hash(
            cfg.get("password", "netids2025")
        )
        submitted_user = request.form.get("username", "")
        submitted_hash = _hash(request.form.get("password", ""))
        if submitted_user == expected_user and hmac.compare_digest(submitted_hash, expected_hash):
            session["logged_in"] = True
            session["username"] = submitted_user
            _login_attempts.pop(client_ip, None)
            return redirect(url_for("index"))
        _login_attempts[client_ip].append(now)
        error = "Invalid credentials"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    return render_template("index.html")


@app.route("/api/alerts")
@login_required
def api_alerts():
    alerts = read_alerts()
    # return last 100 most recent first
    alerts = sorted(alerts, key=lambda a: a.get("ts", 0), reverse=True)[:100]
    for a in alerts:
        ts = a.get("ts", 0)
        try:
            a["time_fmt"] = datetime.fromtimestamp(float(ts)).strftime("%H:%M:%S")
            a["date_fmt"] = datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d")
        except Exception:
            a["time_fmt"] = "N/A"
            a["date_fmt"] = "N/A"
    return jsonify(alerts)


@app.route("/api/stats")
@login_required
def api_stats():
    alerts = read_alerts()
    if not alerts:
        return jsonify({
            "total": 0, "high": 0, "medium": 0, "low": 0,
            "by_type": {}, "by_hour": {}, "top_src": [], "timeline": []
        })

    severity_count = defaultdict(int)
    type_count = defaultdict(int)
    src_count = defaultdict(int)
    hour_count = defaultdict(int)

    for a in alerts:
        sev = a.get("severity", "LOW")
        severity_count[sev] += 1
        type_count[a.get("alert_type", "UNKNOWN")] += 1
        src_count[a.get("src_ip", "unknown")] += 1
        try:
            hour = datetime.fromtimestamp(float(a.get("ts", 0))).strftime("%H:00")
            hour_count[hour] += 1
        except Exception:
            pass

    top_src = sorted(src_count.items(), key=lambda x: x[1], reverse=True)[:5]
    top_src = [{"ip": ip, "count": count} for ip, count in top_src]

    # timeline — last 12 hours
    timeline_labels = sorted(hour_count.keys())[-12:]
    timeline_data = [hour_count[h] for h in timeline_labels]

    return jsonify({
        "total": len(alerts),
        "high": severity_count.get("HIGH", 0),
        "medium": severity_count.get("MEDIUM", 0),
        "low": severity_count.get("LOW", 0),
        "by_type": dict(type_count),
        "top_src": top_src,
        "timeline_labels": timeline_labels,
        "timeline_data": timeline_data,
    })


@app.route("/api/incidents")
@login_required
def api_incidents():
    alerts = read_alerts()
    if not alerts:
        return jsonify([])

    # Group alerts by src_ip. Within each group, split into incidents whenever
    # there is a gap of more than 5 minutes between consecutive alerts.
    INCIDENT_GAP_S = 300

    by_src = defaultdict(list)
    for a in alerts:
        src = a.get("src_ip", "unknown")
        by_src[src].append(a)

    incidents = []
    for src, src_alerts in by_src.items():
        src_alerts.sort(key=lambda a: a.get("ts", 0))
        group = []
        for a in src_alerts:
            if group and float(a.get("ts", 0)) - float(group[-1].get("ts", 0)) > INCIDENT_GAP_S:
                incidents.append(_build_incident(src, group, ALERT_WEIGHTS, SEVERITY_WEIGHT, SEVERITY_ORDER))
                group = []
            group.append(a)
        if group:
            incidents.append(_build_incident(src, group, ALERT_WEIGHTS, SEVERITY_WEIGHT, SEVERITY_ORDER))

    incidents.sort(key=lambda i: i["last_seen"], reverse=True)
    return jsonify(incidents[:20])


def _build_incident(src, group, weights, sev_weights, sev_order):
    type_count = defaultdict(int)
    max_sev = "LOW"
    risk = 0
    for a in group:
        atype = a.get("alert_type", "UNKNOWN")
        type_count[atype] += 1
        sev = a.get("severity", "LOW")
        if sev_order.get(sev, 0) > sev_order.get(max_sev, 0):
            max_sev = sev
        score = weights.get(atype, 15) + sev_weights.get(sev, 10)
        risk = min(100, max(risk, score))

    top_types = sorted(type_count.items(), key=lambda x: x[1], reverse=True)
    return {
        "src_ip": src,
        "severity": max_sev,
        "risk_score": risk,
        "alert_count": len(group),
        "alert_types": [{"type": t, "count": c} for t, c in top_types],
        "first_seen": group[0].get("ts", 0),
        "last_seen": group[-1].get("ts", 0),
        "first_seen_fmt": datetime.fromtimestamp(float(group[0].get("ts", 0))).strftime("%H:%M:%S"),
        "last_seen_fmt": datetime.fromtimestamp(float(group[-1].get("ts", 0))).strftime("%H:%M:%S"),
    }


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
