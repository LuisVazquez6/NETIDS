from __future__ import annotations

import json
import time
import os
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from functools import wraps
from flask import Flask, render_template, jsonify, request, session, redirect, url_for

app = Flask(__name__)
app.secret_key = os.urandom(24)

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


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        cfg = load_dashboard_config()
        username = cfg.get("username", "admin")
        password = cfg.get("password", "netids2025")
        if request.form.get("username") == username and request.form.get("password") == password:
            session["logged_in"] = True
            session["username"] = username
            return redirect(url_for("index"))
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
    ALERT_WEIGHTS = {
        "PORT_SCAN_SUSPECTED": 30,
        "SYN_BURST_SUSPECTED": 35,
        "ICMP_FLOOD_SUSPECTED": 25,
        "SSH_BRUTEFORCE_SUSPECTED": 40,
    }
    SEVERITY_WEIGHT = {"LOW": 10, "MEDIUM": 20, "HIGH": 35}
    SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}

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
