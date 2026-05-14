from __future__ import annotations

import hashlib
import hmac
import json
import sys
import time
import os
import signal
import subprocess
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from functools import wraps
from flask import Flask, render_template, jsonify, request, session, redirect, url_for

# Make sure src/ is on the path so we can import shared modules
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from correlation.incident_manager import ALERT_WEIGHTS, SEVERITY_WEIGHT, detect_chain  # noqa: E402
from models.incidents import SEVERITY_ORDER  # noqa: E402
from response.ai_triage import analyze_async  # noqa: E402

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

# Persist a password hash salt so hashes survive restarts.
_SALT_FILE = Path(__file__).resolve().parents[2] / ".flask_salt"
try:
    if _SALT_FILE.exists():
        _HASH_SALT = _SALT_FILE.read_bytes()
    else:
        _HASH_SALT = os.urandom(16)
        _SALT_FILE.write_bytes(_HASH_SALT)
except Exception:
    _HASH_SALT = b"netids_fallback_"

# Login rate limiter: max 5 attempts per IP within 60 seconds.
_login_attempts: dict[str, list[float]] = defaultdict(list)
_LOGIN_MAX = 5
_LOGIN_WINDOW = 60

ROOT = Path(__file__).resolve().parents[2]
ALERTS_PATH  = ROOT / "logs" / "alerts.jsonl"
TRIAGE_PATH  = ROOT / "logs" / "triage.jsonl"
CLEARED_PATH = ROOT / "logs" / "cleared_incidents.json"
CONFIG_PATH  = ROOT / "config.json"
IDS_PID_PATH = ROOT / "logs" / "ids.pid"
IDS_START_TS = {}   # {"ts": float}


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
    return hashlib.pbkdf2_hmac("sha256", value.encode("utf-8"), _HASH_SALT, 100_000).hex()


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


@app.route("/api/alerts", methods=["DELETE"])
@login_required
def clear_alerts():
    try:
        ALERTS_PATH.write_text("", encoding="utf-8")
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"ok": True})


@app.route("/api/alerts/resolve", methods=["POST"])
@login_required
def resolve_alert():
    data = request.get_json(silent=True) or {}
    try:
        ts = float(data.get("ts"))
    except (TypeError, ValueError):
        return jsonify({"error": "ts required"}), 400

    if not ALERTS_PATH.exists():
        return jsonify({"ok": True, "updated": False})

    lines = ALERTS_PATH.read_text(encoding="utf-8").splitlines()
    new_lines = []
    updated = False
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if not obj.get("resolved") and float(obj.get("ts", -1)) == ts:
                obj["resolved"] = True
                updated = True
                new_lines.append(json.dumps(obj))
                continue
        except Exception:
            pass
        new_lines.append(line)

    ALERTS_PATH.write_text("\n".join(new_lines) + ("\n" if new_lines else ""), encoding="utf-8")
    return jsonify({"ok": True, "updated": updated})


@app.route("/api/alerts")
@login_required
def api_alerts():
    alerts = [a for a in read_alerts() if not a.get("resolved")]

    # Optional filters via query params: ?severity=HIGH&type=PORT_SCAN_SUSPECTED&src=1.2.3.4&limit=200
    sev_filter = request.args.get("severity", "").upper()
    type_filter = request.args.get("type", "")
    src_filter = request.args.get("src", "")
    try:
        limit = min(int(request.args.get("limit", 100)), 500)
    except (ValueError, TypeError):
        limit = 100

    if sev_filter:
        alerts = [a for a in alerts if a.get("severity", "").upper() == sev_filter]
    if type_filter:
        alerts = [a for a in alerts if a.get("alert_type", "") == type_filter]
    if src_filter:
        alerts = [a for a in alerts if a.get("src_ip", "") == src_filter]

    alerts = sorted(alerts, key=lambda a: a.get("ts", 0), reverse=True)[:limit]
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


@app.route("/api/geo")
@login_required
def api_geo():
    alerts = read_alerts()
    seen = {}
    for a in alerts:
        src = a.get("src_ip", "")
        if not src:
            continue
        enrichment = a.get("enrichment", {}) or {}
        lat = enrichment.get("src_lat")
        lon = enrichment.get("src_lon")
        if lat is None or lon is None:
            continue
        if src not in seen:
            seen[src] = {
                "ip": src,
                "lat": lat,
                "lon": lon,
                "country": enrichment.get("src_country", ""),
                "org": enrichment.get("src_org", ""),
                "count": 0,
                "severity": "LOW",
            }
        seen[src]["count"] += 1
        sev = a.get("severity", "LOW")
        order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
        if order.get(sev, 0) > order.get(seen[src]["severity"], 0):
            seen[src]["severity"] = sev
    return jsonify(list(seen.values()))


@app.route("/api/incidents")
@login_required
def api_incidents():
    alerts = read_alerts()
    if not alerts:
        return jsonify([])

    cleared_at = 0.0
    if CLEARED_PATH.exists():
        try:
            cleared_at = float(json.loads(CLEARED_PATH.read_text()).get("cleared_at", 0))
        except Exception:
            pass

    # Group by (src_ip, alert_type) — one incident card per attack type per source
    by_src_type = defaultdict(list)
    for a in alerts:
        src   = a.get("src_ip", "unknown")
        atype = a.get("alert_type", "UNKNOWN")
        by_src_type[(src, atype)].append(a)

    incidents = []
    for (src, atype), group in by_src_type.items():
        group.sort(key=lambda a: a.get("ts", 0))
        inc = _build_incident(src, group, ALERT_WEIGHTS, SEVERITY_WEIGHT, SEVERITY_ORDER)
        inc["alert_type_key"] = atype
        if inc["last_seen"] > cleared_at:
            incidents.append(inc)

    incidents.sort(key=lambda i: i["last_seen"], reverse=True)
    return jsonify(incidents)


@app.route("/api/incidents/clear", methods=["POST"])
@login_required
def clear_incidents():
    CLEARED_PATH.parent.mkdir(parents=True, exist_ok=True)
    CLEARED_PATH.write_text(json.dumps({"cleared_at": time.time()}))
    return jsonify({"ok": True})


def _build_incident(src, group, weights, sev_weights, sev_order):
    type_count = defaultdict(int)
    mitre = set()
    max_sev = "LOW"
    risk = 0
    enrichment = {}
    for a in group:
        atype = a.get("alert_type", "UNKNOWN")
        type_count[atype] += 1
        sev = a.get("severity", "LOW")
        if sev_order.get(sev, 0) > sev_order.get(max_sev, 0):
            max_sev = sev
        score = weights.get(atype, 15) + sev_weights.get(sev, 10)
        risk = min(100, max(risk, score))
        mt = a.get("mitre_technique", "")
        if mt and mt != "UNKNOWN":
            mitre.add(mt)
        if not enrichment:
            enrichment = a.get("enrichment") or {}

    top_types = sorted(type_count.items(), key=lambda x: x[1], reverse=True)
    chain = detect_chain(set(type_count.keys()))
    return {
        "src_ip": src,
        "severity": max_sev,
        "risk_score": risk,
        "alert_count": len(group),
        "alert_types": [{"type": t, "count": c} for t, c in top_types],
        "attack_chain": chain,
        "mitre_techniques": sorted(mitre),
        "country":      enrichment.get("src_country", ""),
        "country_code": enrichment.get("src_country_code", ""),
        "org":          enrichment.get("src_org", ""),
        "first_seen": group[0].get("ts", 0),
        "last_seen": group[-1].get("ts", 0),
        "first_seen_fmt": datetime.fromtimestamp(float(group[0].get("ts", 0))).strftime("%H:%M:%S"),
        "last_seen_fmt": datetime.fromtimestamp(float(group[-1].get("ts", 0))).strftime("%H:%M:%S"),
    }


@app.route("/api/triage")
@login_required
def api_triage():
    if not TRIAGE_PATH.exists():
        return jsonify([])
    results = []
    for line in TRIAGE_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except Exception:
            continue
    results.sort(key=lambda x: x.get("triage_ts", 0), reverse=True)
    return jsonify(results[:20])


@app.route("/api/triage", methods=["DELETE"])
@login_required
def clear_triage():
    if TRIAGE_PATH.exists():
        TRIAGE_PATH.write_text("", encoding="utf-8")
    return jsonify({"ok": True})


@app.route("/api/ids/status")
@login_required
def ids_status():
    pid = _ids_pid()
    running = pid is not None
    uptime = 0
    if running and IDS_START_TS.get("ts"):
        uptime = int(time.time() - IDS_START_TS["ts"])

    alerts = read_alerts()
    by_type = defaultdict(lambda: {"count": 0, "severity": "", "last_ts": ""})
    for a in alerts:
        atype = a.get("alert_type", "")
        if not atype:
            continue
        by_type[atype]["count"] += 1
        sev = a.get("severity", "LOW")
        if not by_type[atype]["severity"] or \
           {"HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(sev, 0) > \
           {"HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(by_type[atype]["severity"], 0):
            by_type[atype]["severity"] = sev
        try:
            t = datetime.fromtimestamp(float(a.get("ts", 0))).strftime("%H:%M:%S")
            by_type[atype]["last_ts"] = t
        except Exception:
            pass

    return jsonify({
        "running": running,
        "pid": pid,
        "uptime_s": uptime,
        "detectors": dict(by_type),
    })


@app.route("/api/ids/start", methods=["POST"])
@login_required
def ids_start():
    if _ids_pid() is not None:
        return jsonify({"ok": False, "error": "already running"})
    data  = request.get_json(silent=True) or {}
    iface = data.get("iface", "enp0s3")
    ids_py = ROOT / "src" / "ids.py"
    env = os.environ.copy()
    try:
        proc = subprocess.Popen(
            [sys.executable, str(ids_py), "--live", "--iface", iface],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env=env, cwd=str(ROOT),
        )
        IDS_PID_PATH.parent.mkdir(parents=True, exist_ok=True)
        IDS_PID_PATH.write_text(str(proc.pid))
        IDS_START_TS["ts"] = time.time()
        return jsonify({"ok": True, "pid": proc.pid})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/ids/stop", methods=["POST"])
@login_required
def ids_stop():
    pid = _ids_pid()
    if pid is None:
        return jsonify({"ok": False, "error": "not running"})
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})
    IDS_PID_PATH.unlink(missing_ok=True)
    IDS_START_TS.clear()
    return jsonify({"ok": True})


def _ids_pid():
    if not IDS_PID_PATH.exists():
        return None
    try:
        pid = int(IDS_PID_PATH.read_text().strip())
        os.kill(pid, 0)   # 0 = just check existence
        return pid
    except (ValueError, ProcessLookupError, OSError):
        IDS_PID_PATH.unlink(missing_ok=True)
        return None


@app.route("/api/triage/trigger", methods=["POST"])
@login_required
def trigger_triage():
    data = request.get_json(silent=True) or {}
    src_ip     = data.get("src_ip", "")
    alert_type = data.get("alert_type", "")
    if not src_ip:
        return jsonify({"error": "src_ip required"}), 400
    alerts = [
        a for a in read_alerts()
        if a.get("src_ip") == src_ip
        and (not alert_type or a.get("alert_type") == alert_type)
    ]
    if not alerts:
        return jsonify({"error": "no alerts"}), 404
    inc = _build_incident(src_ip, alerts, ALERT_WEIGHTS, SEVERITY_WEIGHT, SEVERITY_ORDER)
    inc["alert_type_key"] = alert_type
    analyze_async(inc)
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
