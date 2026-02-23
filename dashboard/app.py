from __future__ import annotations
from streamlit_autorefresh import st_autorefresh

import json
import time
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

import pandas as pd
import streamlit as st
import plotly.express as px


# -----------------------------
# Paths
# -----------------------------
ROOT = Path(__file__).resolve().parents[1]          # netids/
ALERTS_PATH = ROOT / "logs" / "alerts.jsonl"        # netids/logs/alerts.jsonl


# -----------------------------
# Helpers
# -----------------------------
def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def to_dt(ts_val: Any) -> Optional[datetime]:
    try:
        return datetime.fromtimestamp(float(ts_val), tz=timezone.utc).astimezone()
    except Exception:
        return None


def extract_ports(details: Any) -> List[int]:
    if not isinstance(details, dict):
        return []
    ports: List[int] = []

    # single port keys
    for k in ("dst_port", "port"):
        if k in details:
            try:
                ports.append(int(details[k]))
            except Exception:
                pass

    # list port keys
    for k in ("ports", "unique_ports"):
        if k in details and isinstance(details[k], list):
            for p in details[k]:
                try:
                    ports.append(int(p))
                except Exception:
                    pass

    # nested targets list
    if "targets" in details and isinstance(details["targets"], list):
        for t in details["targets"]:
            if isinstance(t, dict) and "port" in t:
                try:
                    ports.append(int(t["port"]))
                except Exception:
                    pass

    return ports


# -----------------------------
# Page config
# -----------------------------
st.set_page_config(
    page_title="NETIDS SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ NETIDS SOC Dashboard")
st.caption("Real-time intrusion detection visibility (alerts, attackers, trends, drill-down).")


# -----------------------------
# Sidebar controls
# -----------------------------
with st.sidebar:
    st.header("Controls")
    auto_refresh = st.toggle("Auto-refresh", value=False)
    refresh_s = st.slider("Refresh interval (seconds)", 2, 30, 5)
    st.divider()
    st.subheader("Data source")
    st.write(f"Path: `{ALERTS_PATH}`")
    st.caption("Make sure your IDS writes JSONL to this path.")

if auto_refresh:
    st_autorefresh(interval = refresh_s * 1000, key = "netids_refresh")


# -----------------------------
# Load data
# -----------------------------
raw = read_jsonl(ALERTS_PATH)
if not raw:
    st.warning("No alerts found yet. Trigger some traffic and refresh.")
    st.stop()

alerts_df = pd.DataFrame(raw)

# Ensure expected columns exist
for col in ["ts", "alert_type", "severity", "src_ip", "details"]:
    if col not in alerts_df.columns:
        alerts_df[col] = None

# Create time column + clean
alerts_df["time"] = alerts_df["ts"].apply(to_dt)
alerts_df = alerts_df.dropna(subset=["time"]).sort_values("time")

# Severity ordering
sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
alerts_df["severity"] = alerts_df["severity"].astype(str).str.upper().astype("category")
alerts_df["severity"] = alerts_df["severity"].cat.set_categories(sev_order, ordered=True)


# -----------------------------
# Filters
# -----------------------------
now = datetime.now().astimezone()
default_start = now - timedelta(hours=1)

colA, colB, colC, colD = st.columns([1.2, 1.2, 1.2, 1.6])
with colA:
    start = st.date_input("Start date", value=default_start.date())
with colB:
    start_time = st.time_input("Start time", value=default_start.time())
with colC:
    end = st.date_input("End date", value=now.date())
with colD:
    end_time = st.time_input("End time", value=now.time())

start_dt = datetime.combine(start, start_time).astimezone()
end_dt = datetime.combine(end, end_time).astimezone()

df_f = alerts_df[(alerts_df["time"] >= start_dt) & (alerts_df["time"] <= end_dt)].copy()

c1, c2, c3 = st.columns([1.2, 1.2, 1.6])
with c1:
    sev_sel = st.multiselect(
        "Severity",
        options=sev_order,
        default=[s for s in sev_order if s in df_f["severity"].astype(str).unique()],
    )
with c2:
    types = sorted(df_f["alert_type"].astype(str).unique().tolist())
    type_sel = st.multiselect("Alert type", options=types, default=types)
with c3:
    src_query = st.text_input("Source IP contains", value="", placeholder="e.g., 192.168.1.")

if sev_sel:
    df_f = df_f[df_f["severity"].astype(str).isin(sev_sel)]
if type_sel:
    df_f = df_f[df_f["alert_type"].astype(str).isin(type_sel)]
if src_query.strip():
    df_f = df_f[df_f["src_ip"].astype(str).str.contains(src_query.strip(), na=False)]

st.divider()

# -----------------------------
# Scoring Engine 
# -----------------------------
RULE_WEIGHTS = {
    "PORT_SCAN_SUSPECTED": 25,
    "SYN_BURST_SUSPECTED": 15,
    "ICMP_FLOOD_SUSPECTED": 10,
    "SSH_BRUTE_FORCE_SUSPECTED": 20,
}

SEV_MULT = {
    "CRITICAL": 3.0,
    "HIGH": 2.0,
    "MEDIUM": 1.0,
    "LOW": 0.5,
    "INFO": 0.2,
}
def compute_score_row(row) -> float:
    at = str(row.get("alert_type","")).upper()
    sev = str(row.get("severity","")).upper()

    base = RULE_WEIGHTS.get(at,5)
    mult = SEV_MULT.get(sev, 0.5)
    return float(base) * float(mult)

df_f["score"] = df_f.apply(compute_score_row, axis = 1)
sev_rank = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

def pick_max_sev(series) -> str:
    vals = [str(x).upper() for x in series if pd.notna(x)]
    return max(vals, key = lambda x: sev_rank.get(x, 0), default = "")

actors = (
    df_f.groupby("src_ip",dropna = False)
        .agg(
            risk_score = ("score","sum"),
            alerts = ("alert_type", "count"),
            last_seen = ("time", "max"),
            top_rule=("alert_type", lambda s: s.astype(str).value_counts().index[0] if len(s) else ""),
            max_sev = ("severity", pick_max_sev),
        )
        .reset_index()
)
actors = actors.sort_values("risk_score", ascending = False)

st.divider()
st.subheader("Investigation Focus")

actor_options = ["(ALL)"] + actors["src_ip"].astype(str).tolist()
selected_actor = st.selectbox("Focus on specific attacker (src_ip)", actor_options)

if selected_actor != "(ALL)":
    df_f = df_f[df_f["src_ip"].astype(str) == selected_actor]

    actor_row = actors[actors["src_ip"].astype(str) == selected_actor]
    if not actor_row.empty:
        row = actor_row.iloc[0]

        last_seen_str = (
            row["last_seen"].strftime("%Y-%m-%d %H:%M:%S")
            if pd.notna(row["last_seen"])
            else "-"
        )
        summary_text = (
            f"Incident Summary - {selected_actor}\n"
            f"Risk Score: {row['risk_score']:.1f}\n"
            f"Max Severity: {row['max_sev']}\n"
            f"Alerts: {int(row['alerts'])}\n"
            f"Top Rule: {row['top_rule']}\n"
            f"Last Seen: {last_seen_str}"
        )
        st.info(summary_text)
else:
    st.caption("Tip: select an attacker to pivot the entire dashboard into investigation mode.")


def risk_lable(score: float) -> str:
    if score >= 150:
        return "CRITICAL"
    if score >= 80:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"

actors["risk_label"] = actors["risk_score"].apply(risk_lable)

with st.sidebar:
    st.divider()
    st.subheader("Triage")
    min_score = st.slider("Min risk score", 0, int(max(10, actors["risk_score"].max() if len(actors) else 10)), 0)

actors_view = actors[actors["risk_score"] >= min_score].copy()

# -----------------------------
# KPI row
# -----------------------------
total_alerts = len(df_f)
crit_high = int(df_f["severity"].astype(str).isin(["CRITICAL", "HIGH"]).sum())
unique_attackers = int(df_f["src_ip"].nunique())
last_seen = df_f["time"].max() if total_alerts > 0 else None

k1, k2, k3, k4 = st.columns(4)
k1.metric("Total alerts", f"{total_alerts:,}")
k2.metric("Critical/High", f"{crit_high:,}")
k3.metric("Unique attackers", f"{unique_attackers:,}")
k4.metric("Last seen", last_seen.strftime("%Y-%m-%d %H:%M:%S") if last_seen else "—")

st.header(" Top Threat Actors")

if len(actors_view) == 0:
    st.info("No actors meet the current risk score threshold. Adjust the slider in the sidebar to see more.")
else:
    show = actors_view.copy()
    show["last_seen"] = show["last_seen"].dt.strftime("%Y-%m-%d %H:%M:%S")
    show = show[["risk_label", "src_ip", "risk_score", "alerts", "top_rule", "max_sev", "last_seen"]]
    st.dataframe(show, use_container_width = True, hide_index = True)


# -----------------------------
# Charts row
# -----------------------------
left, right = st.columns([1.6, 1.0])

with left:
    st.subheader("📈 Alerts over time")
    if total_alerts > 0:
        tmp = df_f.copy()
        tmp["minute"] = tmp["time"].dt.floor("min")
        series = tmp.groupby("minute").size().reset_index(name="count")
        fig_time = px.line(
            series,
            x = "minute",
            y = "count",
            title = "Alerts Over Time",
        )

        fig_time.update_layout(
            template = "plotly_dark",
            xaxis_title = "Time",
            yaxis_title = "Alert Count",
            margin = dict(l = 20, r = 20, t = 50, b = 20),
        )
        st.plotly_chart(fig_time, use_container_width = True)
    else:
        st.info("No alerts in this time window.")

with right:
    st.subheader("⚠️ Severity breakdown")
    sev_counts = df_f["severity"].astype(str).value_counts().reindex(sev_order, fill_value=0)
    sev_df = sev_counts.reset_index()
    sev_df.columns = ["severity", "count"]

    fig = px.bar(
        sev_df,
        x = "severity",
        y = "count",
        color = "severity",
        color_discrete_map = {
            "CRITICAL": "#ff4b4b",
            "HIGH": "#ff914d",
            "MEDIUM": "#f7c948",
            "LOW": "#4dabf7",
            "INFO": "#6c757d",
        },
        title = "Severity Distribution"
    )
    fig.update_layout(
        template = "plotly_dark",
        xaxis_title = "Severity",
        yaxis_title = "Alert Count",
        showlegend = False,
        margin = dict(l = 20, r = 20, t = 50, b = 20)
    )
    st.plotly_chart(fig, use_container_width = True)


# -----------------------------
# Attackers + ports + types
# -----------------------------
a1, a2, a3 = st.columns(3)

with a1:
    st.subheader("🎯 Top attackers (src_ip)")
    top_ips = df_f["src_ip"].astype(str).value_counts().head(10)
    ips_df = top_ips.reset_index()
    ips_df.columns = ["src_ip", "count"]
    fig_ips = px.bar(
        ips_df,
        x = "count",
        y = "src_ip",
        title = "Top Attacker",
    )
    fig_ips.update_traces(
    width=0.35   # smaller = thinner bars (try 0.3–0.5)
    )

    fig_ips.update_layout(
        template="plotly_dark",
        bargap=0.6,
        height=330,
        xaxis_title="Alert Count",
        yaxis_title="Source IP",
        margin=dict(l=20, r=20, t=40, b=20),
    )
    st.plotly_chart(fig_ips, use_container_width = True)

with a2:
    st.subheader("🧩 Top alert types")
    top_types = df_f["alert_type"].astype(str).value_counts().head(10)
    types_df = top_types.reset_index()
    types_df.columns = ["alert_type", "count"]

    fig_types = px.bar(
        types_df,
        x="count",
        y="alert_type",
        title="Top Alert Types",
    )

    fig_types.update_traces(width=0.35)

    fig_types.update_layout(
        template="plotly_dark",
        bargap=0.6,
        height=330,
        xaxis_title="Alert Count",
        yaxis_title="Alert Type",
        margin=dict(l=20, r=20, t=40, b=20),
    )

    st.plotly_chart(fig_types, use_container_width=True)

with a3:
    st.subheader("🔌 Top targeted ports")
    port_rows: List[int] = []
    for _, r in df_f.iterrows():
        port_rows.extend(extract_ports(r.get("details")))
    if port_rows:
        pdf = pd.DataFrame({"port": port_rows})
        top_ports = pdf["port"].value_counts().head(10)
        ports_df = top_ports.reset_index()
        ports_df.columns = ["port", "count"]

        fig_ports = px.bar(
            ports_df,
            x = "count",
            y = "port",
            title = "Top Targeted Ports",
        )
        fig_ports.update_traces(width = 0.35)
        fig_ports.update_layout(
            template = "plotly_dark",
            bargap = 0.6,
            height = 330,
            xaxis_title = "Hits",
            yaxis_title = "Port",
            margin = dict(l = 20, r = 20, t = 40, b = 20),
        )
        st.plotly_chart(fig_ports, use_container_width = True)
    else:
        st.caption("No port info found in `details` (dst_port/ports/targets).")

st.divider()


# -----------------------------
# Alerts table + drill-down
# -----------------------------
st.subheader("🧾 Alerts (filtered)")
show_cols = ["time", "severity", "alert_type", "src_ip"]

table = df_f.copy()
table["time"] = table["time"].dt.strftime("%Y-%m-%d %H:%M:%S")

st.dataframe(table[show_cols], use_container_width=True, hide_index=True)

st.subheader("🔎 Drill-down (latest first)")
latest = df_f.sort_values("time", ascending=False).head(25)

for _, row in latest.iterrows():
    t = row["time"].strftime("%Y-%m-%d %H:%M:%S")
    sev = str(row["severity"])
    at = str(row["alert_type"])
    ip = str(row["src_ip"])

    with st.expander(f"{t} | {sev} | {at} | {ip}"):
        st.write("**Details**")
        st.json(row.get("details", {}))