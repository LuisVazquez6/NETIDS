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
ROOT = Path(__file__).resolve().parents[2]          # netids/
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

    for k in ("dst_port", "port"):
        if k in details:
            try:
                ports.append(int(details[k]))
            except Exception:
                pass

    for k in ("ports", "unique_ports"):
        if k in details and isinstance(details[k], list):
            for p in details[k]:
                try:
                    ports.append(int(p))
                except Exception:
                    pass

    if "targets" in details and isinstance(details["targets"], list):
        for t in details["targets"]:
            if isinstance(t, dict) and "port" in t:
                try:
                    ports.append(int(t["port"]))
                except Exception:
                    pass

    return ports


def risk_label(score: float) -> str:
    if score >= 150:
        return "CRITICAL"
    if score >= 80:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"


# -----------------------------
# Page config
# -----------------------------
st.set_page_config(
    page_title="NETIDS SOC Dashboard",
    page_icon=None,
    layout="wide",
)

# -----------------------------
# CSS (SOC-style polish + subtle animation)
# -----------------------------
st.markdown(
    """
<style>
/* Layout polish */
.block-container { padding-top: 1.25rem; padding-bottom: 2rem; }

/* Card styles */
.soc-card {
  background: rgba(255,255,255,0.04);
  border: 1px solid rgba(255,255,255,0.08);
  border-radius: 14px;
  padding: 14px 14px 10px 14px;
  box-shadow: 0 6px 18px rgba(0,0,0,0.18);
}
.soc-kpi-label { font-size: 0.78rem; opacity: 0.75; margin-bottom: 2px; }
.soc-kpi-value { font-size: 1.55rem; font-weight: 700; line-height: 1.2; }
.soc-kpi-sub   { font-size: 0.78rem; opacity: 0.70; margin-top: 4px; }

/* Subtle fade-in */
.fade-in { animation: fadeIn 240ms ease-in-out; }
@keyframes fadeIn { from { opacity: 0; transform: translateY(4px);} to { opacity: 1; transform: translateY(0);} }

/* Pulse for high urgency */
.pulse {
  animation: pulse 1.4s ease-in-out infinite;
}
@keyframes pulse {
  0% { box-shadow: 0 0 0 0 rgba(255, 75, 75, 0.0); }
  50% { box-shadow: 0 0 0 8px rgba(255, 75, 75, 0.08); }
  100% { box-shadow: 0 0 0 0 rgba(255, 75, 75, 0.0); }
}
/* Tighten tables */
div[data-testid="stDataFrame"] { border-radius: 12px; overflow: hidden; }
</style>
""",
    unsafe_allow_html=True,
)

# Header
st.markdown('<div class="fade-in">', unsafe_allow_html=True)
st.title("NETIDS SOC Dashboard")
st.caption("Real-time intrusion detection visibility: alerts, threat actors, trends, and drill-down.")
st.markdown("</div>", unsafe_allow_html=True)

# -----------------------------
# Sidebar controls
# -----------------------------
with st.sidebar:
    st.header("Controls")
    auto_refresh = st.toggle("Auto-refresh", value=False)
    refresh_s = st.slider("Refresh interval (seconds)", 2, 30, 5)

    st.divider()
    st.subheader("Data source")
    st.code(str(ALERTS_PATH), language="text")

if auto_refresh:
    st_autorefresh(interval=refresh_s * 1000, key="netids_refresh")

# -----------------------------
# Load data
# -----------------------------
raw = read_jsonl(ALERTS_PATH)
if not raw:
    st.warning("No alerts found yet. Generate traffic and refresh.")
    st.stop()

alerts_df = pd.DataFrame(raw)

for col in ["ts", "alert_type", "severity", "src_ip", "details"]:
    if col not in alerts_df.columns:
        alerts_df[col] = None

alerts_df["time"] = pd.to_datetime(alerts_df["ts"], unit="s", utc=True)
alerts_df = alerts_df.dropna(subset=["time"]).sort_values("time")

sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
alerts_df["severity"] = alerts_df["severity"].astype(str).str.upper().astype("category")
alerts_df["severity"] = alerts_df["severity"].cat.set_categories(sev_order, ordered=True)

# -----------------------------
# Filters
# -----------------------------
now = datetime.now().astimezone()
default_start = now - timedelta(hours=1)

fcol1, fcol2, fcol3, fcol4 = st.columns([1.2, 1.2, 1.2, 1.6])
with fcol1:
    start = st.date_input("Start date", value=default_start.date())
with fcol2:
    start_time = st.time_input("Start time", value=default_start.time())
with fcol3:
    end = st.date_input("End date", value=now.date())
with fcol4:
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
    src_query = st.text_input("Source IP contains", value="", placeholder="e.g., 192.168.56.")

if sev_sel:
    df_f = df_f[df_f["severity"].astype(str).isin(sev_sel)]
if type_sel:
    df_f = df_f[df_f["alert_type"].astype(str).isin(type_sel)]
if src_query.strip():
    df_f = df_f[df_f["src_ip"].astype(str).str.contains(src_query.strip(), na=False)]

# -----------------------------
# Scoring Engine
# -----------------------------
RULE_WEIGHTS = {
    "PORT_SCAN_SUSPECTED": 25,
    "SYN_BURST_SUSPECTED": 15,
    "ICMP_FLOOD_SUSPECTED": 10,
    "SSH_BRUTEFORCE_SUSPECTED": 20,
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
    at = str(row.get("alert_type", "")).upper()
    sev = str(row.get("severity", "")).upper()
    base = RULE_WEIGHTS.get(at, 5)
    mult = SEV_MULT.get(sev, 0.5)
    return float(base) * float(mult)

df_f["score"] = df_f.apply(compute_score_row, axis=1)

sev_rank = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
def pick_max_sev(series) -> str:
    vals = [str(x).upper() for x in series if pd.notna(x)]
    return max(vals, key=lambda x: sev_rank.get(x, 0), default="")

actors = (
    df_f.groupby("src_ip", dropna=False)
        .agg(
            risk_score=("score", "sum"),
            alerts=("alert_type", "count"),
            last_seen=("time", "max"),
            top_rule=("alert_type", lambda s: s.astype(str).value_counts().index[0] if len(s) else ""),
            max_sev=("severity", pick_max_sev),
        )
        .reset_index()
)
actors["risk_label"] = actors["risk_score"].apply(risk_label)
actors = actors.sort_values("risk_score", ascending=False)

with st.sidebar:
    st.divider()
    st.subheader("Triage")
    max_rs = int(max(10, actors["risk_score"].max() if len(actors) else 10))
    min_score = st.slider("Min risk score", 0, max_rs, 0)

actors_view = actors[actors["risk_score"] >= min_score].copy()

# -----------------------------
# Tabs
# -----------------------------
tab_overview, tab_actors, tab_trends, tab_alerts = st.tabs(
    ["Overview", "Threat Actors", "Trends", "Alerts"]
)

# -----------------------------
# OVERVIEW
# -----------------------------
with tab_overview:
    total_alerts = len(df_f)
    crit_high = int(df_f["severity"].astype(str).isin(["CRITICAL", "HIGH"]).sum())
    unique_attackers = int(df_f["src_ip"].nunique())
    last_seen = df_f["time"].max() if total_alerts > 0 else None

    # KPI cards
    k1, k2, k3, k4 = st.columns(4)

    def kpi_card(container, label: str, value: str, sub: str = "", urgent: bool = False) -> None:
        cls = "soc-card fade-in"
        if urgent:
            cls += " pulse"
        container.markdown(
            f"""
<div class="{cls}">
  <div class="soc-kpi-label">{label}</div>
  <div class="soc-kpi-value">{value}</div>
  <div class="soc-kpi-sub">{sub}</div>
</div>
""",
            unsafe_allow_html=True,
        )

    kpi_card(k1, "Total alerts", f"{total_alerts:,}", f"Window: {start_dt:%Y-%m-%d %H:%M} to {end_dt:%H:%M}")
    kpi_card(k2, "High urgency", f"{crit_high:,}", "CRITICAL + HIGH", urgent=(crit_high > 0))
    kpi_card(k3, "Unique attackers", f"{unique_attackers:,}", "Distinct src_ip")
    kpi_card(k4, "Last seen", last_seen.strftime("%Y-%m-%d %H:%M:%S") if last_seen else "—", "Most recent alert")

    st.divider()

    # Investigation focus
    st.subheader("Investigation Focus")
    actor_options = ["(ALL)"] + actors["src_ip"].astype(str).tolist()
    selected_actor = st.selectbox("Focus on attacker (src_ip)", actor_options)

    if selected_actor != "(ALL)":
        df_focus = df_f[df_f["src_ip"].astype(str) == selected_actor].copy()
        actor_row = actors[actors["src_ip"].astype(str) == selected_actor]
        if not actor_row.empty:
            row = actor_row.iloc[0]
            last_seen_str = row["last_seen"].strftime("%Y-%m-%d %H:%M:%S") if pd.notna(row["last_seen"]) else "-"
            st.markdown(
                f"""
<div class="soc-card fade-in">
  <div style="font-weight:700; font-size:1.05rem; margin-bottom:6px;">Incident Summary</div>
  <div style="opacity:0.9;">Attacker: <b>{selected_actor}</b></div>
  <div style="opacity:0.9;">Risk score: <b>{row['risk_score']:.1f}</b> ({row['risk_label']})</div>
  <div style="opacity:0.9;">Max severity: <b>{row['max_sev']}</b></div>
  <div style="opacity:0.9;">Alerts: <b>{int(row['alerts'])}</b></div>
  <div style="opacity:0.9;">Top rule: <b>{row['top_rule']}</b></div>
  <div style="opacity:0.9;">Last seen: <b>{last_seen_str}</b></div>
</div>
""",
                unsafe_allow_html=True,
            )
    else:
        df_focus = df_f.copy()
        st.caption("Select a specific attacker to pivot into investigation mode.")

    st.divider()

    # Charts row
    left, right = st.columns([1.6, 1.0])

    with left:
        st.subheader("Alerts over time")
        if len(df_focus) > 0:
            tmp = df_focus.copy()
            tmp["minute"] = tmp["time"].dt.floor("min")
            series = tmp.groupby("minute").size().reset_index(name="count")
            fig_time = px.area(series, x="minute", y="count", title="Alert volume (per minute)")
            fig_time.update_layout(template="plotly_dark", margin=dict(l=20, r=20, t=50, b=20))
            fig_time.update_xaxes(title_text="Time")
            fig_time.update_yaxes(title_text="Alerts")
            st.plotly_chart(fig_time, use_container_width=True)
        else:
            st.info("No alerts in this time window.")

    with right:
        st.subheader("Severity distribution")
        sev_counts = df_focus["severity"].astype(str).value_counts().reindex(sev_order, fill_value=0)
        sev_df = sev_counts.reset_index()
        sev_df.columns = ["severity", "count"]

        fig_donut = px.pie(
            sev_df,
            names="severity",
            values="count",
            hole=0.55,
            title="Severity donut",
        )
        fig_donut.update_layout(template="plotly_dark", margin=dict(l=20, r=20, t=50, b=20), showlegend=True)
        st.plotly_chart(fig_donut, use_container_width=True)

# -----------------------------
# THREAT ACTORS
# -----------------------------
with tab_actors:
    st.subheader("Top Threat Actors")
    if len(actors_view) == 0:
        st.info("No actors meet the current risk score threshold. Adjust the slider in the sidebar.")
    else:
        show = actors_view.copy()
        show["last_seen"] = show["last_seen"].dt.strftime("%Y-%m-%d %H:%M:%S")
        show = show[["risk_label", "src_ip", "risk_score", "alerts", "top_rule", "max_sev", "last_seen"]]
        st.dataframe(show, use_container_width=True, hide_index=True)

    st.divider()

    a1, a2, a3 = st.columns(3)

    with a1:
        st.subheader("Top attackers")
        top_ips = df_f["src_ip"].astype(str).value_counts().head(10)
        ips_df = top_ips.reset_index()
        ips_df.columns = ["src_ip", "count"]
        fig_ips = px.bar(ips_df, x="count", y="src_ip", title="Top attackers (by alert count)")
        fig_ips.update_layout(template="plotly_dark", height=340, margin=dict(l=20, r=20, t=50, b=20))
        st.plotly_chart(fig_ips, use_container_width=True)

    with a2:
        st.subheader("Top alert types")
        top_types = df_f["alert_type"].astype(str).value_counts().head(12)
        types_df = top_types.reset_index()
        types_df.columns = ["alert_type", "count"]
        fig_types = px.bar(types_df, x="count", y="alert_type", title="Top alert types")
        fig_types.update_layout(template="plotly_dark", height=340, margin=dict(l=20, r=20, t=50, b=20))
        st.plotly_chart(fig_types, use_container_width=True)

    with a3:
        st.subheader("Top targeted ports")
        port_rows: List[int] = []
        for _, r in df_f.iterrows():
            port_rows.extend(extract_ports(r.get("details")))
        if port_rows:
            pdf = pd.DataFrame({"port": port_rows})
            top_ports = pdf["port"].value_counts().head(12)
            ports_df = top_ports.reset_index()
            ports_df.columns = ["port", "count"]
            fig_ports = px.bar(ports_df, x="count", y="port", title="Top targeted ports")
            fig_ports.update_layout(template="plotly_dark", height=340, margin=dict(l=20, r=20, t=50, b=20))
            st.plotly_chart(fig_ports, use_container_width=True)
        else:
            st.caption("No port info found in details (dst_port/ports/targets).")

# -----------------------------
# TRENDS
# -----------------------------
with tab_trends:
    st.subheader("Alert Type Coverage")
    if len(df_f) > 0:
        # Treemap reads very SOC-like for coverage
        cov = df_f["alert_type"].astype(str).value_counts().reset_index()
        cov.columns = ["alert_type", "count"]
        fig_tree = px.treemap(cov, path=["alert_type"], values="count", title="Alert type coverage (treemap)")
        fig_tree.update_layout(template="plotly_dark", margin=dict(l=20, r=20, t=50, b=20))
        st.plotly_chart(fig_tree, use_container_width=True)
    else:
        st.info("No alerts in this time window.")

    st.divider()
    st.subheader("Time-of-day Heatmap")
    if len(df_f) > 0:
        tmp = df_f.copy()
        tmp["hour"] = tmp["time"].dt.hour
        tmp["dow"] = tmp["time"].dt.day_name()
        heat = tmp.groupby(["dow", "hour"]).size().reset_index(name="count")
        # order days
        days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
        heat["dow"] = pd.Categorical(heat["dow"], categories=days, ordered=True)
        heat = heat.sort_values(["dow", "hour"])
        fig_heat = px.density_heatmap(
            heat,
            x="hour",
            y="dow",
            z="count",
            histfunc="sum",
            title="Alert density by day/hour",
        )
        fig_heat.update_layout(template="plotly_dark", margin=dict(l=20, r=20, t=50, b=20))
        st.plotly_chart(fig_heat, use_container_width=True)
    else:
        st.info("No alerts to chart.")

# -----------------------------
# ALERTS
# -----------------------------
with tab_alerts:
    st.subheader("Alerts (filtered)")
    show_cols = ["time", "severity", "alert_type", "src_ip"]

    table = df_f.copy()
    table["time"] = table["time"].dt.strftime("%Y-%m-%d %H:%M:%S")
    st.dataframe(table[show_cols], use_container_width=True, hide_index=True)

    st.divider()
    st.subheader("Drill-down (latest first)")
    latest = df_f.sort_values("time", ascending=False).head(40)

    for _, row in latest.iterrows():
        t = row["time"].strftime("%Y-%m-%d %H:%M:%S")
        sev = str(row["severity"])
        at = str(row["alert_type"])
        ip = str(row["src_ip"])

        with st.expander(f"{t} | {sev} | {at} | {ip}"):
            st.write("Details")
            st.json(row.get("details", {}))