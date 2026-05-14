import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, Polygon
import matplotlib.colors as mcolors

# ── Canvas ────────────────────────────────────────────────────────────────────
BG   = "#0d2b1f"
TEXT = "#e8e8e8"
DIM  = "#4a7a5a"

fig, ax = plt.subplots(figsize=(11, 20))
fig.patch.set_facecolor(BG)
ax.set_facecolor(BG)
ax.set_xlim(0, 12)
ax.set_ylim(0, 25)
ax.axis("off")

# Stage palette
C_IN  = "#3776ab"   # blue   – input / capture
C_PRC = "#1db87a"   # green  – processing
C_DET = "#e05252"   # red    – detection engine
C_ALT = "#e0a832"   # yellow – alert pipeline
C_MIT = "#c8102e"   # crimson– MITRE mapper
C_OUT = "#9b59b6"   # purple – output

# ── Layout constants ──────────────────────────────────────────────────────────
CX  = 6.0            # horizontal center of all main elements
BW  = 10.0           # main box width   (left=1.0, right=11.0)
BH  = 0.80           # standard box height
AH  = 0.48           # vertical arrow gap

# Detection engine container spans x: 0.8 → 11.2  (width 10.4)
DET_L, DET_R = 0.8, 11.2
DET_W = DET_R - DET_L   # 10.4

# Row-1 (4 boxes): equal sections of DET_W/4 = 2.6 each
R1_XS = [DET_L + 2.6*i + 1.3 for i in range(4)]   # [2.1, 4.7, 7.3, 9.9]
R1_W  = 2.20
R1_H  = 0.62

# Row-2 (3 boxes): equal sections of DET_W/3 ≈ 3.467 each
R2_XS = [DET_L + (DET_W/3)*i + (DET_W/6) for i in range(3)]  # [2.53, 6.0, 9.47]
R2_W  = 3.00
R2_H  = 0.62

# Output boxes (same centers as row-2)
OUT_XS = R2_XS
OUT_W  = 3.00
OUT_H  = 1.20

# ── Y positions (top-to-bottom, larger = higher) ──────────────────────────────
Y = {}
Y["title"]      = 24.3
Y["sub"]        = 23.80
Y["divider"]    = 23.45

Y["b1"]         = 22.95   # Network Traffic Input
Y["b2"]         = 22.95 - BH - AH        # Scapy Sniffer   = 21.67
Y["b3"]         = Y["b2"] - BH - AH      # Packet Parser   = 20.39

# Detection container  (title 0.28 below top, row1 0.72, row2 1.64, bot 2.25)
Y["det_top"]    = Y["b3"] - BH/2 - AH
Y["det_row1"]   = Y["det_top"] - 0.72
Y["det_row2"]   = Y["det_row1"] - R1_H/2 - 0.30 - R2_H/2
Y["det_bot"]    = Y["det_row2"] - R2_H/2 - 0.34
Y["det_cy"]     = (Y["det_top"] + Y["det_bot"]) / 2

# Diamond
Y["diam"]       = Y["det_bot"] - AH - 0.60            # center of diamond
DIAM_H = 1.20
DIAM_W = 5.00

# Alert pipeline
Y["b4"]         = Y["diam"] - DIAM_H/2 - AH            # Alert Generator
Y["b5"]         = Y["b4"] - BH - AH                    # MITRE Mapper
Y["b6"]         = Y["b5"] - BH - AH                    # IP Enrichment
Y["b7"]         = Y["b6"] - BH - AH                    # Incident Correlator

# Fan-out and outputs
Y["fan"]        = Y["b7"] - BH/2 - 0.50               # horizontal fan line
Y["out"]        = Y["fan"] - 0.50 - OUT_H/2            # output box centers

# ── Helpers ───────────────────────────────────────────────────────────────────

def rgba(hex_color, alpha=0.18):
    r, g, b = mcolors.to_rgb(hex_color)
    return (r, g, b, alpha)

def draw_box(cx, cy, w, h, title, color, sub=None, fs=9.0):
    ax.add_patch(FancyBboxPatch(
        (cx - w/2, cy - h/2), w, h,
        boxstyle="round,pad=0.13",
        facecolor=rgba(color, 0.18), edgecolor=color,
        linewidth=2.0, zorder=3))
    ty = cy + 0.17 if sub else cy
    ax.text(cx, ty, title, ha='center', va='center',
            color=TEXT, fontsize=fs, fontweight='bold', zorder=4,
            linespacing=1.30)
    if sub:
        ax.text(cx, cy - 0.22, sub, ha='center', va='center',
                color=color, fontsize=fs - 2.0, zorder=4, alpha=0.88)

def draw_mini(cx, cy, w, h, label, color):
    ax.add_patch(FancyBboxPatch(
        (cx - w/2, cy - h/2), w, h,
        boxstyle="round,pad=0.08",
        facecolor=rgba(color, 0.30), edgecolor=color,
        linewidth=1.3, zorder=5))
    ax.text(cx, cy, label, ha='center', va='center',
            color=TEXT, fontsize=7.5, fontweight='bold', zorder=6,
            linespacing=1.28)

def draw_diamond(cx, cy, w, h, label, color):
    pts = [[cx, cy+h/2], [cx+w/2, cy], [cx, cy-h/2], [cx-w/2, cy]]
    ax.add_patch(Polygon(pts, closed=True,
                         facecolor=rgba(color, 0.22), edgecolor=color,
                         linewidth=2.2, zorder=3))
    ax.text(cx, cy, label, ha='center', va='center',
            color=TEXT, fontsize=9.5, fontweight='bold', zorder=4,
            linespacing=1.35)

def varrow(x, y_start, y_end, color, label=None):
    ax.annotate('', xy=(x, y_end), xytext=(x, y_start),
                arrowprops=dict(arrowstyle='->', color=color,
                                lw=1.9, mutation_scale=20), zorder=6)
    if label:
        ax.text(x + 0.18, (y_start + y_end)/2, label,
                ha='left', va='center', color=color, fontsize=7.5)

def harrow(x_start, x_end, y, color, label=None):
    ax.annotate('', xy=(x_end, y), xytext=(x_start, y),
                arrowprops=dict(arrowstyle='->', color=color,
                                lw=1.7, mutation_scale=18), zorder=6)
    if label:
        mid = (x_start + x_end) / 2
        ax.text(mid, y + 0.12, label,
                ha='center', va='bottom', color=color, fontsize=7.5)

# ── Title ─────────────────────────────────────────────────────────────────────
ax.text(CX, Y["title"], "NetIDS — System Architecture",
        ha='center', va='center', color=TEXT,
        fontsize=15, fontweight='bold')
ax.text(CX, Y["sub"], "Functional Flow Diagram",
        ha='center', va='center', color=DIM,
        fontsize=10, fontstyle='italic')
ax.plot([1.0, 11.0], [Y["divider"], Y["divider"]], color=C_PRC, lw=1.2, alpha=0.45)

# ── Box 1 — Network Traffic Input ─────────────────────────────────────────────
draw_box(CX, Y["b1"], BW, BH,
         "NETWORK TRAFFIC INPUT", C_IN,
         sub="Live capture: eth0 / wlan0     OR     Offline: .pcap / .pcapng file")

varrow(CX, Y["b1"] - BH/2, Y["b2"] + BH/2, C_IN)

# ── Box 2 — Scapy Sniffer ─────────────────────────────────────────────────────
draw_box(CX, Y["b2"], BW, BH,
         "SCAPY PACKET SNIFFER", C_IN,
         sub="sniff() callback  ·  PcapReader for offline  ·  promiscuous mode")

varrow(CX, Y["b2"] - BH/2, Y["b3"] + BH/2, C_PRC)

# ── Box 3 — Packet Parser ─────────────────────────────────────────────────────
draw_box(CX, Y["b3"], BW, BH,
         "PACKET HEADER PARSER", C_PRC,
         sub="IP src/dst  ·  TCP/UDP ports  ·  ICMP type  ·  DNS query  ·  HTTP verb")

varrow(CX, Y["b3"] - BH/2, Y["det_top"], C_PRC)

# ── Detection Engine container ────────────────────────────────────────────────
det_h = Y["det_top"] - Y["det_bot"]
ax.add_patch(FancyBboxPatch(
    (DET_L, Y["det_bot"]), DET_W, det_h,
    boxstyle="round,pad=0.15",
    facecolor=rgba(C_DET, 0.08), edgecolor=C_DET,
    linewidth=2.2, linestyle='--', zorder=2))

ax.text(CX, Y["det_top"] - 0.28,
        "DETECTION ENGINE  —  7 parallel rule evaluators  (rolling time windows)",
        ha='center', va='center', color=C_DET,
        fontsize=9.0, fontweight='bold', zorder=4)

# Row 1 mini-boxes (4)
r1_labels = ["Port Scan\nT1046", "SYN Flood\nT1499",
             "SSH Brute Force\nT1110", "ICMP Flood\nT1018"]
for cx, lbl in zip(R1_XS, r1_labels):
    draw_mini(cx, Y["det_row1"], R1_W, R1_H, lbl, C_DET)

# Row 2 mini-boxes (3)
r2_labels = ["DNS Tunneling\nT1071.004",
             "HTTP Brute Force\nT1110.003",
             "Slow Loris\nT1499"]
for cx, lbl in zip(R2_XS, r2_labels):
    draw_mini(cx, Y["det_row2"], R2_W, R2_H, lbl, C_DET)

varrow(CX, Y["det_bot"], Y["diam"] + DIAM_H/2, C_DET)

# ── Diamond — Threshold Decision ──────────────────────────────────────────────
draw_diamond(CX, Y["diam"], DIAM_W, DIAM_H, "THRESHOLD\nEXCEEDED?", C_ALT)

# NO branch: horizontal left → discard box (same Y as diamond)
DISC_CX = DET_L - 1.10   # x=−0.30 is off screen; push to left of canvas
DISC_CX = 1.60
ax.plot([CX - DIAM_W/2, DISC_CX + 0.95],
        [Y["diam"], Y["diam"]],
        color=DIM, lw=1.8, solid_capstyle='round', zorder=2)
ax.annotate('', xy=(DISC_CX + 0.95, Y["diam"]), xytext=(DISC_CX + 1.15, Y["diam"]),
            arrowprops=dict(arrowstyle='->', color=DIM, lw=1.6, mutation_scale=14))
ax.text(CX - DIAM_W/2 - 0.12, Y["diam"] + 0.18, "NO",
        ha='right', va='center', color=DIM, fontsize=8.5, fontweight='bold')

draw_box(DISC_CX, Y["diam"], 1.85, 0.68, "DISCARD\nPACKET", DIM, fs=8.0)

# YES label + arrow
ax.text(CX + 0.22, Y["diam"] - DIAM_H/2 - 0.18, "YES",
        ha='left', va='top', color=C_ALT, fontsize=8.5, fontweight='bold')
varrow(CX, Y["diam"] - DIAM_H/2, Y["b4"] + BH/2, C_ALT)

# ── Box 4 — Alert Generator ───────────────────────────────────────────────────
draw_box(CX, Y["b4"], BW, BH,
         "ALERT GENERATOR", C_ALT,
         sub="Severity: LOW / MEDIUM / HIGH  ·  JSON Lines format  ·  SHA-256 event hash")

varrow(CX, Y["b4"] - BH/2, Y["b5"] + BH/2, C_ALT)

# ── Box 5 — MITRE Mapper ──────────────────────────────────────────────────────
draw_box(CX, Y["b5"], BW, BH,
         "MITRE ATT&CK MAPPER", C_MIT,
         sub="Attaches technique ID (T####) and tactic name to every alert")

varrow(CX, Y["b5"] - BH/2, Y["b6"] + BH/2, C_PRC)

# ── Box 6 — IP Enrichment ─────────────────────────────────────────────────────
draw_box(CX, Y["b6"], BW, BH,
         "IP GEOLOCATION ENRICHMENT", C_PRC,
         sub="ip-api.com  ·  country · city · ASN · org  ·  LRU cache (TTL 10 min)")

varrow(CX, Y["b6"] - BH/2, Y["b7"] + BH/2, C_PRC)

# ── Box 7 — Incident Correlator ───────────────────────────────────────────────
draw_box(CX, Y["b7"], BW, BH,
         "INCIDENT CORRELATOR", C_PRC,
         sub="Groups alerts by attacker IP · builds attack chain · computes 0–100 risk score")

# ── Fan-out to 3 output sinks ─────────────────────────────────────────────────
# Vertical stem
ax.plot([CX, CX], [Y["b7"] - BH/2, Y["fan"]],
        color=C_OUT, lw=1.9, zorder=2)
# Horizontal bar
ax.plot([OUT_XS[0], OUT_XS[-1]], [Y["fan"], Y["fan"]],
        color=C_OUT, lw=1.9, zorder=2)
# Drop arrows to each output box
for ox in OUT_XS:
    varrow(ox, Y["fan"], Y["out"] + OUT_H/2, C_OUT)

# ── Output boxes ──────────────────────────────────────────────────────────────
out_data = [
    ("JSON LOG\n(SIEM-ready)",  C_OUT, ".jsonl · one alert per line\nStructured for Splunk / ELK"),
    ("FLASK\nDASHBOARD",        C_OUT, "Live SOC view · /api/alerts\nAuto-refresh every 5 s"),
    ("WEBHOOK\nNOTIFIER",       C_OUT, "Discord · Slack · HTTP POST\nTriggered on HIGH severity"),
]
for (cx, (title, color, sub)) in zip(OUT_XS, out_data):
    draw_box(cx, Y["out"], OUT_W, OUT_H, title, color, sub=sub, fs=9.0)

# ── Legend ────────────────────────────────────────────────────────────────────
leg_y = Y["out"] - OUT_H/2 - 0.55
ax.plot([1.0, 11.0], [leg_y + 0.22, leg_y + 0.22], color=DIM, lw=0.8, alpha=0.4)
legend = [
    (C_IN,  "Input / Capture"),
    (C_PRC, "Processing / Enrichment"),
    (C_DET, "Detection Engine"),
    (C_ALT, "Alert Pipeline"),
    (C_MIT, "MITRE Mapping"),
    (C_OUT, "Output Sinks"),
]
total_w = 10.0
step = total_w / len(legend)
for i, (col, lbl) in enumerate(legend):
    bx = 1.0 + step * i
    ax.add_patch(FancyBboxPatch((bx, leg_y - 0.18), 0.28, 0.28,
                 boxstyle="round,pad=0.04",
                 facecolor=rgba(col, 0.55), edgecolor=col, lw=1.4))
    ax.text(bx + 0.40, leg_y - 0.04, lbl,
            ha='left', va='center', color=col, fontsize=7.5)

ax.set_ylim(Y["out"] - OUT_H/2 - 0.85, Y["title"] + 0.45)
plt.tight_layout(pad=0.2)
plt.savefig("flowchart.png", dpi=180, bbox_inches="tight", facecolor=BG)
print("Saved: flowchart.png")
