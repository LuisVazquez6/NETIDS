import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, Polygon
import matplotlib.colors as mcolors

fig, ax = plt.subplots(figsize=(8, 13))
fig.patch.set_facecolor("white")
ax.set_facecolor("white")
ax.set_xlim(0, 10)
ax.set_ylim(0, 17)
ax.axis("off")

BLUE   = "#1a73e8"
GREEN  = "#1db87a"
RED    = "#e05252"
YELLOW = "#d4900a"
PURPLE = "#7b52ab"
GRAY   = "#888888"
TEXT   = "#1a1a1a"
SUB    = "#555555"

def rgba(c, a=0.10):
    r, g, b = mcolors.to_rgb(c)
    return (r, g, b, a)

def box(cx, cy, w, h, title, color, sub=None, fs=10):
    ax.add_patch(FancyBboxPatch(
        (cx-w/2, cy-h/2), w, h,
        boxstyle="round,pad=0.14",
        facecolor=rgba(color, 0.09), edgecolor=color, lw=2.2, zorder=3))
    if sub:
        ax.text(cx, cy+0.18, title, ha='center', va='center',
                color=TEXT, fontsize=fs, fontweight='bold', zorder=4)
        ax.text(cx, cy-0.20, sub, ha='center', va='center',
                color=SUB, fontsize=fs-2.5, zorder=4)
    else:
        ax.text(cx, cy, title, ha='center', va='center',
                color=TEXT, fontsize=fs, fontweight='bold', zorder=4, linespacing=1.35)

def diamond(cx, cy, w, h, label, color):
    pts = [[cx,cy+h/2],[cx+w/2,cy],[cx,cy-h/2],[cx-w/2,cy]]
    ax.add_patch(Polygon(pts, closed=True,
                         facecolor=rgba(color,0.11), edgecolor=color, lw=2.2, zorder=3))
    ax.text(cx, cy, label, ha='center', va='center',
            color=TEXT, fontsize=10, fontweight='bold', zorder=4, linespacing=1.35)

def varrow(x, y1, y2, c=GRAY):
    ax.annotate('', xy=(x, y2), xytext=(x, y1),
                arrowprops=dict(arrowstyle='->', color=c, lw=1.8, mutation_scale=20), zorder=6)

def step_badge(x, y, n, color):
    ax.text(x, y, str(n), ha='center', va='center', color='white',
            fontsize=9, fontweight='bold', zorder=6,
            bbox=dict(boxstyle="circle,pad=0.22", facecolor=color, edgecolor="none"))

CX  = 5.0
BW  = 7.2
BH  = 0.88
GAP = 0.44

# ── Title ─────────────────────────────────────────────────────────────────────
ax.text(CX, 16.70, "NetIDS — System Flow",
        ha='center', va='center', color=TEXT, fontsize=14, fontweight='bold')
ax.plot([1.5, 8.5], [16.35, 16.35], color=GREEN, lw=1.5, alpha=0.45)

# ── Step 1: Packet Capture  (y top = 16.10) ───────────────────────────────────
Y1 = 15.70
box(CX, Y1, BW, BH, "PACKET CAPTURE", BLUE,
    sub="Scapy  ·  live interface (eth0 / wlan0)  or  .pcap file")
step_badge(0.62, Y1, 1, BLUE)

varrow(CX, Y1-BH/2, Y1-BH/2-GAP+0.02, GRAY)

# ── Step 2: Detection Engine ──────────────────────────────────────────────────
Y2 = Y1 - BH - GAP
box(CX, Y2, BW, BH, "DETECTION ENGINE", RED,
    sub="7 rule-based detectors  ·  rolling time-window thresholds")
step_badge(0.62, Y2, 2, RED)

# Detector pills
PILL_W, PILL_H = 0.97, 0.32
detectors = ["Port Scan","SYN Flood","SSH Brute","ICMP Flood",
             "DNS Tunnel","HTTP Brute","Slow Loris"]
pill_rows = [detectors[:4], detectors[4:]]
pill_top_y = Y2 - BH/2   # pills start flush below box

for ri, row in enumerate(pill_rows):
    py = pill_top_y - 0.24 - ri*(PILL_H + 0.12)
    n = len(row)
    total = n*PILL_W + (n-1)*0.12
    sx = CX - total/2
    for i, det in enumerate(row):
        px = sx + i*(PILL_W+0.12)
        ax.add_patch(FancyBboxPatch(
            (px, py-PILL_H/2), PILL_W, PILL_H,
            boxstyle="round,pad=0.05",
            facecolor=rgba(RED, 0.12), edgecolor=RED, lw=1.0, zorder=4))
        ax.text(px+PILL_W/2, py, det, ha='center', va='center',
                color=TEXT, fontsize=6.9, zorder=5)

# bottom of pill band
pill_bot = pill_top_y - 0.24 - 1*(PILL_H+0.12) - PILL_H/2 - 0.12

# Define diamond geometry early so every arrow can target exact edges
DW, DH = 3.6, 1.10
Y3 = pill_bot - GAP - DH/2
# arrow ends exactly at diamond top edge (no overshoot)
varrow(CX, pill_bot, Y3 + DH/2, GRAY)

# ── Decision diamond ──────────────────────────────────────────────────────────
diamond(CX, Y3, DW, DH, "THRESHOLD\nEXCEEDED?", YELLOW)

# NO → DROP  (horizontal left)
NO_X = CX - DW/2
ax.plot([NO_X, 1.52], [Y3, Y3], color=GRAY, lw=1.6, solid_capstyle='round')
ax.annotate('', xy=(1.52, Y3), xytext=(1.72, Y3),
            arrowprops=dict(arrowstyle='->', color=GRAY, lw=1.4, mutation_scale=14))
ax.text(NO_X - 0.12, Y3+0.17, "NO", ha='right', va='center',
        color=GRAY, fontsize=8.5, fontweight='bold')
ax.add_patch(FancyBboxPatch((0.18, Y3-0.27), 1.28, 0.54,
             boxstyle="round,pad=0.10",
             facecolor=rgba(GRAY,0.09), edgecolor=GRAY, lw=1.5, zorder=3))
ax.text(0.82, Y3, "DROP", ha='center', va='center',
        color=GRAY, fontsize=9, fontweight='bold', zorder=4)

# ── Step 3: Alert Generator ───────────────────────────────────────────────────
# Compute Y4 BEFORE drawing YES arrow so arrow ends exactly at box top
Y4 = Y3 - DH/2 - 0.72     # 0.28 of clear space above box top
Y4_top = Y4 + BH/2         # exact top edge of alert box

# YES label centred in the gap between diamond bottom and box top
YES_mid = (Y3 - DH/2 + Y4_top) / 2
ax.text(CX + 0.20, YES_mid, "YES", ha='left', va='center',
        color=YELLOW, fontsize=8.5, fontweight='bold')
varrow(CX, Y3 - DH/2, Y4_top, YELLOW)  # arrow ends exactly at box top

box(CX, Y4, BW, BH, "ALERT GENERATOR", YELLOW,
    sub="Severity: LOW / MEDIUM / HIGH  ·  JSON Lines format  ·  SHA-256 hash")
step_badge(0.62, Y4, 3, YELLOW)

# arrow ends exactly at Enrich box top
varrow(CX, Y4 - BH/2, Y4 - BH/2 - GAP * 0.55, GRAY)

# ── Step 4: Enrich & Map ──────────────────────────────────────────────────────
Y5 = Y4 - BH - GAP * 0.55   # matches the shortened arrow above
box(CX, Y5, BW, BH, "ENRICH & MAP", GREEN,
    sub="MITRE ATT&CK technique ID  ·  IP geolocation  ·  0–100 risk score")
step_badge(0.62, Y5, 4, GREEN)

# Fan-out stem
FAN_Y = Y5 - BH/2 - 0.46
OUT_W = 2.15
OUT_H = 1.15
OUT_XS = [CX-2.55, CX, CX+2.55]

ax.plot([CX, CX], [Y5-BH/2, FAN_Y], color=GRAY, lw=1.7)
ax.plot([OUT_XS[0], OUT_XS[-1]], [FAN_Y, FAN_Y], color=GRAY, lw=1.7)
for ox in OUT_XS:
    varrow(ox, FAN_Y, FAN_Y-0.44, GRAY)

# ── Step 5: Output sinks ──────────────────────────────────────────────────────
Y6 = FAN_Y - 0.44 - OUT_H/2
out_data = [
    ("JSON LOG",          PURPLE, ".jsonl · SIEM-ready"),
    ("FLASK\nDASHBOARD",  PURPLE, "Live SOC · auto-refresh"),
    ("WEBHOOK",           PURPLE, "Discord · Slack"),
]
for ox, (title, color, sub) in zip(OUT_XS, out_data):
    ax.add_patch(FancyBboxPatch(
        (ox-OUT_W/2, Y6-OUT_H/2), OUT_W, OUT_H,
        boxstyle="round,pad=0.12",
        facecolor=rgba(color, 0.09), edgecolor=color, lw=2.0, zorder=3))
    ax.text(ox, Y6+0.16, title, ha='center', va='center',
            color=TEXT, fontsize=8.5, fontweight='bold', zorder=4, linespacing=1.30)
    ax.text(ox, Y6-0.30, sub, ha='center', va='center',
            color=SUB, fontsize=7.0, zorder=4)

step_badge(0.62, Y6, 5, PURPLE)

# ── Footer ────────────────────────────────────────────────────────────────────
foot_y = Y6 - OUT_H/2 - 0.38
ax.plot([1.5, 8.5], [foot_y, foot_y], color="#dddddd", lw=1.0)
ax.text(CX, foot_y-0.22,
        "NetIDS  ·  Luis Vazquez  ·  COMP 499 Capstone  ·  CSUCI 2026",
        ha='center', va='center', color="#aaaaaa", fontsize=7.5, fontstyle='italic')

ax.set_ylim(foot_y-0.45, 17.10)
plt.tight_layout(pad=0.2)
plt.savefig("flowchart_simple.png", dpi=180, bbox_inches="tight", facecolor="white")
print("Saved: flowchart_simple.png")
