import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch

BG     = "#0d2b1f"
PANEL  = "#0f3024"
CARD   = "#14402e"
TEXT   = "#e8e8e8"
ACCENT = "#1db87a"
DIM    = "#7a9e8a"
RED    = "#e05252"
YELLOW = "#e0a832"
BLUE   = "#6ab0f5"

fig, ax = plt.subplots(figsize=(11, 6.5))
fig.patch.set_facecolor(BG)
ax.set_facecolor(BG)
ax.axis("off")

# ── Top accent line ────────────────────────────────────────────────────────────
ax.plot([0.03, 0.97], [0.96, 0.96], transform=ax.transAxes,
        color=ACCENT, linewidth=2.5)

# ── Title ─────────────────────────────────────────────────────────────────────
ax.text(0.5, 0.915, "Project Conclusion",
        transform=ax.transAxes, ha="center", va="top",
        color=TEXT, fontsize=16, fontweight="bold")

ax.text(0.5, 0.865,
        "NetIDS — Network Intrusion Detection System  |  Luis Vazquez  |  CSUCI Capstone 2026",
        transform=ax.transAxes, ha="center", va="top",
        color=DIM, fontsize=8.5, fontstyle="italic")

# ── Divider ───────────────────────────────────────────────────────────────────
ax.plot([0.03, 0.97], [0.835, 0.835], transform=ax.transAxes,
        color="#1e4a36", linewidth=1)

# ── Stats row ─────────────────────────────────────────────────────────────────
stats = [
    ("7 / 7", "Attack Types\nDetected"),
    ("<2s",   "Avg Time to\nFirst Alert"),
    ("0",     "False Positives\nBaseline Test"),
    ("3",     "Severity\nTiers"),
    ("100",   "Max Risk\nScore"),
]

stat_xs = [0.10, 0.28, 0.50, 0.72, 0.90]

for sx, (val, label) in zip(stat_xs, stats):
    # big number
    ax.text(sx, 0.79, val,
            transform=ax.transAxes, ha="center", va="top",
            color=ACCENT, fontsize=22, fontweight="bold")
    # label
    ax.text(sx, 0.70, label,
            transform=ax.transAxes, ha="center", va="top",
            color=DIM, fontsize=7.5, linespacing=1.5)

# dividers between stats
for dx in [0.19, 0.39, 0.61, 0.81]:
    ax.plot([dx, dx], [0.68, 0.80], transform=ax.transAxes,
            color="#1e4a36", linewidth=1, linestyle="--")

# ── Divider ───────────────────────────────────────────────────────────────────
ax.plot([0.03, 0.97], [0.645, 0.645], transform=ax.transAxes,
        color="#1e4a36", linewidth=1)

# ── Three columns: Summary | Future Work | References ─────────────────────────
cols = [
    {
        "x": 0.05, "title": "Summary", "color": ACCENT,
        "items": [
            "Successfully detects 7 attack types in real time",
            "MITRE ATT&CK mapping on every alert",
            "Incident correlation with 0-100 risk scoring",
            "Runs on commodity hardware, no license cost",
            "Open-source and extensible architecture",
        ]
    },
    {
        "x": 0.38, "title": "Future Work", "color": YELLOW,
        "items": [
            "ML anomaly detection (isolation forest)",
            "TLS / encrypted traffic fingerprinting",
            "Windows support via Npcap",
            "Automated PCAP export for incidents",
            "Role-based dashboard access control",
        ]
    },
    {
        "x": 0.70, "title": "References", "color": BLUE,
        "items": [
            "Scapy — scapy.net",
            "MITRE ATT&CK — attack.mitre.org",
            "Flask — flask.palletsprojects.com",
            "ip-api.com — IP geolocation",
            "Plotly — plotly.com/python",
        ]
    },
]

for col in cols:
    ax.text(col["x"], 0.615, col["title"],
            transform=ax.transAxes, ha="left", va="top",
            color=col["color"], fontsize=10.5, fontweight="bold")

    y = 0.555
    for item in col["items"]:
        ax.text(col["x"], y, f"  {item}",
                transform=ax.transAxes, ha="left", va="top",
                color=TEXT, fontsize=8, linespacing=1.4)
        ax.text(col["x"] - 0.005, y + 0.004, "–",
                transform=ax.transAxes, ha="left", va="top",
                color=col["color"], fontsize=8, fontweight="bold")
        y -= 0.095

# vertical dividers
for dx in [0.355, 0.675]:
    ax.plot([dx, dx], [0.09, 0.64], transform=ax.transAxes,
            color="#1e4a36", linewidth=1, linestyle="--")

# ── Bottom accent line ────────────────────────────────────────────────────────
ax.plot([0.03, 0.97], [0.07, 0.07], transform=ax.transAxes,
        color=ACCENT, linewidth=2.5)

ax.text(0.5, 0.038,
        "NetIDS is a fully functional, open-source IDS built to make professional-grade network monitoring accessible to everyone.",
        transform=ax.transAxes, ha="center", va="top",
        color=DIM, fontsize=8, fontstyle="italic")

plt.tight_layout(pad=0.2)
out = "conclusion_professional.png"
plt.savefig(out, dpi=180, bbox_inches="tight", facecolor=BG)
print(f"Saved: {out}")
