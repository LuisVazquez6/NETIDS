import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch
import matplotlib.colors as mcolors

BG     = "#0d2b1f"
PANEL  = "#12372a"
TEXT   = "#e8e8e8"
ACCENT = "#1db87a"
DIM    = "#aaaaaa"
RED    = "#e05252"
YELLOW = "#e0a832"

fig, ax = plt.subplots(figsize=(10, 6))
fig.patch.set_facecolor(BG)
ax.set_facecolor(BG)
ax.axis("off")

# ── Column layout ─────────────────────────────────────────────────────────────
# Left: Conclusion   Middle: Future Work   Right: References
col_x = [0.03, 0.38, 0.70]
col_w = 0.30

sections = [
    {
        "title": "Conclusion",
        "color": ACCENT,
        "items": [
            "7 / 7 attack types detected\nin real time",
            "Sub-2s average latency\nto first alert",
            "Runs on commodity hardware,\nno cloud or license cost",
            "Fully open-source and\nextensible architecture",
        ],
        "bullets": ACCENT,
    },
    {
        "title": "Future Work",
        "color": YELLOW,
        "items": [
            "ML anomaly detection\n(isolation forest)",
            "TLS / encrypted traffic\nfingerprinting",
            "Windows support\nvia Npcap",
            "Automated PCAP export\nfor flagged incidents",
        ],
        "bullets": YELLOW,
    },
    {
        "title": "References",
        "color": "#6ab0f5",
        "items": [
            "Scapy — scapy.net",
            "MITRE ATT&CK —\nattack.mitre.org",
            "Flask —\nflask.palletsprojects.com",
            "ip-api.com —\nIP geolocation API",
        ],
        "bullets": "#6ab0f5",
    },
]

for col, sec in zip(col_x, sections):
    # Section title
    ax.text(col + col_w / 2, 0.93, sec["title"],
            transform=ax.transAxes,
            ha="center", va="top",
            color=sec["color"], fontsize=13, fontweight="bold")

    # Underline
    ax.plot([col, col + col_w], [0.895, 0.895],
            transform=ax.transAxes,
            color=sec["color"], linewidth=1.2)

    # Items
    y = 0.845
    for item in sec["items"]:
        # bullet dot
        ax.text(col + 0.012, y, "•",
                transform=ax.transAxes,
                ha="left", va="top",
                color=sec["bullets"], fontsize=11)
        ax.text(col + 0.030, y, item,
                transform=ax.transAxes,
                ha="left", va="top",
                color=TEXT, fontsize=8.5,
                linespacing=1.4)
        y -= 0.175

# ── Tech stack badges (fill the empty lower third) ────────────────────────────
tech = [
    ("Python",  "#3776ab", "#ffd43b"),   # blue bg, yellow text
    ("Scapy",   "#1db87a", "#ffffff"),
    ("Flask",   "#9a9a9a", "#ffffff"),
    ("Plotly",  "#4c7fc5", "#ffffff"),
    ("Npcap",   "#7a4fb5", "#ffffff"),
]

badge_h  = 0.072
badge_w  = 0.116
gap      = 0.020
total_w  = len(tech) * badge_w + (len(tech) - 1) * gap
start_bx = (1.0 - total_w) / 2
badge_cy = 0.145   # vertical center of the badge row

ax.text(0.5, 0.245, "Built with",
        transform=ax.transAxes,
        ha="center", va="center",
        color=DIM, fontsize=7.5, fontstyle="italic")

for i, (name, bg_hex, fg_hex) in enumerate(tech):
    bx = start_bx + i * (badge_w + gap)
    r, g, b = mcolors.to_rgb(bg_hex)
    face = (r, g, b, 0.20)           # semi-transparent fill

    pill = FancyBboxPatch(
        (bx, badge_cy - badge_h / 2), badge_w, badge_h,
        boxstyle="round,pad=0.008",
        linewidth=1.1, edgecolor=bg_hex,
        facecolor=face, zorder=3,
        transform=ax.transAxes
    )
    ax.add_patch(pill)

    # Python badge: two-color label (blue "Py" + yellow "thon")
    if name == "Python":
        half = badge_w / 2
        ax.text(bx + half * 0.52, badge_cy, "Py",
                transform=ax.transAxes, ha="right", va="center",
                color="#3776ab", fontsize=8.5, fontweight="bold", zorder=4)
        ax.text(bx + half * 0.52, badge_cy, "thon",
                transform=ax.transAxes, ha="left", va="center",
                color="#ffd43b", fontsize=8.5, fontweight="bold", zorder=4)
    else:
        ax.text(bx + badge_w / 2, badge_cy, name,
                transform=ax.transAxes, ha="center", va="center",
                color=bg_hex, fontsize=8, fontweight="bold", zorder=4)

# ── Dividers between columns ──────────────────────────────────────────────────
for divx in [0.365, 0.685]:
    ax.plot([divx, divx], [0.05, 0.95],
            transform=ax.transAxes,
            color="#1e4a36", linewidth=1, linestyle="--")

# ── Bottom tagline ─────────────────────────────────────────────────────────────
ax.text(0.5, 0.04,
        "NetIDS  —  Open-source Network Intrusion Detection  |  California State University Channel Islands",
        transform=ax.transAxes,
        ha="center", va="bottom",
        color=DIM, fontsize=7.5, fontstyle="italic")

plt.tight_layout(pad=0.3)
out = "conclusion_card.png"
plt.savefig(out, dpi=180, bbox_inches="tight", facecolor=BG)
print(f"Saved: {out}")
