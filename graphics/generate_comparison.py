import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

BG     = "#0d2b1f"
PANEL  = "#12372a"
ALT    = "#0f2e20"
HEADER = "#1a4a30"
TEXT   = "#e8e8e8"
ACCENT = "#1db87a"
DIM    = "#7a9e8a"

COLORS = {"YES": "#1db87a", "PARTIAL": "#e0a832", "NO": "#e05252"}

features = [
    "Free & Open Source",
    "No install / cloud dependency",
    "Real-time packet capture",
    "PCAP file analysis",
    "7 built-in attack detectors",
    "3-tier severity scoring",
    "Incident correlation",
    "MITRE ATT&CK mapping",
    "IP geolocation enrichment",
    "Web dashboard",
    "Webhook notifications",
    "Auto-blocking (iptables)",
    "Beginner friendly / educational",
]

data = [
    ("YES", "YES",     "YES"),
    ("YES", "NO",      "NO"),
    ("YES", "YES",     "YES"),
    ("YES", "YES",     "YES"),
    ("YES", "PARTIAL", "PARTIAL"),
    ("YES", "NO",      "NO"),
    ("YES", "PARTIAL", "PARTIAL"),
    ("YES", "NO",      "PARTIAL"),
    ("YES", "NO",      "NO"),
    ("YES", "NO",      "PARTIAL"),
    ("YES", "NO",      "NO"),
    ("YES", "NO",      "YES"),
    ("YES", "NO",      "NO"),
]

nrows = len(features)
fig, ax = plt.subplots(figsize=(11, 7.5))
fig.patch.set_facecolor(BG)
ax.set_facecolor(BG)
ax.set_xlim(0, 1)
ax.set_ylim(0, 1)
ax.axis("off")

# Layout constants (all in axes coords)
TITLE_Y   = 0.965
LINE_Y    = 0.935
HDR_Y     = 0.925   # top of header band
HDR_H     = 0.055
TABLE_TOP = HDR_Y - HDR_H - 0.008
TABLE_BOT = 0.065
ROW_H     = (TABLE_TOP - TABLE_BOT) / nrows

# Column positions: [x_start, width]
C_FEAT  = (0.02,  0.54)
C_NETIDS= (0.575, 0.125)
C_SNORT = (0.710, 0.125)
C_SURI  = (0.845, 0.125)
COLS = [("Feature", C_FEAT), ("NetIDS", C_NETIDS), ("Snort", C_SNORT), ("Suricata", C_SURI)]

# ── Title ─────────────────────────────────────────────────────────────────────
ax.text(0.5, TITLE_Y, "Tool Comparison — NetIDS vs Snort vs Suricata",
        transform=ax.transAxes, ha="center", va="top",
        color=TEXT, fontsize=13, fontweight="bold")
ax.plot([0.02, 0.98], [LINE_Y, LINE_Y], transform=ax.transAxes,
        color=ACCENT, linewidth=1.5)

# ── Header ────────────────────────────────────────────────────────────────────
for label, (cx, cw) in COLS:
    ax.add_patch(FancyBboxPatch((cx, HDR_Y - HDR_H), cw - 0.003, HDR_H,
                                boxstyle="round,pad=0.005",
                                linewidth=0, facecolor=HEADER, zorder=2,
                                transform=ax.transAxes))
    ax.text(cx + (cw - 0.003) / 2, HDR_Y - HDR_H / 2, label,
            transform=ax.transAxes, ha="center", va="center",
            color=ACCENT, fontsize=10, fontweight="bold", zorder=3)

# ── Rows ──────────────────────────────────────────────────────────────────────
for i, (feat, (n, s, su)) in enumerate(zip(features, data)):
    row_top = TABLE_TOP - i * ROW_H
    row_bot = row_top - ROW_H
    mid_y   = (row_top + row_bot) / 2
    bg_col  = PANEL if i % 2 == 0 else ALT

    # row background spanning all columns
    ax.add_patch(FancyBboxPatch((0.02, row_bot + 0.003), 0.96, ROW_H - 0.004,
                                boxstyle="round,pad=0.003",
                                linewidth=0, facecolor=bg_col, zorder=1,
                                transform=ax.transAxes))

    # feature name
    cx, cw = C_FEAT
    ax.text(cx + 0.012, mid_y, feat,
            transform=ax.transAxes, ha="left", va="center",
            color=TEXT, fontsize=9, zorder=3)

    # badges
    badge_h = ROW_H * 0.56
    badge_w = 0.090
    for val, (cx, cw) in zip([n, s, su], [C_NETIDS, C_SNORT, C_SURI]):
        bx = cx + cw / 2
        ax.add_patch(FancyBboxPatch((bx - badge_w / 2, mid_y - badge_h / 2),
                                    badge_w, badge_h,
                                    boxstyle="round,pad=0.005",
                                    linewidth=0, facecolor=COLORS[val],
                                    alpha=0.88, zorder=3,
                                    transform=ax.transAxes))
        ax.text(bx, mid_y, val,
                transform=ax.transAxes, ha="center", va="center",
                color="white", fontsize=8, fontweight="bold", zorder=4)

# ── Legend ────────────────────────────────────────────────────────────────────
leg_y   = 0.025
leg_bh  = 0.030
leg_bw  = 0.020
lx      = 0.22
for label, color in [("YES  —  Supported", "#1db87a"),
                      ("PARTIAL  —  Limited support", "#e0a832"),
                      ("NO  —  Not available", "#e05252")]:
    ax.add_patch(FancyBboxPatch((lx, leg_y - leg_bh / 2), leg_bw, leg_bh,
                                boxstyle="round,pad=0.003",
                                facecolor=color, linewidth=0, zorder=3,
                                transform=ax.transAxes))
    ax.text(lx + leg_bw + 0.012, leg_y, label,
            transform=ax.transAxes, ha="left", va="center",
            color=DIM, fontsize=8.5, zorder=3)
    lx += 0.28

plt.tight_layout(pad=0.3)
plt.savefig("comparison_table.png", dpi=180, bbox_inches="tight", facecolor=BG)
print("Saved: comparison_table.png")
