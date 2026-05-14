import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch
import numpy as np

# ── Data ──────────────────────────────────────────────────────────────────────
attacks = [
    "Port Scan",
    "SYN Flood",
    "SSH Brute\nForce",
    "ICMP Flood",
    "DNS\nTunneling",
    "HTTP Brute\nForce",
    "Slow Loris",
]

tools = [
    "nmap -sS",
    "hping3 --flood",
    "hydra",
    "ping -f",
    "crafted packets",
    "custom script",
    "slowloris.py",
]

severities = ["HIGH", "HIGH", "HIGH", "MEDIUM", "HIGH", "HIGH", "MEDIUM"]
detected   = [True, True, True, True, True, True, True]
latency_s  = [1.2, 0.8, 1.5, 0.9, 1.1, 1.3, 2.0]   # approx seconds to first alert
mitre      = ["T1046", "T1499", "T1110", "T1018", "T1071.004", "T1110.003", "T1499"]

SEV_COLOR = {"HIGH": "#e05252", "MEDIUM": "#e0a832"}
BG        = "#0d2b1f"
PANEL     = "#12372a"
TEXT      = "#e8e8e8"
GREEN     = "#3dba6f"
ACCENT    = "#1db87a"

# ── Figure ────────────────────────────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(12, 5.5))
fig.patch.set_facecolor(BG)
ax.set_facecolor(PANEL)

x = np.arange(len(attacks))
bar_w = 0.55

bars = ax.bar(x, latency_s, width=bar_w,
              color=[SEV_COLOR[s] for s in severities],
              zorder=3, linewidth=0)

# ── Grid ──────────────────────────────────────────────────────────────────────
ax.set_axisbelow(True)
ax.yaxis.grid(True, color="#1e4a36", linewidth=0.8, linestyle="--")
ax.xaxis.grid(False)

# ── Axes styling ──────────────────────────────────────────────────────────────
ax.set_xticks(x)
ax.set_xticklabels(attacks, color=TEXT, fontsize=10, fontweight="bold")
ax.set_ylabel("Time to First Alert (seconds)", color=TEXT, fontsize=10, labelpad=10)
ax.set_ylim(0, max(latency_s) * 1.55)
ax.tick_params(colors=TEXT, length=0)
for spine in ax.spines.values():
    spine.set_visible(False)

# ── Value labels + badges on bars ─────────────────────────────────────────────
for i, (bar, sev, mit, det) in enumerate(zip(bars, severities, mitre, detected)):
    h = bar.get_height()
    # latency label
    ax.text(bar.get_x() + bar.get_width() / 2, h + 0.07,
            f"{h:.1f}s", ha="center", va="bottom",
            color=TEXT, fontsize=9, fontweight="bold")
    # MITRE tag
    ax.text(bar.get_x() + bar.get_width() / 2, h + 0.32,
            mit, ha="center", va="bottom",
            color=ACCENT, fontsize=7.5, fontstyle="italic")
    # DETECTED checkmark
    ax.text(bar.get_x() + bar.get_width() / 2, 0.08,
            "✓ DETECTED", ha="center", va="bottom",
            color="white", fontsize=7.5, fontweight="bold")

# ── Tool labels below x-axis ──────────────────────────────────────────────────
for i, tool in enumerate(tools):
    ax.text(x[i], -0.38, tool, ha="center", va="top",
            color="#aaaaaa", fontsize=7.5, transform=ax.get_xaxis_transform())

# ── Legend ────────────────────────────────────────────────────────────────────
high_patch   = mpatches.Patch(color=SEV_COLOR["HIGH"],   label="HIGH severity")
medium_patch = mpatches.Patch(color=SEV_COLOR["MEDIUM"], label="MEDIUM severity")
leg = ax.legend(handles=[high_patch, medium_patch],
                loc="upper right", frameon=True,
                framealpha=0.25, facecolor=BG,
                edgecolor=ACCENT, labelcolor=TEXT,
                fontsize=9)

# ── Title ─────────────────────────────────────────────────────────────────────
ax.set_title("NetIDS — Detection Performance  (7 / 7 attacks detected)",
             color=TEXT, fontsize=13, fontweight="bold", pad=14)

plt.tight_layout()
out = "detection_results.png"
plt.savefig(out, dpi=180, bbox_inches="tight", facecolor=BG)
print(f"Saved: {out}")
