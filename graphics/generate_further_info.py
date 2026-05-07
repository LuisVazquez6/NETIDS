import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

BG        = "#0d2b1f"
HEADER_BG = "#1a4a30"
BOX_BG    = "#12372a"
TEXT      = "#e8e8e8"
ACCENT    = "#1db87a"
BLUE      = "#6ab0f5"

EMAIL = "vazquez.luis1998@gmail.com"

fig, ax = plt.subplots(figsize=(9, 5.5))
fig.patch.set_facecolor(BG)
ax.set_facecolor(BG)
ax.set_xlim(0, 1)
ax.set_ylim(0, 1)
ax.axis("off")

# Outer box
box = FancyBboxPatch((0.03, 0.05), 0.94, 0.88,
                     boxstyle="round,pad=0.01",
                     linewidth=1.5, edgecolor=ACCENT,
                     facecolor=BOX_BG, zorder=1)
ax.add_patch(box)

# Header bar
hdr = FancyBboxPatch((0.03, 0.82), 0.94, 0.11,
                     boxstyle="round,pad=0.01",
                     linewidth=0, facecolor=HEADER_BG, zorder=2)
ax.add_patch(hdr)

ax.text(0.50, 0.875, "Further Information",
        transform=ax.transAxes, ha="center", va="center",
        color=ACCENT, fontsize=14, fontweight="bold", zorder=3)

refs = [
    ("Email",   EMAIL),
    ("Course",  "Senior Capstone — CSUCI 2026"),
    ("Scapy",   "scapy.net"),
    ("MITRE",   "attack.mitre.org"),
    ("Flask",   "flask.palletsprojects.com"),
    ("Plotly",  "plotly.com/python"),
    ("ip-api",  "ip-api.com"),
]

y = 0.745
for label, val in refs:
    ax.text(0.10, y, f"{label}:",
            transform=ax.transAxes, ha="left", va="top",
            color=ACCENT, fontsize=10, fontweight="bold", zorder=3)
    ax.text(0.28, y, val,
            transform=ax.transAxes, ha="left", va="top",
            color=BLUE if "@" in val else TEXT,
            fontsize=10, zorder=3)
    y -= 0.096

# Bottom accent line
ax.plot([0.05, 0.95], [0.10, 0.10],
        transform=ax.transAxes,
        color=ACCENT, linewidth=1, linestyle="--", alpha=0.4)

plt.tight_layout(pad=0.2)
out = "further_info.png"
plt.savefig(out, dpi=180, bbox_inches="tight", facecolor=BG)
print(f"Saved: {out}")
