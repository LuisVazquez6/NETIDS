import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, Ellipse, Arc, Circle
from matplotlib.patches import PathPatch
from matplotlib.path import Path
import numpy as np

BG      = "#0d2b1f"
SHARK   = "#1db87a"
DARK    = "#0b7a50"
SHADE   = "#0f9460"
LIGHT   = "#3de09a"
WHITE   = "#e8f8f0"

fig, ax = plt.subplots(figsize=(6, 5))
fig.patch.set_facecolor(BG)
ax.set_facecolor(BG)
ax.set_xlim(0, 12)
ax.set_ylim(0, 10)
ax.set_aspect("equal")
ax.axis("off")

# ── Shark body (smooth path, faces right) ─────────────────────────────────────
# Drawn as a closed cubic-bezier path
verts = [
    # Start: tail center
    (2.0, 5.0),
    # ── Top edge: tail → dorsal base start ──
    (2.5, 6.2), (3.8, 6.8), (4.6, 6.6),   # curve up from tail
    # ── Dorsal fin (top) ──
    (4.9, 6.7), (5.1, 8.4), (5.3, 8.4),   # rise to dorsal tip
    (5.5, 8.4), (5.8, 6.8), (6.1, 6.6),   # fall from dorsal tip
    # ── Top edge: dorsal base end → snout ──
    (7.0, 6.4), (8.5, 6.0), (9.5, 5.5),
    (10.2, 5.2), (10.6, 5.0), (10.6, 5.0), # snout tip
    # ── Bottom edge: snout → tail ──
    (10.6, 5.0), (10.2, 4.8), (9.5, 4.5),
    (8.5, 4.2), (7.5, 3.9), (6.5, 3.8),
    # ── Pectoral fin notch ──
    (5.8, 3.8), (5.4, 3.0), (5.0, 3.2),   # fin tip dip
    (4.6, 3.4), (4.0, 3.8), (3.2, 4.1),
    (2.5, 4.2), (2.1, 4.6), (2.0, 5.0),   # back to tail
]

codes = [Path.MOVETO]
for i in range(1, len(verts) - 1, 3):
    codes += [Path.CURVE4, Path.CURVE4, Path.CURVE4]
codes.append(Path.CLOSEPOLY)

# Pad verts to match codes length
while len(verts) < len(codes):
    verts.append(verts[-1])
while len(verts) > len(codes):
    codes.append(Path.CURVE4)

body_path = Path(verts, codes)
body_patch = PathPatch(body_path, facecolor=SHARK, edgecolor=DARK,
                       linewidth=2.5, zorder=2)
ax.add_patch(body_patch)

# ── Belly shading (lighter stripe along underside) ────────────────────────────
belly_verts = [
    (3.5, 4.5),
    (5.0, 4.0), (7.0, 4.0), (8.5, 4.4),
    (9.5, 4.7), (9.5, 4.7), (9.5, 4.7),
    (8.5, 4.3), (7.0, 3.85), (5.0, 3.85),
    (3.5, 4.3), (3.5, 4.5), (3.5, 4.5),
]
belly_codes = [Path.MOVETO,
               Path.CURVE4, Path.CURVE4, Path.CURVE4,
               Path.LINETO, Path.LINETO, Path.LINETO,
               Path.CURVE4, Path.CURVE4, Path.CURVE4,
               Path.LINETO, Path.LINETO, Path.CLOSEPOLY]
belly_path = Path(belly_verts, belly_codes)
belly_patch = PathPatch(belly_path, facecolor=LIGHT, edgecolor="none",
                        alpha=0.22, zorder=3)
ax.add_patch(belly_patch)

# ── Tail fins ─────────────────────────────────────────────────────────────────
tail_top = plt.Polygon(
    [[2.0, 5.0], [0.3, 7.2], [1.0, 7.0], [2.3, 5.8]],
    closed=True, facecolor=SHARK, edgecolor=DARK, linewidth=2, zorder=2
)
ax.add_patch(tail_top)

tail_bot = plt.Polygon(
    [[2.0, 5.0], [0.3, 2.8], [1.0, 3.2], [2.3, 4.2]],
    closed=True, facecolor=SHARK, edgecolor=DARK, linewidth=2, zorder=2
)
ax.add_patch(tail_bot)

# Tail shadow line
ax.plot([2.0, 2.0], [4.35, 5.65], color=DARK, linewidth=2.5, zorder=4)

# ── Pectoral fin (separate, darker) ──────────────────────────────────────────
pec = plt.Polygon(
    [[5.4, 3.9], [4.8, 2.2], [5.6, 2.5], [6.4, 3.7]],
    closed=True, facecolor=SHADE, edgecolor=DARK, linewidth=1.5, zorder=3
)
ax.add_patch(pec)

# ── Gill slits ────────────────────────────────────────────────────────────────
gill_xs = [7.0, 7.45, 7.9]
for gx in gill_xs:
    ax.plot([gx, gx - 0.12], [6.2, 4.4],
            color=DARK, linewidth=2.0, solid_capstyle="round", zorder=5)

# ── Eye ───────────────────────────────────────────────────────────────────────
eye_outer = Circle((8.6, 5.55), radius=0.38,
                   facecolor=BG, edgecolor=LIGHT, linewidth=2, zorder=6)
ax.add_patch(eye_outer)
eye_pupil = Circle((8.65, 5.52), radius=0.16,
                   facecolor=WHITE, edgecolor="none", zorder=7)
ax.add_patch(eye_pupil)

# ── Mouth ─────────────────────────────────────────────────────────────────────
mouth = Arc((10.0, 5.0), width=1.4, height=0.9,
            angle=0, theta1=195, theta2=345,
            color=BG, linewidth=2.5, zorder=6)
ax.add_patch(mouth)

# Tooth suggestions
for tx, ty in [(9.65, 4.62), (9.95, 4.56), (10.25, 4.60)]:
    tooth = plt.Polygon([[tx, ty], [tx + 0.10, ty - 0.18], [tx + 0.20, ty]],
                        closed=True, facecolor=WHITE, edgecolor="none", zorder=7)
    ax.add_patch(tooth)

# ── Dorsal fin highlight ──────────────────────────────────────────────────────
ax.plot([5.1, 5.3], [8.0, 7.2], color=LIGHT, linewidth=1.2,
        alpha=0.5, zorder=5)

# ── Packet dots (network flavor) ─────────────────────────────────────────────
rng = np.random.default_rng(42)
for _ in range(18):
    px = rng.uniform(0.3, 11.7)
    py = rng.uniform(0.3, 1.8)
    size = rng.uniform(2, 8)
    alpha = rng.uniform(0.2, 0.6)
    ax.scatter(px, py, s=size, color=SHARK, alpha=alpha, zorder=1)

# Connecting dashes between some dots
ax.plot([1.0, 2.5, 4.0], [1.2, 1.5, 1.1],
        color=SHARK, linewidth=0.8, alpha=0.35,
        linestyle="--", zorder=1)
ax.plot([7.0, 8.5, 10.2], [1.3, 1.0, 1.4],
        color=SHARK, linewidth=0.8, alpha=0.35,
        linestyle="--", zorder=1)

# ── "scapy" wordmark ─────────────────────────────────────────────────────────
ax.text(6.0, 1.15, "scapy",
        ha="center", va="center",
        color=SHARK, fontsize=30, fontweight="bold",
        fontfamily="monospace", zorder=8,
        alpha=0.90)

# Thin underline
ax.plot([3.6, 8.4], [0.52, 0.52], color=SHARK,
        linewidth=1.0, alpha=0.40, zorder=8)

plt.tight_layout(pad=0.1)
out = "scapy_logo.png"
plt.savefig(out, dpi=180, bbox_inches="tight", facecolor=BG)
print(f"Saved: {out}")
