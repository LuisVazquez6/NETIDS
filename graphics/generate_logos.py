import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, Ellipse, Arc, Circle, Polygon
import numpy as np

BG = "#0d2b1f"

def new_ax():
    fig, ax = plt.subplots(figsize=(4, 4))
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(BG)
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 10)
    ax.set_aspect("equal")
    ax.axis("off")
    return fig, ax

def save(name):
    plt.tight_layout(pad=0.15)
    plt.savefig(f"logo_{name}.png", dpi=180, bbox_inches="tight", facecolor=BG)
    print(f"Saved: logo_{name}.png")
    plt.close()

# ── Python ─────────────────────────────────────────────────────────────────────
fig, ax = new_ax()
PYBL = "#3776ab"; PYYL = "#ffd43b"; PYDBL = "#255c8a"; PYDYL = "#b89200"

# Blue body (upper-right half)
ax.add_patch(Ellipse((5.8, 6.5), 5.2, 3.2, facecolor=PYBL, edgecolor='none', zorder=2))
ax.add_patch(Circle((3.6, 7.2), 1.6, facecolor=PYBL, edgecolor='none', zorder=2))  # tail bump
ax.add_patch(Circle((8.0, 5.8), 1.5, facecolor=PYBL, edgecolor='none', zorder=4))  # head

# Yellow body (lower-left half)
ax.add_patch(Ellipse((4.2, 3.5), 5.2, 3.2, facecolor=PYYL, edgecolor='none', zorder=2))
ax.add_patch(Circle((6.4, 2.8), 1.6, facecolor=PYYL, edgecolor='none', zorder=2))  # tail bump
ax.add_patch(Circle((2.0, 4.2), 1.5, facecolor=PYYL, edgecolor='none', zorder=4))  # head

# Negative holes (BG punchthrough to create interlocking)
ax.add_patch(Circle((5.5, 5.5), 1.25, facecolor=BG, edgecolor='none', zorder=3))
ax.add_patch(Circle((4.5, 4.5), 1.25, facecolor=BG, edgecolor='none', zorder=3))

# Neck fill through holes
ax.add_patch(Ellipse((4.8, 5.0), 1.0, 2.0, facecolor=PYYL, edgecolor='none', zorder=4))
ax.add_patch(Ellipse((5.2, 5.0), 1.0, 2.0, facecolor=PYBL, edgecolor='none', zorder=4))

# Eyes
ax.add_patch(Circle((8.35, 6.1), 0.38, facecolor='white', edgecolor='none', zorder=6))
ax.add_patch(Circle((8.4, 6.1), 0.18, facecolor=PYDBL, edgecolor='none', zorder=7))
ax.add_patch(Circle((1.65, 4.7), 0.38, facecolor=PYDYL, edgecolor='none', zorder=6))
ax.add_patch(Circle((1.6, 4.7), 0.18, facecolor='white', edgecolor='none', zorder=7))

# Highlights
ax.add_patch(Circle((7.2, 7.0), 0.45, facecolor='white', edgecolor='none', alpha=0.2, zorder=3))
ax.add_patch(Circle((2.8, 3.0), 0.45, facecolor='white', edgecolor='none', alpha=0.2, zorder=3))

ax.text(5.0, 1.2, "Python", ha='center', va='center',
        color='#e8e8e8', fontsize=26, fontweight='bold')
save("python")

# ── Flask ─────────────────────────────────────────────────────────────────────
fig, ax = new_ax()
FLGRAY = "#cccccc"; FLDARK = "#777777"; FLGREEN = "#1db87a"

# Stopper
ax.add_patch(FancyBboxPatch((3.7, 8.6), 2.6, 0.85, boxstyle="round,pad=0.1",
    facecolor=FLDARK, edgecolor=FLDARK, zorder=3))
# Neck
ax.add_patch(Polygon([[4.1,7.1],[5.9,7.1],[5.9,8.6],[4.1,8.6]],
    facecolor=FLGRAY, edgecolor=FLDARK, lw=1.5, zorder=2))
# Body
ax.add_patch(Polygon([[4.1,7.1],[2.0,2.8],[8.0,2.8],[5.9,7.1]],
    facecolor=FLGRAY, edgecolor=FLDARK, lw=1.5, zorder=2))
# Bottom cap
ax.add_patch(Ellipse((5.0,2.8), 6.0,1.5, facecolor=FLGRAY, edgecolor=FLDARK, lw=1.5, zorder=3))
# Liquid fill
ax.add_patch(Polygon([[2.3,2.8],[7.7,2.8],[6.7,5.2],[3.3,5.2]],
    facecolor=FLGREEN, edgecolor='none', alpha=0.85, zorder=4))
ax.add_patch(Ellipse((5.0,2.8), 5.4,1.3, facecolor=FLGREEN, edgecolor='none', alpha=0.85, zorder=4))
# Liquid surface ellipse
ax.add_patch(Ellipse((5.0,5.2), 3.4,0.7, facecolor=FLGREEN, edgecolor='none', alpha=0.5, zorder=4))
# Bubbles
for bx,by,br in [(3.8,3.7,0.22),(5.3,4.5,0.16),(6.5,3.4,0.14),(4.5,4.0,0.10)]:
    ax.add_patch(Circle((bx,by), br, facecolor='white', edgecolor='none', alpha=0.55, zorder=5))
# Neck shine
ax.add_patch(Polygon([[4.25,7.1],[4.65,7.1],[4.65,8.6],[4.25,8.6]],
    facecolor='white', edgecolor='none', alpha=0.22, zorder=3))

ax.text(5.0, 1.4, "Flask", ha='center', va='center',
        color=FLGRAY, fontsize=28, fontweight='bold', fontfamily='monospace')
save("flask")

# ── MITRE ATT&CK ─────────────────────────────────────────────────────────────
fig, ax = new_ax()
RED="#c8102e"; RDARK="#8b0c20"; RLIGHT="#e84060"

# Shield body
ax.add_patch(Polygon([
    [5.0,0.8],[1.1,3.5],[1.1,7.8],[5.0,9.3],[8.9,7.8],[8.9,3.5]],
    closed=True, facecolor=RED, edgecolor=RDARK, lw=2.5, zorder=2))
# Inner border
ax.add_patch(Polygon([
    [5.0,1.9],[2.1,4.1],[2.1,7.5],[5.0,8.5],[7.9,7.5],[7.9,4.1]],
    closed=True, facecolor='none', edgecolor=RLIGHT, lw=1.0, alpha=0.45, zorder=3))
# Crosshair rings
for r,lw in [(2.1,2.0),(1.1,2.0)]:
    ax.add_patch(Circle((5.0,5.3), r, facecolor='none', edgecolor='white', lw=lw, alpha=0.92, zorder=4))
ax.add_patch(Circle((5.0,5.3), 0.35, facecolor='white', edgecolor='none', zorder=5))
ax.plot([2.9,7.1],[5.3,5.3], color='white', lw=1.6, alpha=0.85, zorder=4)
ax.plot([5.0,5.0],[3.2,7.4], color='white', lw=1.6, alpha=0.85, zorder=4)
# Shield gloss
ax.add_patch(Polygon([[3.5,7.8],[2.5,5.5],[3.2,5.5],[4.2,7.8]],
    facecolor='white', edgecolor='none', alpha=0.10, zorder=3))

ax.text(5.0,1.35,"MITRE  ATT&CK", ha='center', va='center',
        color=RED, fontsize=15, fontweight='bold')
save("mitre")

# ── Linux (Tux) ───────────────────────────────────────────────────────────────
fig, ax = new_ax()
BLK="#1a1a1a"; CREAM="#f5dfc0"; ORG="#e87c1e"; YEL="#f5d020"

# Wings
ax.add_patch(Polygon([[1.8,3.5],[1.1,5.6],[2.8,6.2],[3.2,4.0]],
    closed=True, facecolor=BLK, edgecolor="#333", lw=1.5, zorder=3))
ax.add_patch(Polygon([[8.2,3.5],[8.9,5.6],[7.2,6.2],[6.8,4.0]],
    closed=True, facecolor=BLK, edgecolor="#333", lw=1.5, zorder=3))
# Body
ax.add_patch(Ellipse((5.0,4.5), 5.5,6.5, facecolor=BLK, edgecolor="#333", lw=2, zorder=2))
# Belly
ax.add_patch(Ellipse((5.0,4.0), 3.2,5.2, facecolor=CREAM, edgecolor='none', zorder=3))
# Head
ax.add_patch(Circle((5.0,8.2), 1.75, facecolor=BLK, edgecolor="#333", lw=2, zorder=4))
# Ear bumps
ax.add_patch(Ellipse((3.55,9.35), 1.1,0.75, angle=30, facecolor=BLK, edgecolor="#333", lw=1.5, zorder=5))
ax.add_patch(Ellipse((6.45,9.35), 1.1,0.75, angle=-30, facecolor=BLK, edgecolor="#333", lw=1.5, zorder=5))
# Eyes (yellow sclera + black pupil)
for ex in [4.25, 5.75]:
    ax.add_patch(Ellipse((ex,8.3), 0.7,0.6, facecolor=YEL, edgecolor='none', zorder=6))
    ax.add_patch(Ellipse((ex,8.25), 0.30,0.38, facecolor=BLK, edgecolor='none', zorder=7))
    ax.add_patch(Circle((ex+0.08,8.32), 0.08, facecolor='white', edgecolor='none', zorder=8))
# Beak
ax.add_patch(Polygon([[4.35,7.7],[5.65,7.7],[5.0,7.0]],
    facecolor=ORG, edgecolor='#c05500', lw=1, zorder=6))
# Feet + toes
for fx,fa in [(3.5,-12),(6.5,12)]:
    ax.add_patch(Ellipse((fx,1.65), 2.3,0.85, angle=fa, facecolor=ORG, edgecolor='#c05500', lw=1.5, zorder=4))
    for dx in [-0.55,0.0,0.55]:
        ax.plot([fx+dx,fx+dx],[1.25,1.95], color='#c05500', lw=1.2, zorder=5)
# Belly button highlight
ax.add_patch(Ellipse((5.0,3.5), 1.5,1.2, facecolor='white', edgecolor='none', alpha=0.15, zorder=4))

ax.text(5.0,0.55,"Linux", ha='center', va='center',
        color='#e8e8e8', fontsize=26, fontweight='bold')
save("linux")

# ── GitHub ────────────────────────────────────────────────────────────────────
fig, ax = new_ax()
GHW="#e8e8e8"; GHB="#24292f"

# Dark background circle
ax.add_patch(Circle((5.0,5.5), 4.1, facecolor=GHB, edgecolor="#555", lw=2, zorder=2))
# Head
ax.add_patch(Circle((5.0,6.3), 2.3, facecolor=GHW, edgecolor='none', zorder=3))
# Cat ears
for ex in [3.4, 6.6]:
    ax.add_patch(Polygon([[ex-0.6,7.7],[ex,9.0],[ex+0.6,7.7]],
        closed=True, facecolor=GHW, edgecolor='none', zorder=3))
# Eyes
for ex in [4.15, 5.85]:
    ax.add_patch(Circle((ex,6.5), 0.35, facecolor=GHB, edgecolor='none', zorder=4))
# Nose
ax.add_patch(Circle((5.0,5.95), 0.2, facecolor=GHB, edgecolor='none', zorder=4))
# Whiskers
for wx,wy,ex2,ey2 in [(3.6,6.1,2.4,5.9),(3.6,5.8,2.4,5.6),(6.4,6.1,7.6,5.9),(6.4,5.8,7.6,5.6)]:
    ax.plot([wx,ex2],[wy,ey2], color=GHB, lw=1.2, zorder=5)
# Octo body + tentacles
ax.add_patch(Ellipse((5.0,3.9), 3.0,2.2, facecolor=GHW, edgecolor='none', zorder=3))
for tx,ty in [(3.2,2.1),(3.95,1.5),(5.0,1.3),(6.05,1.5),(6.8,2.1)]:
    ax.plot([tx,tx],[3.1,ty], color=GHW, lw=2.5, solid_capstyle='round', zorder=3)
    ax.add_patch(Circle((tx,ty), 0.22, facecolor=GHW, edgecolor='none', zorder=4))

ax.text(5.0,0.6,"GitHub", ha='center', va='center',
        color=GHW, fontsize=24, fontweight='bold')
save("github")

# ── Discord ───────────────────────────────────────────────────────────────────
fig, ax = new_ax()
BLP="#5865f2"; BLPD="#3a45c9"; BLPL="#8891f5"

# Main rounded body
ax.add_patch(FancyBboxPatch((1.4,2.4), 7.2,5.8, boxstyle="round,pad=0.9",
    facecolor=BLP, edgecolor=BLPD, lw=2, zorder=2))
# Ears
ax.add_patch(Circle((3.1,8.9), 1.25, facecolor=BLP, edgecolor=BLPD, lw=2, zorder=2))
ax.add_patch(Circle((6.9,8.9), 1.25, facecolor=BLP, edgecolor=BLPD, lw=2, zorder=2))
# Eye whites
ax.add_patch(Ellipse((3.5,5.9), 2.0,2.3, facecolor='white', edgecolor='none', zorder=3))
ax.add_patch(Ellipse((6.5,5.9), 2.0,2.3, facecolor='white', edgecolor='none', zorder=3))
# Pupils
ax.add_patch(Ellipse((3.75,5.65), 1.1,1.5, facecolor=BLPD, edgecolor='none', zorder=4))
ax.add_patch(Ellipse((6.25,5.65), 1.1,1.5, facecolor=BLPD, edgecolor='none', zorder=4))
# Eye shines
ax.add_patch(Circle((3.55,6.15), 0.32, facecolor='white', edgecolor='none', alpha=0.6, zorder=5))
ax.add_patch(Circle((6.05,6.15), 0.32, facecolor='white', edgecolor='none', alpha=0.6, zorder=5))
# Smile
ax.add_patch(Arc((5.0,3.9), 3.2,1.6, angle=0, theta1=200, theta2=340,
    color='white', lw=2.8, zorder=4))
# Body highlight
ax.add_patch(Ellipse((3.8,8.5), 2.5,0.9, facecolor='white', edgecolor='none', alpha=0.12, zorder=3))

ax.text(5.0,1.45,"Discord", ha='center', va='center',
        color=BLP, fontsize=24, fontweight='bold')
save("discord")

# ── SQLite ────────────────────────────────────────────────────────────────────
fig, ax = new_ax()
SBL="#0064a5"; SBLD="#003b57"; SBLL="#3d9ed4"; SBMID="#1a7ab8"

# Body rectangle
ax.add_patch(Polygon([[2.2,2.5],[7.8,2.5],[7.8,7.5],[2.2,7.5]],
    facecolor=SBL, edgecolor=SBLD, lw=2, zorder=2))
# Bottom cap
ax.add_patch(Ellipse((5.0,2.5), 5.6,1.4, facecolor=SBLD, edgecolor=SBLD, lw=2, zorder=3))
# Top lid
ax.add_patch(Ellipse((5.0,7.5), 5.6,1.4, facecolor=SBLL, edgecolor=SBLD, lw=2, zorder=3))
# Data row lines
for ry,alpha in [(4.0,0.55),(5.0,0.45),(6.0,0.35)]:
    ax.add_patch(Ellipse((5.0,ry+0.15), 5.6,0.55, facecolor=SBMID,
        edgecolor=SBLD, lw=0.8, alpha=alpha, zorder=3))
# Lid shine
ax.add_patch(Ellipse((4.3,7.5), 2.8,0.65, facecolor='white', edgecolor='none', alpha=0.28, zorder=4))
# Body right-side shading
ax.add_patch(Polygon([[7.8,2.5],[7.8,7.5],[7.0,7.5],[7.0,2.5]],
    facecolor=SBLD, edgecolor='none', alpha=0.4, zorder=3))

ax.text(5.0,1.45,"SQLite", ha='center', va='center',
        color=SBLL, fontsize=26, fontweight='bold', fontfamily='monospace')
save("sqlite")

# ── MITRE (already done) / Summary ────────────────────────────────────────────
print("\nAll logos generated:")
for n in ["python","flask","mitre","linux","github","discord","sqlite"]:
    print(f"  logo_{n}.png")
