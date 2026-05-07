import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch
from matplotlib.offsetbox import OffsetImage, AnnotationBbox
import qrcode
import numpy as np

# ── Colors ────────────────────────────────────────────────────────────────────
BG        = "#f0f0f0"
HEADER_BG = "#3a3a3a"
BOX_BG    = "#c8c8c8"
TEXT_DARK = "#111111"
TEXT_HEAD = "#ffffff"
BULLET_COL= "#222222"

GITHUB_URL = "https://github.com/LuisVazquez6/NETIDS"
EMAIL      = "vazquez.luis1998@gmail.com"

# ── Generate QR code ──────────────────────────────────────────────────────────
qr = qrcode.QRCode(box_size=6, border=2)
qr.add_data(GITHUB_URL)
qr.make(fit=True)
qr_img = qr.make_image(fill_color="black", back_color="white")
qr_arr = np.array(qr_img.convert("RGB"))

# ── Figure ────────────────────────────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(8, 7))
fig.patch.set_facecolor(BG)
ax.set_facecolor(BG)
ax.set_xlim(0, 1)
ax.set_ylim(0, 1)
ax.axis("off")

def draw_box(ax, x, y, w, h, header_text, bg=BOX_BG, hdr=HEADER_BG, hdr_h=0.07):
    # outer box
    box = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.005",
                         linewidth=1.2, edgecolor="#888888",
                         facecolor=bg, zorder=1)
    ax.add_patch(box)
    # header bar
    hdr_box = FancyBboxPatch((x, y + h - hdr_h), w, hdr_h,
                              boxstyle="round,pad=0.005",
                              linewidth=0, facecolor=hdr, zorder=2)
    ax.add_patch(hdr_box)
    # header text
    ax.text(x + w / 2, y + h - hdr_h / 2, header_text,
            ha="center", va="center",
            color=TEXT_HEAD, fontsize=12, fontweight="bold", zorder=3)

# ── Box 1: Future Works ───────────────────────────────────────────────────────
bx, by, bw, bh = 0.05, 0.48, 0.90, 0.46
draw_box(ax, bx, by, bw, bh, "Future Works")

future_items = [
    "Add ML-based anomaly detection using an isolation forest model\nto catch zero-day-style traffic patterns",
    "Integrate TLS fingerprinting (JA3/JA4) to detect threats\nin encrypted traffic",
    "Extend Windows support via Npcap for broader deployment\non non-Linux environments",
]

fy = by + bh - 0.13
for item in future_items:
    ax.text(bx + 0.04, fy, "•", ha="left", va="top",
            color=BULLET_COL, fontsize=13, zorder=3)
    ax.text(bx + 0.075, fy, item, ha="left", va="top",
            color=TEXT_DARK, fontsize=9, linespacing=1.5,
            wrap=True, zorder=3)
    fy -= 0.135

# ── Box 2: Further Information ────────────────────────────────────────────────
bx2, by2, bw2, bh2 = 0.05, 0.02, 0.90, 0.42
draw_box(ax, bx2, by2, bw2, bh2, "Further Information")

# Text block
ax.text(bx2 + 0.04, by2 + bh2 - 0.12, "GitHub:",
        ha="left", va="top", color=TEXT_DARK,
        fontsize=10, fontweight="bold", zorder=3)
ax.text(bx2 + 0.20, by2 + bh2 - 0.12, GITHUB_URL,
        ha="left", va="top", color="#1a5fa8",
        fontsize=9, zorder=3)

ax.text(bx2 + 0.04, by2 + bh2 - 0.22, "Email:",
        ha="left", va="top", color=TEXT_DARK,
        fontsize=10, fontweight="bold", zorder=3)
ax.text(bx2 + 0.20, by2 + bh2 - 0.22, EMAIL,
        ha="left", va="top", color="#1a5fa8",
        fontsize=9, zorder=3)

ax.text(bx2 + 0.04, by2 + bh2 - 0.32, "Course:",
        ha="left", va="top", color=TEXT_DARK,
        fontsize=10, fontweight="bold", zorder=3)
ax.text(bx2 + 0.20, by2 + bh2 - 0.32, "Senior Capstone — CSUCI 2026",
        ha="left", va="top", color=TEXT_DARK,
        fontsize=9, zorder=3)

# QR code image
oi = OffsetImage(qr_arr, zoom=0.55)
ab = AnnotationBbox(oi, (0.82, by2 + bh2 / 2 - 0.02),
                    frameon=True, pad=0.3,
                    bboxprops=dict(edgecolor="#333333", linewidth=1.5,
                                   facecolor="white", boxstyle="round,pad=0.3"),
                    zorder=4)
ax.add_artist(ab)

ax.text(0.82, by2 + 0.045, "SCAN ME",
        ha="center", va="bottom",
        color=TEXT_DARK, fontsize=8, fontweight="bold", zorder=5)

plt.tight_layout(pad=0.3)
out = "conclusion_v3.png"
plt.savefig(out, dpi=180, bbox_inches="tight", facecolor=BG)
print(f"Saved: {out}")
