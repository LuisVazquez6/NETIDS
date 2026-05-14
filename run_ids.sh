#!/bin/bash
cd "$(dirname "$0")"
[ -f .env ] && export $(grep -v '^#' .env | xargs)
echo "[*] Starting NetIDS on interface enp0s3..."
sudo --preserve-env=ANTHROPIC_API_KEY .venv/bin/python3 src/ids.py --live --iface enp0s3