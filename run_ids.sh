#!/bin/bash
cd "$(dirname "$0")"
echo "[*] Starting NetIDS on interface enp0s3..."
sudo .venv/bin/python3 src/ids.py --live --iface enp0s3