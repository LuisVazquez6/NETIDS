#!/bin/bash
cd "$(dirname "$0")"
[ -f .env ] && export $(grep -v '^#' .env | xargs)
echo "[*] Starting NetIDS dashboard at http://$(hostname -I | awk '{print $1}'):5000"
.venv/bin/python3 src/dashboard/flask_app.py
