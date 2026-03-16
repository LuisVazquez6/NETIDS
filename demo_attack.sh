#!/bin/bash
# =============================================================================
# NetIDS Capstone Demo — Attack Sequence
# Run this from your Kali machine against the victim IDS
# Usage: sudo bash demo_attack.sh <victim-ip>
# Example: sudo bash demo_attack.sh 192.168.56.103
# =============================================================================

VICTIM="${1:-192.168.56.103}"

RED='\033[91m'
YELLOW='\033[93m'
GREEN='\033[92m'
CYAN='\033[96m'
BOLD='\033[1m'
RESET='\033[0m'

banner() {
    echo -e "\n${CYAN}${BOLD}========================================${RESET}"
    echo -e "${CYAN}${BOLD}  $1${RESET}"
    echo -e "${CYAN}${BOLD}========================================${RESET}\n"
}

step() {
    echo -e "${YELLOW}${BOLD}[*] $1${RESET}"
}

done_msg() {
    echo -e "${GREEN}${BOLD}[+] $1${RESET}"
}

echo -e "\n${BOLD}NetIDS Demo Attack Sequence${RESET}"
echo -e "Target: ${BOLD}${VICTIM}${RESET}"
echo -e "Press ENTER to start or Ctrl+C to abort..."
read

# -----------------------------------------------------------------------------
# 1. ICMP Flood — triggers ICMP_FLOOD_SUSPECTED (MEDIUM -> HIGH)
# -----------------------------------------------------------------------------
banner "Stage 1/4 — ICMP Flood (T1498)"
step "Sending 20 ICMP echo requests at 0.3s intervals..."
hping3 --icmp --count 20 --interval u300000 "$VICTIM"
done_msg "ICMP flood complete. Expected: ICMP_FLOOD_SUSPECTED MEDIUM then HIGH"
sleep 2

# -----------------------------------------------------------------------------
# 2. Port Scan — triggers PORT_SCAN_SUSPECTED (MEDIUM -> HIGH)
# -----------------------------------------------------------------------------
banner "Stage 2/4 — Port Scan (T1046)"
step "Running nmap SYN scan across 50 ports..."
nmap -sS --max-rate 200 -p 1-50 "$VICTIM" -Pn
done_msg "Port scan complete. Expected: PORT_SCAN_SUSPECTED MEDIUM"
sleep 2

# -----------------------------------------------------------------------------
# 3. SYN Burst — triggers SYN_BURST_SUSPECTED (MEDIUM -> HIGH)
# -----------------------------------------------------------------------------
banner "Stage 3/4 — SYN Burst / DoS (T1498)"
step "Sending 15 SYN packets at 0.3s intervals to port 80..."
hping3 -S -p 80 --count 15 --interval u300000 "$VICTIM"
done_msg "SYN burst complete. Expected: SYN_BURST_SUSPECTED MEDIUM then HIGH"
sleep 2

# -----------------------------------------------------------------------------
# 4. SSH Brute Force — triggers SSH_BRUTEFORCE_SUSPECTED (MEDIUM -> HIGH)
# -----------------------------------------------------------------------------
banner "Stage 4/4 — SSH Brute Force (T1110)"
step "Sending 35 SYN packets to port 22 at 0.6s intervals..."
step "Watch for MEDIUM at attempt 12, HIGH at attempt 30..."
hping3 -S -p 22 --count 35 --interval u600000 "$VICTIM"
done_msg "SSH brute force complete. Expected: SSH_BRUTEFORCE_SUSPECTED MEDIUM then HIGH"

# -----------------------------------------------------------------------------
# Done
# -----------------------------------------------------------------------------
echo -e "\n${GREEN}${BOLD}========================================${RESET}"
echo -e "${GREEN}${BOLD}  Demo complete.${RESET}"
echo -e "${GREEN}${BOLD}  All 4 detectors triggered from ${VICTIM}${RESET}"
echo -e "${GREEN}${BOLD}  Check IDS console and dashboard.${RESET}"
echo -e "${GREEN}${BOLD}========================================${RESET}\n"
