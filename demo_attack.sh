#!/bin/bash
# =============================================================================
# NetIDS Capstone Demo — Attack Sequence
# Run this from your Kali machine against the victim IDS
# Usage: sudo bash demo_attack.sh <victim-ip>
# Example: sudo bash demo_attack.sh 192.168.56.103
# =============================================================================

VICTIM="${1:-192.168.56.103}"

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
# 1. ICMP Flood — IP1 (Tor exit node)
# -----------------------------------------------------------------------------
banner "Stage 1/8 — ICMP Flood from ${IP1} (T1498)"
step "Sending 20 ICMP echo requests spoofed from ${IP1}..."
hping3 --icmp --count 20 --interval u300000 -a "$IP1" "$VICTIM"
done_msg "ICMP flood complete. Expected: ICMP_FLOOD_SUSPECTED MEDIUM"
sleep 2

# -----------------------------------------------------------------------------
# 2. Port Scan — real Kali IP (nmap can't spoof easily)
# -----------------------------------------------------------------------------
banner "Stage 2/8 — Port Scan (T1046)"
step "Running nmap SYN scan across 50 ports..."
nmap -sS --max-rate 200 -p 1-50 "$VICTIM" -Pn
done_msg "Port scan complete. Expected: PORT_SCAN_SUSPECTED MEDIUM"
sleep 2

# -----------------------------------------------------------------------------
# 3. SYN Burst — IP2 (Linode VPS)
# -----------------------------------------------------------------------------
banner "Stage 3/8 — SYN Burst from ${IP2} (T1498)"
step "Sending 60 SYN packets spoofed from ${IP2}..."
hping3 -S -p 80 --count 60 --interval u100000 -a "$IP2" "$VICTIM"
done_msg "SYN burst complete. Expected: SYN_BURST_SUSPECTED MEDIUM then HIGH"
sleep 2

# -----------------------------------------------------------------------------
# 4. SSH Brute Force — IP3 (Russian VPS)
# -----------------------------------------------------------------------------
banner "Stage 4/8 — SSH Brute Force from ${IP3} (T1110)"
step "Sending 35 SYN packets to port 22 spoofed from ${IP3}..."
hping3 -S -p 22 --count 35 --interval u600000 -a "$IP3" "$VICTIM"
done_msg "SSH brute force complete. Expected: SSH_BRUTEFORCE_SUSPECTED MEDIUM"
sleep 2

# -----------------------------------------------------------------------------
# 5. ARP Spoofing — SKIPPED (disrupts VirtualBox network stack)
# -----------------------------------------------------------------------------
banner "Stage 5/8 — ARP Spoofing (SKIPPED)"
step "ARP flood skipped — disrupts VirtualBox network interface."
sleep 1

# -----------------------------------------------------------------------------
# 6. DNS Tunneling — real Kali IP (dig needs real source for UDP response)
# -----------------------------------------------------------------------------
banner "Stage 6/8 — DNS Tunneling (T1071.004)"
step "Sending 50 rapid DNS queries..."
for i in $(seq 1 50); do
    dig @"$VICTIM" "query${i}.example.com" +time=1 +tries=1 &>/dev/null &
done
wait
done_msg "DNS rate flood complete. Expected: DNS_TUNNEL_SUSPECTED MEDIUM"
sleep 1

step "Sending long-subdomain query..."
LONG_NAME=$(python3 -c "print('A'*76)")
dig @"$VICTIM" "${LONG_NAME}.tunnel.example.com" +time=1 +tries=1 &>/dev/null
done_msg "Long DNS query sent. Expected: DNS_TUNNEL_SUSPECTED HIGH"
sleep 2

# -----------------------------------------------------------------------------
# 7. HTTP Brute Force — IP4 (Alibaba Cloud) via hping3 + real curl
# -----------------------------------------------------------------------------
banner "Stage 7/8 — HTTP Brute Force (T1110)"
step "Sending 30 POST requests to port 8080..."
for i in $(seq 1 30); do
    curl -s -X POST "http://${VICTIM}:8080/login" \
        -d "user=admin&pass=attempt${i}" \
        --connect-timeout 1 &>/dev/null &
done
wait
done_msg "HTTP brute force complete. Expected: HTTP_BRUTEFORCE_SUSPECTED MEDIUM"
sleep 2

# -----------------------------------------------------------------------------
# 8. Slow Loris — IP5 (rogue internal host)
# -----------------------------------------------------------------------------
banner "Stage 8/8 — Slow Loris from ${IP5} (T1499)"
step "Opening 25 half-open TCP connections spoofed from ${IP5}..."
hping3 -S -p 80 --count 25 --interval u200000 -a "$IP5" "$VICTIM"
done_msg "Slow Loris simulation complete. Expected: SLOW_LORIS_SUSPECTED MEDIUM then HIGH"

# -----------------------------------------------------------------------------
# Done
# -----------------------------------------------------------------------------
echo -e "\n${GREEN}${BOLD}========================================${RESET}"
echo -e "${GREEN}${BOLD}  Demo complete.${RESET}"
echo -e "${GREEN}${BOLD}  Attacks simulated from 5 different IPs${RESET}"
echo -e "${GREEN}${BOLD}  Check IDS console and dashboard.${RESET}"
echo -e "${GREEN}${BOLD}========================================${RESET}\n"
