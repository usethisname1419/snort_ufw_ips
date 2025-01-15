#!/bin/bash

# Define file locations and constants
LOG_FILE="/var/log/snort/alert_fast.txt"
BLOCKED_IPS_FILE="/var/log/snort/blocked_ips.txt"
BLOCKED_ALERTS_FILE="/var/log/snort/blocked_alerts.log"
TEMP_ALERTS_FILE="/tmp/alerts_count.txt"
BLOCK_DURATION=$((14 * 3600))  # 14 hours in seconds

# Function to check if a command exists
check_command() {
    local cmd=$1
    if ! command -v "$cmd" &>/dev/null; then
        echo "[$(date)] ERROR: $cmd is not installed or not in PATH!"
        exit 1
    fi
}

# Initial setup checks
echo "[$(date)] Verifying UFW installation and accessibility..."
check_command "ufw"

if ! sudo ufw status &>/dev/null; then
    echo "[$(date)] ERROR: Failed to execute 'ufw status'. Check permissions or UFW setup!"
    exit 1
fi

# Ensure the blocked IPs file is writable
if [ ! -w "$BLOCKED_IPS_FILE" ]; then
    echo "[$(date)] ERROR: Cannot write to $BLOCKED_IPS_FILE. Check permissions!"
    exit 1
fi

# Function to block an IP and log the action
block_ip() {
    local ip=$1
    local alert_line=$2
    local priority=$3

    # Check if the IP is already blocked
    if ! grep -q "^$ip$" "$BLOCKED_IPS_FILE"; then
        echo "[$(date)] Blocking IP: $ip (Priority $priority)"
        sudo ufw deny from "$ip"
        echo "$ip" >>"$BLOCKED_IPS_FILE"
        echo "$(date): Blocked $ip - Alert: $alert_line" >>"$BLOCKED_ALERTS_FILE"

        # If Priority 2, unblock after 14 hours
        if [[ "$priority" == "2" ]]; then
            (sleep "$BLOCK_DURATION" && sudo ufw delete deny from "$ip" && sed -i "/^$ip$/d" "$BLOCKED_IPS_FILE") &
        fi
    fi
}

# Function to extract the first public IP from a log entry
extract_public_ip() {
    local log_line=$1
    echo "$log_line" | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | grep -vE '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)' | head -n 1
}

# Process existing Priority 1 alerts in the log file
echo "[$(date)] Processing existing Priority 1 alerts in $LOG_FILE..."
grep "Priority: 1" "$LOG_FILE" | while read -r line; do
    # Extract the first public source IP address
    SRC_IP=$(extract_public_ip "$line")
    
    # Only proceed if a valid IP address is found
    if [[ -n "$SRC_IP" ]]; then
        block_ip "$SRC_IP" "$line" "1"
    fi
done
echo "[$(date)] Finished processing old Priority 1 alerts."

# Monitor Snort log file for new Priority 1 and 2 alerts
echo "[$(date)] Switching to real-time log monitoring..."
tail -Fn0 "$LOG_FILE" | while read -r line; do
    if echo "$line" | grep -q "Priority: 1\|Priority: 2"; then
        # Extract the first public source IP address
        SRC_IP=$(extract_public_ip "$line")
        PRIORITY=$(echo "$line" | grep -oP 'Priority: \d' | grep -oP '\d')

        # Only proceed if a valid IP address is found
        if [[ -n "$SRC_IP" ]]; then
            if [[ "$PRIORITY" == "1" ]]; then
                block_ip "$SRC_IP" "$line" "1"
            elif [[ "$PRIORITY" == "2" ]]; then
                echo "$SRC_IP:$line" >>"$TEMP_ALERTS_FILE"
            fi
        fi
    fi
done &

# Process Priority 2 alerts every 5 minutes
while true; do
    sleep 300
    if [[ -s "$TEMP_ALERTS_FILE" ]]; then
        awk -F':' '{count[$1]++; lines[$1] = $2} END {
            for (ip in count) {
                if (count[ip] >= 3) {
                    print ip ":" lines[ip];
                }
            }
        }' "$TEMP_ALERTS_FILE" | while IFS=: read -r ip alert_line; do
            block_ip "$ip" "$alert_line" "2"
        done
        >"$TEMP_ALERTS_FILE"  # Clear the temporary file
    fi
done
