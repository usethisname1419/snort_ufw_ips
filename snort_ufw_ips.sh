#!/bin/bash

# Define log file location
LOG_FILE="/var/log/snort/{you alert file}"
BLOCKED_IPS_FILE="/var/log/snort/blocked_ips.txt"

# Parse the log for new Priority 1 alerts
grep "Priority: 1" "$LOG_FILE" | while read -r line; do
  # Extract the source IP (after '->')
  SRC_IP=$(echo "$line" | grep -oP '\d{1,3}(\.\d{1,3}){3}(?= ->)')

  # Check if the IP is already blocked
  if ! grep -q "$SRC_IP" "$BLOCKED_IPS_FILE"; then
    echo "Blocking $SRC_IP due to Priority 1 alert."

    # Block the IP using UFW
    sudo ufw deny from "$SRC_IP"

    # Log the blocked IP
    echo "$SRC_IP" >> "$BLOCKED_IPS_FILE"
  fi
done
