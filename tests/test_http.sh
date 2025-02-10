#!/bin/bash

# Set up directories
LOG_DIR="tests/logs"
mkdir -p "$LOG_DIR"

# Variables
INTERFACE="eth0"  # Change if needed
TCPDUMP_FILE="$LOG_DIR/tcpdump_http.pcap"
MY_TOOL_FILE="$LOG_DIR/my_sniffer_http.log"
TCPDUMP_HTTP_LOG="$LOG_DIR/tcpdump_http.log"
TCPDUMP_FILTER="tcp port 80 or tcp port 8080"  # HTTP traffic only
CAPTURE_DURATION=10  # Duration to capture packets

# Ensure script runs as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (sudo)."
   exit 1
fi

# Start tcpdump in the background with a timeout
echo "[+] Starting tcpdump..."
timeout "$CAPTURE_DURATION" tcpdump -i "$INTERFACE" -w "$TCPDUMP_FILE" "$TCPDUMP_FILTER" > /dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 2  # Allow initialization

# Start your network sniffer in the background with a timeout
echo "[+] Running your network sniffer..."
timeout "$CAPTURE_DURATION" python3 capture.py -i "$INTERFACE" > "$MY_TOOL_FILE" 2>&1 &
MY_TOOL_PID=$!
sleep 2  # Allow initialization

# Generate HTTP traffic using curl
echo "[+] Generating HTTP traffic..."
curl -s http://www.aniwatch.com > /dev/null # Non-standard port test

# Ensure "Waiting" message prints at the right time
echo "[+] Waiting for packets to be captured..."
sleep "$CAPTURE_DURATION"

# Ensure both processes are terminated cleanly
echo "[+] Stopping tcpdump and sniffer..."
kill $TCPDUMP_PID 2>/dev/null
kill $MY_TOOL_PID 2>/dev/null
wait $TCPDUMP_PID 2>/dev/null
wait $MY_TOOL_PID 2>/dev/null

# Extract HTTP GET/POST requests from tcpdump for comparison
echo "[+] Extracting HTTP traffic from tcpdump..."
tcpdump -r "$TCPDUMP_FILE" -A | grep -E "GET|POST" > "$TCPDUMP_HTTP_LOG"

# Compare results
echo "[+] Comparing sniffer output with tcpdump..."
diff -u "$TCPDUMP_HTTP_LOG" "$MY_TOOL_FILE"

echo "[+] Test complete! Logs are in $LOG_DIR"