#!/bin/sh
# Start Suricata on the target's interface with NetScan's rules, then forward
# every alert it writes to SOAR-Lite.
set -e
mkdir -p /var/log/suricata
# -k none: inside Docker, checksums are often left to the NIC and look invalid
suricata -i eth0 -S /netscan/detections/suricata/netscan.rules \
         -l /var/log/suricata -k none -D
exec python3 /sensor/forward.py
