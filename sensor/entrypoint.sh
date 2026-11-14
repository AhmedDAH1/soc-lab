#!/bin/sh
# Start Suricata on the target's interface with NetScan's rules, then forward
# every alert it writes to SOAR-Lite. A packet tap reports the traffic to the
# lab's live console; it only shows packets and takes no part in detection.
set -e
mkdir -p /var/log/suricata
# -k none: inside Docker, checksums are often left to the NIC and look invalid
suricata -i eth0 -S /netscan/detections/suricata/netscan.rules \
         -l /var/log/suricata -k none -D
python3 /sensor/sniff.py &
exec python3 /sensor/forward.py
