# Suricata watching the target's network interface, plus a forwarder that
# sends its alerts to SOAR-Lite. The detection rules and the forwarding code
# come from the NetScan repository at a fixed release.
FROM ubuntu:24.04

ARG NETSCAN_VERSION=v2.3.0
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      suricata python3 git ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && git clone --depth 1 --branch "$NETSCAN_VERSION" https://github.com/AhmedDAH1/network-scanner.git /netscan

COPY entrypoint.sh forward.py /sensor/
RUN chmod +x /sensor/entrypoint.sh
ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["/sensor/entrypoint.sh"]
