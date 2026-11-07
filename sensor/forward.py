"""
Follow Suricata's eve.json and send each NetScan alert to SOAR-Lite as it
appears, using the signed-webhook code from NetScan's
detections/forward_alerts.py.
"""

import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, "/netscan/detections")
from forward_alerts import NETSCAN_SIDS, forward  # noqa: E402

EVE = Path("/var/log/suricata/eve.json")
SOAR_URL = os.environ.get("SOAR_URL", "http://soar:8000")
SECRET = os.environ["SOAR_WEBHOOK_SECRET"]
RETRIES = 20


def send(event):
    sid = event["alert"]["signature_id"]
    for _ in range(RETRIES):
        ok, message = forward(event, SOAR_URL, SECRET)
        if ok:
            print(f"[sensor] sid {sid} from {event['src_ip']} -> SOAR-Lite {message}", flush=True)
            return
        print(f"[sensor] sid {sid}: {message}; retrying", flush=True)
        time.sleep(3)


def follow(path):
    while not path.exists():
        time.sleep(0.5)
    with path.open() as f:
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line


if __name__ == "__main__":
    print(f"[sensor] Suricata running with NetScan rules; forwarding alerts to {SOAR_URL}", flush=True)
    for line in follow(EVE):
        event = json.loads(line)
        if event.get("event_type") == "alert" and event["alert"]["signature_id"] in NETSCAN_SIDS:
            send(event)
