"""
Follow Suricata's eve.json and send each NetScan alert to SOAR-Lite as it
appears, signed with the code from NetScan's detections/forward_alerts.py.

Every alert and every webhook is also reported to the lab's live console
(labevents.py), so you can watch the rule fire and the signed request go out.
"""

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from labevents import emit

sys.path.insert(0, "/netscan/detections")
from forward_alerts import NETSCAN_SIDS, SIEM_WEBHOOK_PATH, alert_payload, sign  # noqa: E402

EVE = Path("/var/log/suricata/eve.json")
RULES = Path(os.environ.get("SENSOR_RULES", "/netscan/detections/suricata/netscan.rules"))
SOAR_URL = os.environ.get("SOAR_URL", "http://soar:8000")
SECRET = os.environ["SOAR_WEBHOOK_SECRET"]
RETRIES = 20
TIMEOUT_SECONDS = 10


def post(event):
    """Sign one alert and send it. Returns (accepted, message, what the console shows)."""
    url = SOAR_URL.rstrip("/") + SIEM_WEBHOOK_PATH
    payload = alert_payload(event)
    body = json.dumps(payload).encode()
    timestamp = int(time.time())
    signature = sign(body, SECRET, timestamp)
    headers = {
        "Content-Type": "application/json",
        "X-Webhook-Timestamp": str(timestamp),
        "X-Webhook-Signature": signature,
    }
    shown = {
        "sid": event["alert"]["signature_id"], "path": SIEM_WEBHOOK_PATH, "timestamp": timestamp,
        # enough of the signature to recognise it, not enough to replay the request
        "signature": signature[:23] + "...", "bytes": len(body), "body": payload,
    }
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")  # noqa: S310 - lab URL
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310
            reply = json.load(response)
            shown.update(status=response.status, incident_id=reply.get("incident_id"))
            return True, f"incident #{reply.get('incident_id')}", shown
    except urllib.error.HTTPError as e:
        detail = e.read()[:200].decode(errors="replace")
        shown.update(status=e.code, detail=detail)
        return False, f"refused: HTTP {e.code} {detail}", shown
    except (urllib.error.URLError, OSError, ValueError) as e:
        shown.update(status=None, detail=e.__class__.__name__)
        return False, f"could not reach SOAR-Lite at {url} ({e.__class__.__name__})", shown


def send(event):
    sid = event["alert"]["signature_id"]
    for _ in range(RETRIES):
        ok, message, shown = post(event)
        emit("sensor", "sensor", "webhook", ok=ok, **shown)
        if ok:
            print(f"[sensor] sid {sid} from {event['src_ip']} -> SOAR-Lite {message}", flush=True)
            return
        print(f"[sensor] sid {sid}: {message}; retrying", flush=True)
        time.sleep(3)


def report_alert(event):
    alert = event["alert"]
    emit("sensor", "sensor", "alert",
         sid=alert["signature_id"], signature=alert.get("signature"), category=alert.get("category"),
         src=event.get("src_ip"), sport=event.get("src_port"),
         dst=event.get("dest_ip"), dport=event.get("dest_port"), proto=event.get("proto"),
         agent=(event.get("http") or {}).get("http_user_agent"),
         technique=(alert.get("metadata") or {}).get("mitre_technique_id"))


def report_rules():
    """Tell the console which rules Suricata loaded, in their own words."""
    try:
        lines = [line.strip() for line in RULES.read_text(encoding="utf-8").splitlines()
                 if line.startswith("alert ")]
    except OSError:
        return
    rules = []
    for line in lines:
        sid = re.search(r"\bsid:(\d+);", line)
        msg = re.search(r'msg:"([^"]*)"', line)
        rules.append({"sid": int(sid.group(1)) if sid else None, "msg": msg.group(1) if msg else "", "rule": line})
    emit("sensor", "sensor", "rules", rules=rules)


def follow(path):
    while not path.exists():
        time.sleep(0.5)
    with path.open() as f:
        pending = ""
        while True:
            chunk = f.readline()
            if not chunk:
                time.sleep(0.5)
                continue
            pending += chunk
            if pending.endswith("\n"):      # Suricata may still be writing the line
                yield pending
                pending = ""


if __name__ == "__main__":
    print(f"[sensor] Suricata running with NetScan rules; forwarding alerts to {SOAR_URL}", flush=True)
    report_rules()
    for line in follow(EVE):
        event = json.loads(line)
        if event.get("event_type") == "alert" and event["alert"]["signature_id"] in NETSCAN_SIDS:
            report_alert(event)
            send(event)
