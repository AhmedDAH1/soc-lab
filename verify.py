"""
Check that the pipeline worked end to end: wait until SOAR-Lite holds an
incident from every tool, then print them.

    python3 verify.py [--timeout SECONDS] [--url http://localhost:8000]

Exits 0 when every expected incident arrived, 1 otherwise (used by CI).
"""

import argparse
import json
import sys
import time
import urllib.request

SCANNER_IP = "172.28.0.20"

# (what arrives, title fragment to look for)
EXPECTED = [
    ("NetScan caught by Suricata: packet fingerprint", "NETSCAN Scapy-default TCP SYN probe"),
    ("NetScan caught by Suricata: HTTP probe", "NETSCAN HTTP service probe"),
    ("Log Threat Detector: SSH brute force", "BRUTE_FORCE from"),
    ("Email Threat Analyzer: phishing verdict", "[EMAIL_GATEWAY] Phishing email"),
]


def get(url):
    with urllib.request.urlopen(url, timeout=5) as response:  # noqa: S310 - local lab URL
        return json.load(response)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://localhost:8000")
    parser.add_argument("--timeout", type=int, default=600)
    args = parser.parse_args()

    deadline = time.time() + args.timeout
    incidents, missing = [], EXPECTED
    while time.time() < deadline:
        try:
            incidents = get(f"{args.url}/api/incidents/?limit=100")
        except OSError:
            incidents = []
        missing = [(label, frag) for label, frag in EXPECTED
                   if not any(frag in i["title"] for i in incidents)]
        if not missing:
            break
        time.sleep(3)

    for label, frag in EXPECTED:
        match = next((i for i in incidents if frag in i["title"]), None)
        mark = "✓" if match else "✗"
        print(f"  {mark} {label:<48} {'incident #' + str(match['id']) if match else 'not received'}")

    if missing:
        print(f"\nMissing after {args.timeout}s. Check: docker compose logs sensor scanner logs email")
        return 1

    # The scanner's address must be on the NetScan incident as an indicator
    netscan = next(i for i in incidents if EXPECTED[0][1] in i["title"])
    iocs = [ioc["value"] for ioc in get(f"{args.url}/api/incidents/{netscan['id']}")["iocs"]]
    found = SCANNER_IP in iocs
    print(f"  {'✓' if found else '✗'} {'Scanner address ' + SCANNER_IP + ' extracted as an IOC':<48}")
    print(f"\n{len(incidents)} incidents in SOAR-Lite.")
    return 0 if found else 1


if __name__ == "__main__":
    sys.exit(main())
