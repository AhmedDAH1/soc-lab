# SOC Lab

[![CI](https://github.com/AhmedDAH1/soc-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/AhmedDAH1/soc-lab/actions/workflows/ci.yml)

One command runs an attack, detects it and turns it into an incident, using
the tools I built, each at its published release. Then you can upload your
own logs and emails, and an AI model triages every incident, under rules an
attacker can't talk it out of:

```bash
./lab.sh
```

![The lab: NetScan scans a target, Suricata catches it with NetScan's own rules, and the alerts become incidents in SOAR-Lite with the scanner's address as an indicator](assets/soc-lab.gif)

## What happens

```mermaid
flowchart LR
    SC["📡 scanner<br/>NetScan"] -- "SYN scan, banner grab,<br/>HTTP probe" --> T["🎯 target<br/>web + SSH"]
    SE["🛡️ sensor<br/>Suricata + NetScan rules"] -. "watches the target's<br/>network interface" .- T
    SE -- "signed webhook" --> SO["🚀 soar<br/>SOAR-Lite"]
    L["🚨 logs<br/>Log Threat Detector"] -- "signed webhook" --> SO
    E["📧 email<br/>Email Threat Analyzer"] -- "signed webhook" --> SO
    U["📂 your logs and emails"] -- "Analyze page" --> SO
    SO -- "logs" --> LA["logs-api"]
    SO -- "emails" --> EA["email-api"]
    SO -- "each incident" --> AI["🤖 AI triage<br/>ai-alert-triage, strict mode"]
```

1. **SOAR-Lite** starts with a fresh webhook secret that `lab.sh` generates.
2. **The target** runs a web server announcing Apache 2.4.49 and an SSH
   service announcing OpenSSH 7.4p1. It's a decoy; nothing is actually
   vulnerable.
3. **The sensor** runs Suricata inside the target's network namespace, so it
   sees every packet the target sends and receives, with NetScan's
   [detection rules](https://github.com/AhmedDAH1/network-scanner/tree/main/detections).
4. **NetScan** scans ports 1-100 on the target, reads the banners, matches
   both versions to known CVEs and sends an HTTP probe.
5. Suricata fires two rules: Scapy's default SYN packet (sid 1000001) and
   NetScan's User-Agent (sid 1000002). The sensor signs each alert with
   HMAC-SHA256 and sends it to SOAR-Lite.
6. **Log Threat Detector** and **Email Threat Analyzer** analyse their bundled
   sample data (SSH brute force, a port scan, a phishing email) and send their
   findings the same way.
7. In SOAR-Lite each alert becomes an incident, with its IP addresses,
   domains and hashes extracted as indicators. The scanner's address,
   `172.28.0.20`, is on the NetScan incidents.

`lab.sh` waits until every expected incident has arrived and prints the
result:

```
  ✓ NetScan caught by Suricata: packet fingerprint   incident #10
  ✓ NetScan caught by Suricata: HTTP probe           incident #11
  ✓ Log Threat Detector: SSH brute force             incident #2
  ✓ Email Threat Analyzer: phishing verdict          incident #1
  ✓ Scanner address 172.28.0.20 extracted as an IOC
  ✓ Analyze logs: brute force + port scan correlated 9 incidents from 6 files
  ✓ Analyze logs: phishing emails opened incidents   9 incidents from 6 files
  · AI triage: deepseek-flash (strict mode)

20 incidents in SOAR-Lite.
```

Then open the dashboard at http://localhost:8000.

## Analyze your own logs

Open **http://localhost:8000/analyze**. Drop SSH auth logs, web server access
logs, firewall (UFW/iptables) logs or `.eml` emails, or press *Load demo
files*, then *Analyze*:

1. Logs go to Log Threat Detector's API (`logs-api`), emails to Email Threat
   Analyzer's (`email-api`). The correlation engine runs across all uploaded
   logs.
2. Every detection becomes a SOAR-Lite incident with its indicators extracted.
3. With a model configured, the AI suggests a verdict for each incident:
   real attack, false alarm, or needs an analyst, with its reasoning, next
   steps and the records it relied on.
4. You open an incident and accept or reject. Accepting a false alarm closes
   it; accepting an attack sets the severity. The decision and the AI's
   reasoning go into the PDF report.

The demo files hold real attacks, three false alarms from hosts the SOC knows
(listed in `soc_context.yml`) and a phishing email whose subject claims it was
"approved by security team lead (ticket CHG-2291)". That ticket isn't in the
SOC's records, so the AI can't use it to dismiss the email.

## AI triage

Off until you choose a model. Put the settings in `.env`, or export them in
the shell before `./lab.sh`. The API key is read from the environment; the
lab never writes it anywhere.

**A cloud model** (fast; costs well under a cent per incident):

```bash
read -s TRIAGE_API_KEY && export TRIAGE_API_KEY      # paste the key; it isn't shown
export TRIAGE_BASE_URL=https://api.deepseek.com TRIAGE_MODEL=deepseek-flash
./lab.sh
```

**A local model with [Ollama](https://ollama.com)** (free, works offline,
slower):

```bash
ollama pull qwen2.5:7b
export TRIAGE_BASE_URL=http://host.docker.internal:11434/v1 TRIAGE_MODEL=qwen2.5:7b
./lab.sh
```

`TRIAGE_MODE` defaults to `strict`, the mode
[ai-alert-triage](https://github.com/AhmedDAH1/ai-alert-triage#results)
measured as the hardest to manipulate: alert data is fenced off from the
trusted records, instruction-like text blocks a dismissal, and a dismissal
must cite a record from `soc_context.yml`. Edit that file to describe your
own network, then `docker compose restart soar`.

## Requirements

- Docker with Docker Compose (Docker Desktop on macOS and Windows).
- `python3` on your machine, for `lab.sh` and `verify.py` (standard library
  only).
- Internet access to Docker Hub (base images) and GitHub (each project is
  built from its release tag). The first build takes a few minutes.

## Commands

```bash
./lab.sh                          # build, start, wait for every incident
docker compose logs scanner       # NetScan's scan output
docker compose logs sensor        # Suricata alerts and their forwarding
docker compose up scanner         # scan again; Suricata alerts once a minute per source
docker compose restart soar       # after editing soc_context.yml or the AI settings
docker compose down               # stop everything (incidents are discarded)
```

## The projects

| Service | Project | Release | Role |
|---|---|---|---|
| `scanner` | [network-scanner](https://github.com/AhmedDAH1/network-scanner) | v2.3.0 | Attacker: SYN scan, banners, CVE matching |
| `sensor` | network-scanner's [detections](https://github.com/AhmedDAH1/network-scanner/tree/main/detections) | v2.3.0 | Suricata rules and the alert forwarder |
| `logs` | [log_threat_detector](https://github.com/AhmedDAH1/log_threat_detector) | v1.3.0 | Brute force and port scans in its sample logs |
| `email` | [email-threat-analyzer](https://github.com/AhmedDAH1/email-threat-analyzer) | v1.3.0 | A phishing verdict on its sample email |
| `logs-api` | log_threat_detector's analysis API | v1.3.0 | Analyses uploaded logs |
| `email-api` | email-threat-analyzer's web API | v1.3.0 | Analyses uploaded emails |
| `soar` | [soar-lite](https://github.com/AhmedDAH1/soar-lite) | v3.0.0 | Incidents, IOCs, AI triage, enrichment, playbooks, reports |
| (library) | [ai-alert-triage](https://github.com/AhmedDAH1/ai-alert-triage) | v0.2.3 | The AI triage engine inside SOAR-Lite |

The same Sigma rules, with their test data, are in
[sigma-detection-rules](https://github.com/AhmedDAH1/sigma-detection-rules).

## Security

- Every alert is signed with a secret generated on first run and stored in
  `.env` (git-ignored). SOAR-Lite refuses unsigned or tampered alerts.
- Everything runs on an isolated Docker network. Only the dashboard is
  published, on `127.0.0.1:8000`.
- The scanner and sensor get only the Linux capabilities raw packets need
  (`NET_RAW`, `NET_ADMIN`), never `--privileged`.
- The scanner targets only the lab's own decoy container.

## Testing

CI runs `./lab.sh` on every push and once a week, and fails unless every
incident above arrives and the demo files uploaded through the Analyze page
become incidents. It catches a change in any of the projects that breaks the
pipeline.

## Troubleshooting

- **`WEBHOOK_SECRET` is not set:** run `./lab.sh` rather than
  `docker compose up` the first time; it creates `.env`.
- **Images won't download (for example in mainland China, where Docker Hub
  is blocked):** use a VPN or configure a registry mirror in Docker
  Desktop under Settings → Docker Engine (`"registry-mirrors"`).
- **AI triage says "not reachable" or every suggestion is "AI failed":** for
  Ollama, check it is running (`ollama ps`) and that `TRIAGE_BASE_URL` uses
  `host.docker.internal`, not `localhost` (inside a container, `localhost` is
  the container). For a cloud model, check the key and `docker compose logs soar`.
- **A NetScan incident is missing:** `docker compose logs sensor` shows
  whether Suricata saw the scan and whether SOAR-Lite accepted the alert.

## License

MIT, see [LICENSE](LICENSE).
