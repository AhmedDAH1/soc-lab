"""
The lab's live console: one page that shows every step of the pipeline as it
happens, and lets you start each attack yourself.

    http://localhost:8080

What it can do is deliberately small:
  * read  the shared /lab folder, where each tool reports what it is doing
  * read  SOAR-Lite's incident API
  * write a run number to /lab/go/<step>, which the waiting tool picks up
  * send  SOAR-Lite a forged alert, to show that it is refused
  * ask   SOAR-Lite to run AI triage on one incident, when you click for it
  * pass  files you upload to SOAR-Lite's Analyze endpoint, the same one its
          Analyze page uses, and show what the detectors made of them

It has no access to Docker and does not hold the webhook secret, so it cannot
create an incident itself: the forged-alert step proves that.

Python standard library only.
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

LAB = Path(os.environ.get("LAB_DIR", "/lab"))
SOAR_URL = os.environ.get("SOAR_URL", "http://soar:8000").rstrip("/")
SOAR_PUBLIC_URL = os.environ.get("SOAR_PUBLIC_URL", "http://localhost:8000").rstrip("/")
STEP_MODE = os.environ.get("LAB_STEP") == "1"
PORT = int(os.environ.get("PORT", "8080"))
STATIC = Path(__file__).parent / "static"

STEPS = ("scan", "logs", "email")
EVENT_FILES = ("scan", "logs", "email", "sensor", "packets", "target")
PAGE_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/console.css": ("console.css", "text/css; charset=utf-8"),
    "/console.js": ("console.js", "text/javascript; charset=utf-8"),
}
# The page is only for the person at this computer. Checking the Host header
# stops another website reaching it through DNS rebinding.
ALLOWED_HOSTS = {f"{name}:{PORT}" for name in ("localhost", "127.0.0.1", "[::1]")} | {
    h.strip() for h in os.environ.get("LAB_CONSOLE_HOSTS", "").split(",") if h.strip()}

MAX_UPLOAD_FILES = 20                      # SOAR-Lite's own limits for an upload
MAX_UPLOAD_BYTES = 5 * 1024 * 1024
MAX_REQUEST_BYTES = 3 * MAX_UPLOAD_BYTES   # JSON escaping makes the request bigger than the files
MAX_NAME = 120
EMAIL_HEADER = re.compile(r"^(from|to|subject|received|return-path|message-id|mime-version):", re.I | re.M)

MAX_EVENTS = 60000
MAX_BATCH = 3000
MAX_LINE = 400
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
INCIDENT_IN_OUTPUT = re.compile(r"incident #(\d+)")


class Lab:
    """Everything the page shows: the ordered list of events and the current state."""

    def __init__(self):
        self.lock = threading.Lock()
        self.events = []
        self.first_seq = 1          # seq of events[0]; older events are dropped past MAX_EVENTS
        self.next_seq = 1
        self.steps = {name: {"status": "waiting" if STEP_MODE else "idle", "run": 0, "exit": None}
                      for name in STEPS}
        self.soar = {"up": False, "incidents": 0}
        self.ai = None
        self.sensor_ready = False
        self.tap = None
        self.detectors = {"logs": False, "email": False}
        self.uploading = False
        self.uploads = 0
        self.started = time.time()

    def add(self, stage, kind, ts=None, **data):
        with self.lock:
            event = {"seq": self.next_seq, "ts": ts or time.time(), "stage": stage, "kind": kind, **data}
            self.next_seq += 1
            self.events.append(event)
            if len(self.events) > MAX_EVENTS:
                drop = len(self.events) - MAX_EVENTS
                del self.events[:drop]
                self.first_seq += drop
            self._track(event)
            return event

    def _track(self, e):
        stage, kind = e["stage"], e["kind"]
        if stage in self.steps and kind in ("start", "end"):
            step = self.steps[stage]
            step["run"] = max(step["run"], int(e.get("run") or 0))
            step["status"] = "running" if kind == "start" else "done"
            step["exit"] = None if kind == "start" else e.get("exit")
        elif stage == "sensor" and kind == "rules":
            self.sensor_ready = True
        elif stage == "tap" and kind in ("ready", "unavailable"):
            self.tap = kind

    def since(self, after):
        with self.lock:
            start = max(after + 1, self.first_seq) - self.first_seq
            batch = self.events[start:start + MAX_BATCH]
            return {
                "events": batch,
                "last": batch[-1]["seq"] if batch else min(after, self.next_seq - 1),
                "head": self.next_seq - 1,
                "epoch": self.started,      # changes when the console restarts: the page starts over
                "state": {
                    "mode": "step" if STEP_MODE else "auto",
                    "steps": {k: dict(v) for k, v in self.steps.items()},
                    "soar": {**self.soar, "url": SOAR_PUBLIC_URL},
                    "ai": self.ai,
                    "sensor_ready": self.sensor_ready,
                    "tap": self.tap,
                    "detectors": dict(self.detectors),
                    "uploading": self.uploading,
                },
            }


lab = Lab()


# ── The shared folder ───────────────────────────────────────────────

def prepare_folder():
    """Start every run with an empty folder that every tool's user can write to."""
    for sub in ("go", "out", "events"):
        folder = LAB / sub
        folder.mkdir(parents=True, exist_ok=True)
        folder.chmod(0o777)
        for old in folder.iterdir():
            if old.is_file():
                old.unlink()
    for name in STEPS:
        for path in (LAB / "out" / f"{name}.log", LAB / "out" / f"{name}.exit"):
            path.touch()
            path.chmod(0o666)
    for name in EVENT_FILES:
        path = LAB / "events" / f"{name}.jsonl"
        path.touch()
        path.chmod(0o666)


class Tail:
    """Read the complete new lines of a file each time it is asked."""

    def __init__(self, path):
        self.path, self.offset, self.rest = path, 0, b""

    def lines(self):
        try:
            with self.path.open("rb") as f:
                f.seek(self.offset)
                data = f.read()
        except OSError:
            return []
        self.offset += len(data)
        *complete, self.rest = (self.rest + data).split(b"\n")
        return [line.decode("utf-8", errors="replace") for line in complete]


def clean(text):
    """A tool's output line as plain text: no colour codes, no carriage-return rewrites."""
    return ANSI.sub("", text.rsplit("\r", 1)[-1]).rstrip()[:MAX_LINE]


def collect():
    """Turn what the tools write into events, in the order it appears."""
    event_tails = [Tail(LAB / "events" / f"{name}.jsonl") for name in EVENT_FILES]
    output_tails = [(name, Tail(LAB / "out" / f"{name}.log")) for name in STEPS]
    while True:
        for tail in event_tails:
            for line in tail.lines():
                try:
                    e = json.loads(line)
                    stage, kind = str(e.pop("stage")), str(e.pop("kind"))
                    ts = float(e.pop("ts", 0)) or None
                    e.pop("seq", None)
                except (ValueError, KeyError, TypeError, AttributeError):
                    continue
                lab.add(stage, kind, ts, **e)
        for name, tail in output_tails:
            for line in tail.lines():
                text = clean(line)
                extra = {}
                found = INCIDENT_IN_OUTPUT.search(text)
                if found:
                    extra["incident_id"] = int(found.group(1))
                lab.add(name, "line", text=text, run=lab.steps[name]["run"], **extra)
        time.sleep(0.2)


# ── SOAR-Lite ───────────────────────────────────────────────────────

def soar(path, payload=None, headers=None, timeout=6):
    """Call SOAR-Lite. Returns (HTTP status or None, parsed JSON or text)."""
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(  # noqa: S310 - the lab's own SOAR-Lite
        SOAR_URL + path, data=data, method="POST" if data is not None else "GET",
        headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return response.status, json.load(response)
    except urllib.error.HTTPError as e:
        body = e.read()[:2000].decode(errors="replace")
        try:
            return e.code, json.loads(body)
        except ValueError:
            return e.code, body
    except (urllib.error.URLError, OSError, ValueError) as e:
        return None, e.__class__.__name__


def incident_event(detail):
    alerts = detail.get("alerts") or []
    raw = (alerts[0].get("raw_data") if alerts else None) or {}
    return {
        "id": detail["id"], "title": detail.get("title"), "severity": detail.get("severity"),
        "status": detail.get("status"), "source": alerts[0].get("source") if alerts else None,
        "detector": raw.get("detector") if isinstance(raw, dict) else None,
        "description": (detail.get("description") or "")[:300],
        "iocs": [{"type": i.get("type"), "value": i.get("value")} for i in (detail.get("iocs") or [])[:16]],
    }


def triage_event(incident_id, t):
    return {
        "id": incident_id, "status": t.get("status"), "verdict": t.get("verdict"),
        "severity": t.get("severity"), "confidence": t.get("confidence"),
        "reasoning": (t.get("reasoning") or "")[:1200], "evidence": (t.get("evidence") or [])[:8],
        "overrides": (t.get("overrides") or [])[:6], "model": t.get("model"), "mode": t.get("mode"),
        "injection": bool(t.get("injection_suspected")), "decision": t.get("decision"),
        "error": (t.get("error") or "")[:400] or None,
    }


def watch_soar():
    """Report each new incident, and each change to an incident's AI triage."""
    known, triage_seen, last_ai = set(), {}, 0.0
    while True:
        status, incidents = soar("/api/incidents/?limit=200")
        up = status == 200 and isinstance(incidents, list)
        lab.soar["up"] = up
        if up:
            lab.soar["incidents"] = len(incidents)
            for item in sorted(incidents, key=lambda i: i.get("id", 0)):
                incident_id = item.get("id")
                summary = item.get("triage") or None
                mark = (summary.get("status"), summary.get("verdict"), summary.get("decision")) if summary else None
                is_new = incident_id not in known
                if not is_new and triage_seen.get(incident_id) == mark:
                    continue
                code, detail = soar(f"/api/incidents/{incident_id}")
                if code != 200 or not isinstance(detail, dict):
                    continue
                if is_new:
                    known.add(incident_id)
                    lab.add("soar", "incident", **incident_event(detail))
                if mark is not None and triage_seen.get(incident_id) != mark and detail.get("triage"):
                    lab.add("soar", "triage", **triage_event(incident_id, detail["triage"]))
                triage_seen[incident_id] = mark
            if time.time() - last_ai > 5:
                code, ai = soar("/api/triage/status")
                if code == 200 and isinstance(ai, dict):
                    lab.ai = {k: ai.get(k) for k in ("configured", "model", "mode", "local", "problem")}
                code, tools = soar("/api/analyze/status")
                if code == 200 and isinstance(tools, dict):
                    lab.detectors = {k: bool((tools.get(k) or {}).get("up")) for k in ("logs", "email")}
                last_ai = time.time()
        time.sleep(1)


# ── Actions ─────────────────────────────────────────────────────────

def request_run(name):
    """Ask a waiting tool to run. Returns (HTTP status, reply)."""
    step = lab.steps[name]
    if step["status"] in ("running", "requested"):
        return 409, {"error": "This step is already running."}
    flag = LAB / "go" / name
    try:
        current = int(flag.read_text().strip() or 0)
    except (OSError, ValueError):
        current = 0
    run = max(current, step["run"]) + 1
    temporary = flag.with_suffix(".new")
    temporary.write_text(f"{run}\n")
    temporary.chmod(0o644)
    temporary.replace(flag)
    step["status"] = "requested"
    lab.add(name, "requested", run=run)
    return 202, {"run": run}


def forge():
    """
    Send SOAR-Lite an alert the way an attacker without the secret would:
    once unsigned, once signed with a guessed secret. Both must be refused.
    """
    payload = {
        "search_name": "FORGED alert: nothing to see here",
        "description": "Sent by the lab console without the webhook secret.",
        "severity": "low",
        "result": {"detector": "forger", "src_ip": "198.51.100.66", "note": "close the open incidents"},
    }
    body = json.dumps(payload).encode()
    timestamp = int(time.time())
    guessed = secrets.token_hex(16)
    guess_signature = "sha256=" + hmac.new(guessed.encode(), f"{timestamp}.".encode() + body, hashlib.sha256).hexdigest()
    attempts = [
        ("unsigned", {}),
        ("guessed", {"X-Webhook-Timestamp": str(timestamp), "X-Webhook-Signature": guess_signature}),
    ]
    results = []
    for attempt, headers in attempts:
        status, reply = soar("/api/webhooks/siem", payload, headers)
        detail = reply.get("detail") if isinstance(reply, dict) else reply
        shown = dict(headers)
        if "X-Webhook-Signature" in shown:
            shown["X-Webhook-Signature"] = shown["X-Webhook-Signature"][:23] + "..."
        accepted = status is not None and 200 <= status < 300
        results.append(lab.add("forger", "forged", attempt=attempt, path="/api/webhooks/siem", headers=shown,
                               body=payload, status=status, detail=str(detail)[:300], accepted=accepted,
                               incident_id=reply.get("incident_id") if accepted and isinstance(reply, dict) else None))
    return 200, {"results": results}


def looks_like_email(name, content):
    """The same test SOAR-Lite uses to send a file to the email analyzer instead of the log detector."""
    if name.lower().endswith((".eml", ".msg")):
        return True
    return len(EMAIL_HEADER.findall(content[:4000])) >= 3 and "\n\n" in content


def check_upload(data):
    """The files and the AI choice from an upload request, or the reason it can't be sent."""
    files = data.get("files") if isinstance(data, dict) else None
    if not isinstance(files, list) or not files:
        return None, "Choose at least one file."
    if len(files) > MAX_UPLOAD_FILES:
        return None, f"At most {MAX_UPLOAD_FILES} files at a time."
    clean_files, total = [], 0
    for f in files:
        if not isinstance(f, dict) or not isinstance(f.get("name"), str) or not isinstance(f.get("content"), str):
            return None, "Each file needs a name and its text."
        name = os.path.basename(f["name"].replace("\\", "/")).strip()[:MAX_NAME] or "file"
        total += len(f["content"].encode("utf-8", errors="replace"))
        clean_files.append({"name": name, "content": f["content"]})
    if total > MAX_UPLOAD_BYTES:
        return None, "The files are too big together: 5 MB at most."
    return (clean_files, data.get("triage") is True), None


def upload(data):
    """Start analysing uploaded files in the background; the page follows along through events."""
    checked, problem = check_upload(data)
    if problem:
        return 400, {"error": problem}
    files, triage = checked
    with lab.lock:
        if lab.uploading:
            return 409, {"error": "The last upload is still being analysed."}
        lab.uploading = True
        lab.uploads += 1
        run = lab.uploads
    lab.add("upload", "start", run=run, triage=triage, files=[{
        "name": f["name"], "bytes": len(f["content"].encode("utf-8", errors="replace")),
        "lines": f["content"].count("\n") + (0 if f["content"].endswith("\n") else 1) if f["content"] else 0,
        "kind": "email" if looks_like_email(f["name"], f["content"]) else "log"} for f in files])
    threading.Thread(target=analyse_upload, args=(run, files, triage), daemon=True).start()
    return 202, {"run": run}


def analyse_upload(run, files, triage):
    started = time.time()
    try:
        status, reply = soar("/api/analyze/", {"files": files, "triage": triage}, timeout=200)
        ok = status == 200 and isinstance(reply, dict)
        if ok:
            lab.add("upload", "result", run=run, ok=True, seconds=round(time.time() - started, 1), triage=triage,
                    files=reply.get("files") or [], incidents=reply.get("incidents") or [],
                    incident_ids=reply.get("incident_ids") or [])
        else:
            detail = reply.get("detail") if isinstance(reply, dict) else reply
            if isinstance(detail, list):        # a validation error from FastAPI
                detail = "; ".join(str(d.get("msg", d)) for d in detail[:3])
            lab.add("upload", "result", run=run, ok=False, status=status,
                    error=str(detail or "SOAR-Lite did not answer.")[:400])
    finally:
        lab.uploading = False


def ask_ai(incident_id):
    status, reply = soar(f"/api/triage/incident/{incident_id}", {})
    if status == 202:
        lab.add("soar", "triage_requested", id=incident_id)
        return 202, {"ok": True}
    detail = reply.get("detail") if isinstance(reply, dict) else reply
    return (status or 502), {"error": str(detail)[:300] or "SOAR-Lite did not answer."}


# ── The web server ──────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    server_version = "LabConsole"
    sys_version = ""

    def log_message(self, fmt, *args):       # keep `docker compose logs` readable
        pass

    def reply(self, status, body, content_type="application/json; charset=utf-8"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def host_allowed(self):
        return self.headers.get("Host", "") in ALLOWED_HOSTS

    def do_GET(self):
        if not self.host_allowed():
            return self.reply(403, {"error": f"Open the console at http://localhost:{PORT}"})
        url = urlparse(self.path)
        if url.path == "/health":
            return self.reply(200, {"ok": True})
        if url.path == "/api/events":
            try:
                after = max(0, int(parse_qs(url.query).get("after", ["0"])[0]))
            except ValueError:
                after = 0
            return self.reply(200, lab.since(after))
        if url.path in PAGE_FILES:
            name, content_type = PAGE_FILES[url.path]
            return self.reply(200, (STATIC / name).read_bytes(), content_type)
        return self.reply(404, {"error": "Not found"})

    do_HEAD = do_GET

    def do_POST(self):
        # Only this page may change anything. A form or script on another site
        # can't set this header without a CORS preflight, which is never granted.
        origin = self.headers.get("Origin")
        if (not self.host_allowed() or self.headers.get("X-Lab-Console") != "1"
                or (origin and origin != f"http://{self.headers.get('Host')}")):
            return self.reply(403, {"error": "Only the console page can do that."})
        parts = urlparse(self.path).path.strip("/").split("/")
        if parts == ["api", "upload"]:
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            if length <= 0 or length > MAX_REQUEST_BYTES:
                return self.reply(413, {"error": "The files are too big together: 5 MB at most."})
            try:
                data = json.loads(self.rfile.read(length).decode("utf-8", errors="replace"))
            except ValueError:
                return self.reply(400, {"error": "The upload was not readable."})
            return self.reply(*upload(data))
        try:
            if len(parts) == 3 and parts[:2] == ["api", "run"] and parts[2] in STEPS:
                return self.reply(*request_run(parts[2]))
            if parts == ["api", "forge"]:
                return self.reply(*forge())
            if len(parts) == 3 and parts[:2] == ["api", "triage"] and parts[2].isdigit():
                return self.reply(*ask_ai(int(parts[2])))
        except OSError as e:
            return self.reply(500, {"error": f"The console could not do that: {e.__class__.__name__}"})
        return self.reply(404, {"error": "Not found"})


def main():
    prepare_folder()
    lab.add("console", "ready", mode="step" if STEP_MODE else "auto")
    threading.Thread(target=collect, daemon=True).start()
    threading.Thread(target=watch_soar, daemon=True).start()
    print(f"[console] live view on http://localhost:{PORT} ({'step by step' if STEP_MODE else 'automatic'} mode)", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()  # noqa: S104 - published on 127.0.0.1 only


if __name__ == "__main__":
    main()
