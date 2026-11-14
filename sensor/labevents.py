"""
Report what the sensor sees to the lab's live console.

Each event is one JSON line in the shared /lab folder. The console only reads
these files. If the folder isn't there (the sensor run on its own), nothing
is written and the sensor works as before.
"""

import json
import os
import time
from pathlib import Path

LAB_DIR = Path(os.environ.get("LAB_DIR", "/lab"))


def emit(file, stage, kind, **data):
    """Append one event. Never raises: the console is optional, detection is not."""
    try:
        if not (LAB_DIR / "events").is_dir():
            return
        line = json.dumps({"ts": time.time(), "stage": stage, "kind": kind, **data})
        with (LAB_DIR / "events" / f"{file}.jsonl").open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    except (OSError, TypeError, ValueError):
        pass
