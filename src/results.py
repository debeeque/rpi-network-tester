import hashlib
import json
import os
import subprocess
from datetime import datetime

RESULTS_DIR = "/home/muk0015/results"


def md5(path):
    try:
        with open(path, "rb") as f:
            return hashlib.md5(f.read()).hexdigest()
    except OSError:
        return None


def ntp_synced():
    try:
        return subprocess.run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"],
                              capture_output=True, text=True, timeout=3).stdout.strip() == "yes"
    except (OSError, subprocess.SubprocessError):
        return None


def parse_result(out, script):
    head = "RESULT %s " % script
    for line in reversed(out.splitlines()):
        if line.startswith(head):
            try:
                return json.loads(line[len(head):])
            except ValueError:
                return None
    return None


def save(script, port, result, now=None):
    """~/results/<YYYYMMDD>/<HHMMSS>_<script>_<port>.json with time, NTP state and the script's md5."""
    now = now or datetime.now().astimezone()
    folder = os.path.join(RESULTS_DIR, now.strftime("%Y%m%d"))
    os.makedirs(folder, exist_ok=True)
    name = script[:-3] if script.endswith(".py") else script
    path = os.path.join(folder, "%s_%s_%s.json" % (now.strftime("%H%M%S"), name, port))
    record = {"script": script, "port": port, "time": now.isoformat(timespec="seconds"),
              "ntp_synchronized": ntp_synced(), "script_md5": md5(script) if script.endswith(".py") else None,
              "result": result}
    with open(path, "w") as f:
        json.dump(record, f, indent=1)
    return path
