import argparse
import json
import os
import subprocess
import sys

STATE_DIR = "/run/analyzer"
SYSFS = "/sys/class/net/%s/%s"
COUNTERS = ("rx_errors", "tx_errors", "rx_crc_errors", "rx_frame_errors", "rx_length_errors",
            "rx_over_errors", "rx_dropped", "tx_dropped", "collisions")


def run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def sysfs(iface, name):
    try:
        with open(SYSFS % (iface, name)) as f:
            return f.read().strip()
    except OSError:
        return None


def number(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def mode(name):
    """1000baseT/Full -> (1000, "Full")"""
    speed, _, duplex = name.partition("/")
    digits = "".join(ch for ch in speed.split("base")[0] if ch.isdigit())
    return (int(digits), duplex) if digits else None


def short_modes(names):
    modes = sorted({m for m in map(mode, names) if m}, key=lambda m: (-m[0], m[1] != "Full"))
    return " ".join("%d%s" % (s, d[:1]) for s, d in modes)


def best_common(ours, theirs):
    common = {m for m in map(mode, ours) if m} & {m for m in map(mode, theirs) if m}
    if not common:
        return None
    return max(common, key=lambda m: (m[0], m[1] == "Full"))


def ethtool(iface):
    try:
        data = json.loads(run(["ethtool", "--json", iface]) or "[]")
        settings = data[0] if data else {}
    except ValueError:
        settings = {}
    info = dict(line.split(": ", 1) for line in run(["ethtool", "-i", iface]).splitlines() if ": " in line)
    stats = {}
    for line in run(["ethtool", "-S", iface]).splitlines():
        key, _, value = line.strip().partition(": ")
        if value.strip().isdigit():
            stats[key] = int(value)
    return settings, info, stats


def load_last(iface):
    try:
        with open(os.path.join(STATE_DIR, "port_%s.json" % iface)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def store(iface, counters):
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(os.path.join(STATE_DIR, "port_%s.json" % iface), "w") as f:
            json.dump(counters, f)
    except OSError:
        pass


def delta(now, last, key, wrap=None):
    if now.get(key) is None:
        return None
    before = last.get(key)
    if before is None:
        return 0
    d = now[key] - before
    if wrap and d < 0:
        d %= wrap
    return max(d, 0)


def verdict(r):
    if not r["present"]:
        return "FAIL", "adapter not plugged in"
    if not r["link"]:
        return "FAIL", "no link: cable unplugged or the other end is off"
    words = []
    level = "PASS"
    if r["duplex"] == "Half":
        level, words = "WARN", ["half duplex"]
    best = r.get("best_common")
    if best and r["speed"] and r["speed"] < best[0]:
        level = "WARN"
        words.append("both ends do %d Mb/s, link at %d: check the cable" % (best[0], r["speed"]))
    if r["autoneg"] and r["partner_autoneg"] is False:
        level = "WARN"
        words.append("other end has a fixed speed")
    if r["errors_new"] or r["missed_new"]:
        level = "WARN"
        words.append("%d new errors, %d missed" % (r["errors_new"] or 0, r["missed_new"] or 0))
    if not words:
        words = ["%s Mb/s %s duplex" % (r["speed"] or "?", (r["duplex"] or "?").lower())]
    return level, ", ".join(words)


def read(iface, keep=True):
    """keep: store the counters as the base for the next "new since last check"."""
    r = {"iface": iface, "present": os.path.exists(SYSFS % (iface, "")), "link": False, "speed": None,
         "duplex": None, "autoneg": None, "advertised": [], "partner": [], "partner_autoneg": None,
         "partner_pause": None, "best_common": None, "driver": None, "firmware": None, "bus": None,
         "mac": None, "mtu": None, "carrier_down_count": None, "drops_new": None, "counters": {},
         "errors_new": None, "missed_new": None}
    if not r["present"]:
        r["verdict"], r["short"] = verdict(r)
        return r

    settings, info, stats = ethtool(iface)
    r["link"] = bool(settings.get("link-detected", sysfs(iface, "carrier") == "1"))
    r["mac"] = sysfs(iface, "address")
    r["mtu"] = number(sysfs(iface, "mtu"))
    r["driver"], r["firmware"], r["bus"] = info.get("driver"), info.get("firmware-version"), info.get("bus-info")
    r["autoneg"] = settings.get("auto-negotiation")
    r["advertised"] = settings.get("advertised-link-modes", [])
    if r["link"]:
        speed = settings.get("speed")
        r["speed"] = speed if isinstance(speed, int) and speed > 0 else None
        r["duplex"] = settings.get("duplex") if settings.get("duplex") in ("Full", "Half") else None
        r["partner"] = settings.get("link-partner-advertised-link-modes", [])
        r["partner_autoneg"] = settings.get("link-partner-advertised-auto-negotiation")
        r["partner_pause"] = settings.get("link-partner-advertised-pause-frame-use")
        best = best_common(r["advertised"], r["partner"])
        r["best_common"] = list(best) if best else None

    counters = {k: number(sysfs(iface, "statistics/" + k)) for k in COUNTERS}
    counters["rx_missed"] = stats.get("rx_missed")
    counters["align_errors"] = stats.get("align_errors")
    counters["carrier_down_count"] = number(sysfs(iface, "carrier_down_count"))
    r["counters"] = counters
    r["carrier_down_count"] = counters["carrier_down_count"]
    last = load_last(iface)
    r["drops_new"] = delta(counters, last, "carrier_down_count")
    new_errors = [delta(counters, last, k) for k in ("rx_errors", "tx_errors", "align_errors")]
    r["errors_new"] = sum(d for d in new_errors if d)
    # r8152 keeps rx_missed in 16 bits
    r["missed_new"] = delta(counters, last, "rx_missed", wrap=65536)
    if keep:
        store(iface, counters)
    r["verdict"], r["short"] = verdict(r)
    return r


def main():
    ap = argparse.ArgumentParser(description="Link diagnostics of a test port (reads the adapter, sends nothing)")
    ap.add_argument("iface")
    args = ap.parse_args()
    r = read(args.iface)
    if not r["present"]:
        print("%s: no such interface in this namespace" % args.iface)
        print("RESULT port_info " + json.dumps(r))
        return 2
    print("Port      : %s (%s, %s, firmware %s)" % (r["iface"], r["mac"], r["driver"], r["firmware"]))
    if r["link"]:
        print("Link      : up, %s Mb/s, %s duplex, autoneg %s" % (r["speed"], r["duplex"], "on" if r["autoneg"] else "off"))
        print("This port : %s" % short_modes(r["advertised"]))
        print("Partner   : %s%s" % (short_modes(r["partner"]) or "nothing advertised",
                                    "" if r["partner_autoneg"] else " (no autonegotiation)"))
    else:
        print("Link      : down")
    print("Link drops: %s new, %s since boot" % (r["drops_new"], r["carrier_down_count"]))
    print("Errors    : %s new, missed %s new" % (r["errors_new"], r["missed_new"]))
    print("Verdict   : %s %s" % (r["verdict"], r["short"]))
    print("RESULT port_info " + json.dumps(r))
    return 0 if r["link"] else 2


if __name__ == "__main__":
    sys.exit(main())
