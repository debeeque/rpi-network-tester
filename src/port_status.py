import json
import os
import subprocess
import sys
import threading
import time

PORTS = {"mon0": "analyzer_monitor", "snd0": "analyzer_sender"}
# The adapters with the MAC stickers always take their own port; any other USB adapter takes a free one
KNOWN = {"mon0": "00:e0:4c:68:02:01", "snd0": "00:e0:4c:68:02:23"}
SETUP = "/home/muk0015/diploma_project/setup_network.sh"
GRACE_S = 30
VACANT_S = 3
RUN = "/run/analyzer"
OUT = os.path.join(RUN, "ports.json")
DHCP_FLAG = os.path.join(RUN, "dhcp")
REFRESH_S = 10

changed = threading.Event()


def run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=5)
    except subprocess.SubprocessError:
        return None


def serving(dev):
    try:
        with open(os.path.join(RUN, "dnsmasq_%s.pid" % dev)) as f:
            os.kill(int(f.read().strip()), 0)
        return True
    except (OSError, ValueError):
        return False


def read_port(dev, ns):
    state = {"ns": ns, "present": False, "dhcp": serving(dev)}
    if not os.path.exists("/run/netns/" + ns):
        return state
    r = run(["ip", "-n", ns, "-j", "addr", "show", "dev", dev])
    if r is None or r.returncode != 0 or not r.stdout.strip():
        return state
    info = json.loads(r.stdout)[0]
    flags = info.get("flags", [])
    state.update(present=True, mac=info.get("address"), up="UP" in flags,
                 carrier="LOWER_UP" in flags, speed=None, duplex=None,
                 addr4=[], addr6=[])
    for a in info.get("addr_info", []):
        key = "addr4" if a.get("family") == "inet" else "addr6"
        state[key].append("%s/%s" % (a["local"], a["prefixlen"]))
    if state["carrier"]:
        base = "/sys/class/net/%s/" % dev
        r = run(["ip", "netns", "exec", ns, "cat", base + "speed", base + "duplex"])
        if r is not None and r.returncode == 0:
            lines = r.stdout.split()
            if len(lines) == 2 and lines[0].isdigit():
                state["speed"], state["duplex"] = int(lines[0]), lines[1]
    return state


def sysread(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return None


# USB Ethernet adapters in the default namespace, i.e. not in use as a test port
def spares():
    out = {}
    for name in os.listdir("/sys/class/net"):
        base = "/sys/class/net/" + name
        if "/usb" not in os.path.realpath(base + "/device") or os.path.exists(base + "/wireless"):
            continue
        driver = os.path.basename(os.path.realpath(base + "/device/driver"))
        if driver == "lan78xx" or sysread(base + "/type") != "1":
            continue
        out[name] = {"name": name, "mac": sysread(base + "/address"), "driver": driver}
    return out


def uptime():
    try:
        return float(sysread("/proc/uptime").split()[0])
    except (AttributeError, ValueError):
        return 0.0


vacant = {}


def log(text):
    print(time.strftime("%H:%M:%S"), text, flush=True)


def assign(data):
    if uptime() < GRACE_S:
        return False
    acted = False
    now = time.monotonic()
    free = spares()
    for dev, ns in PORTS.items():
        held = data["ports"].get(dev, {}).get("mac") if data["ports"].get(dev, {}).get("present") else None
        own = next((n for n, a in free.items() if a["mac"] == KNOWN[dev]), None)
        if held and held != KNOWN[dev] and own:
            spare = "usb" + held.replace(":", "")[-4:]
            run(["ip", "-n", ns, "link", "set", dev, "down"])
            run(["ip", "-n", ns, "link", "set", dev, "name", spare])
            run(["ip", "-n", ns, "link", "set", spare, "netns", "1"])
            log("%s: adapter %s is back, %s gives the port up as %s" % (dev, KNOWN[dev], held, spare))
            held, vacant[dev] = None, 0
        if held:
            vacant.pop(dev, None)
            continue
        since = vacant.setdefault(dev, now)
        if own:
            name = own
        elif dev in free and free[dev]["mac"] not in KNOWN.values():
            name = dev
        else:
            others = sorted(n for n, a in free.items() if a["mac"] not in KNOWN.values() and n not in PORTS)
            if not others:
                continue
            name = others[0]
        # analyzer-port@ sets up a freshly named adapter by itself; step in only if it did not
        if now - since < VACANT_S:
            continue
        if name != dev:
            run(["ip", "link", "set", name, "down"])
            run(["ip", "link", "set", name, "name", dev])
        r = run([SETUP, "port", dev])
        log("%s: adapter %s (%s) took the port: %s" % (dev, free[name]["mac"], name,
                                                       (r.stdout.strip() if r else "setup failed")))
        free = spares()
        vacant.pop(dev, None)
        acted = True
    return acted


def snapshot():
    data = {"time": time.time(), "dhcp": os.path.exists(DHCP_FLAG), "ports": {}}
    for dev, ns in PORTS.items():
        data["ports"][dev] = read_port(dev, ns)
    data["spare"] = sorted(spares().values(), key=lambda a: a["name"])
    return data


def write(data):
    tmp = OUT + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f)
    os.replace(tmp, OUT)


# One `ip monitor` per namespace (None: the default one, where new adapters appear);
# it exits when the namespace is deleted
def watch(ns):
    while True:
        if ns and not os.path.exists("/run/netns/" + ns):
            time.sleep(1)
            continue
        try:
            proc = subprocess.Popen(["ip"] + (["-n", ns] if ns else []) + ["monitor", "link", "address"],
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        except OSError:
            time.sleep(5)
            continue
        changed.set()
        for _ in proc.stdout:
            changed.set()
        proc.wait()
        changed.set()
        time.sleep(1)


def main():
    os.makedirs(RUN, exist_ok=True)
    for ns in list(PORTS.values()) + [None]:
        threading.Thread(target=watch, args=(ns,), daemon=True).start()
    last, last_flag, last_t = None, None, 0
    data = snapshot()
    while True:
        fired = changed.wait(1)
        if assign(data):
            fired = True
        flag = os.path.exists(DHCP_FLAG)
        if not fired and flag == last_flag and time.monotonic() - last_t < REFRESH_S:
            continue
        changed.clear()
        time.sleep(0.2)
        last_flag, last_t = flag, time.monotonic()
        data = snapshot()
        key = json.dumps({k: v for k, v in data.items() if k != "time"}, sort_keys=True)
        if key != last:
            print(time.strftime("%H:%M:%S"), key, flush=True)
            last = key
        write(data)


if __name__ == "__main__":
    sys.exit(main())
