import ipaddress
import json
import os
import re
import subprocess
import time

RUN = "/run/analyzer"
PORTS_JSON = os.path.join(RUN, "ports.json")
# Addresses of the test bench; anything else needs confirmation (RFC 6815)
STAND = [ipaddress.ip_network(n) for n in ("10.0.1.0/24", "10.0.2.0/24", "fd00:1::/64", "fd00:2::/64",
                                          "fe80::/10")]


def sh(cmd, timeout=10):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def bare(addr):
    return addr.split("%")[0]


def scoped(addr, iface):
    addr = bare(addr)
    return "%s%%%s" % (addr, iface) if addr.lower().startswith("fe80") else addr


def in_stand(addr):
    try:
        ip = ipaddress.ip_address(bare(addr))
    except ValueError:
        return False
    return any(ip in net for net in STAND)


def carrier(iface):
    try:
        with open("/sys/class/net/%s/carrier" % iface) as f:
            return f.read().strip() == "1"
    except OSError:
        return False


def device_ports():
    try:
        with open(PORTS_JSON) as f:
            return {n: p for n, p in json.load(f).get("ports", {}).items() if p.get("mac")}
    except (OSError, ValueError):
        return {}


def own_port(mac):
    for name, p in device_ports().items():
        if mac and p["mac"].lower() == mac.lower():
            return name
    return None


def own_nets(iface, family):
    nets = []
    try:
        info = json.loads(sh(["ip", "-j", "-%d" % family, "addr", "show", "dev", iface]) or "[]")
    except ValueError:
        return nets
    for dev in info:
        for a in dev.get("addr_info", []):
            nets.append(ipaddress.ip_interface("%s/%s" % (a["local"], a["prefixlen"])))
    return nets


def neighbours(iface, family):
    try:
        rows = json.loads(sh(["ip", "-j", "-%d" % family, "neigh", "show", "dev", iface]) or "[]")
    except ValueError:
        return []
    return [(r["dst"], r["lladdr"].lower()) for r in rows
            if r.get("lladdr") and not set(r.get("state", [])) & {"FAILED", "INCOMPLETE"}]


def mac_of(iface, family, addr):
    for dst, mac in neighbours(iface, family):
        if dst == bare(addr):
            return mac
    return None


def dhcp_on(iface):
    try:
        with open(os.path.join(RUN, "dnsmasq_%s.pid" % iface)) as f:
            os.kill(int(f.read().strip()), 0)
        return True
    except (OSError, ValueError):
        return False


# dnsmasq lease file: v4 "expiry mac ip host clientid", v6 "expiry iaid ip host duid"
def leases(iface, family):
    found = []
    try:
        with open(os.path.join(RUN, "dnsmasq_%s.leases" % iface)) as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[0] != "duid" and (":" in parts[2]) == (family == 6) and                         (parts[0] == "0" or int(parts[0]) > time.time()):
                    found.append((parts[2], parts[3] if parts[3] != "*" else ""))
    except OSError:
        pass
    return found


def ping_once(addr, family, iface):
    cmd = ["ping", "-%d" % family, "-n", "-c", "1", "-W", "1", scoped(addr, iface)]
    return subprocess.run(cmd, capture_output=True).returncode == 0


# A lease or a cached neighbour may be hours old: resolve the address afresh; a host that blocks ping
# still answers ARP or ND, which leaves the entry REACHABLE
def alive(addr, family, iface):
    subprocess.run(["ip", "-%d" % family, "neigh", "del", bare(addr), "dev", iface], capture_output=True)
    if ping_once(addr, family, iface):
        return True
    try:
        rows = json.loads(sh(["ip", "-j", "-%d" % family, "neigh", "show", "dev", iface]) or "[]")
    except ValueError:
        return False
    return any(r.get("dst") == bare(addr) and "REACHABLE" in r.get("state", []) for r in rows)


# One echo request to all nodes; replies come from link-local addresses
def probe6(iface, secs=1):
    out = sh(["ping", "-6", "-n", "-i", "0.3", "-w", str(secs), "ff02::1%" + iface], timeout=secs + 5)
    own = {str(n.ip) for n in own_nets(iface, 6)}
    seen = []
    for addr in re.findall(r"from ([0-9a-f:]+)%", out):
        if addr not in own and addr not in seen:
            seen.append(addr)
    return seen


def peer_text(port, mac):
    if port:
        return "%s of this device (loop)" % port
    return "host %s" % mac if mac else "host"


def resolve(iface, family, given=None):
    """Pick the address to test; say where it came from and, if none, why."""
    res = {"family": "v%d" % family, "iface": iface, "target": None, "source": None, "peer": None}
    if not carrier(iface):
        res.update(short="no link on %s" % iface, reason="no link on %s" % iface,
                   hint="check the cable and that the other end is powered")
        return res
    if given:
        mac = mac_of(iface, family, given)
        res.update(target=scoped(given, iface), source="given", mac=mac, peer=peer_text(own_port(mac), mac))
        return res

    nets = [n.network for n in own_nets(iface, family) if not n.ip.is_link_local]
    own = {str(n.ip) for n in own_nets(iface, family)}

    def ours(addr):
        ip = ipaddress.ip_address(bare(addr))
        return str(ip) not in own and any(ip in n for n in nets)

    for addr, host in leases(iface, family):
        if ours(addr) and alive(addr, family, iface):
            mac = mac_of(iface, family, addr)
            res.update(target=addr, source="DHCP lease" + (" of " + host if host else ""), mac=mac,
                       peer=host or peer_text(own_port(mac), mac))
            return res
    for addr, mac in neighbours(iface, family):
        if not addr.lower().startswith("fe80") and ours(addr) and alive(addr, family, iface):
            mac = mac_of(iface, family, addr) or mac
            res.update(target=addr, source="neighbour table", mac=mac, peer=peer_text(own_port(mac), mac))
            return res

    peers = []
    # Windows ignores an echo to ff02::1: fall back to link-local neighbours the kernel has already seen
    own6 = {str(n.ip) for n in own_nets(iface, 6)}
    heard = probe6(iface) or [a for a, m in neighbours(iface, 6) if a.startswith("fe80") and a not in own6]
    for addr in heard:
        if alive(addr, 6, iface):
            mac = mac_of(iface, 6, addr)
            peers.append((addr, mac, own_port(mac)))
    if family == 6 and peers:
        addr, mac, port = peers[0]
        res.update(target=scoped(addr, iface), source="neighbour answered on the cable", mac=mac,
                   peer=peer_text(port, mac))
        return res

    loop = next((p[2] for p in peers if p[2]), None)
    if family == 4 and loop:
        res.update(short="loop to %s: no IPv4 host, use v6" % loop,
                   reason="%s is cabled to %s of this device; the ports are in different IPv4 networks"
                          " and nothing routes between them" % (iface, loop),
                   hint="on the loop use IPv6; IPv4 needs a host that takes an address from DHCP")
    elif family == 4 and dhcp_on(iface):
        res.update(short="no host took a DHCP address", reason="no host took an IPv4 address from DHCP on %s" % iface,
                   hint="set the host's adapter to obtain an address automatically")
    elif family == 4:
        res.update(short="no IPv4 host known, DHCP is off", reason="no IPv4 host known on %s and DHCP/RA is off" % iface,
                   hint="turn DHCP / RA on, or find hosts with SCAN > ARP")
    else:
        res.update(short="no IPv6 neighbour answered", reason="no IPv6 neighbour answered on %s" % iface,
                   hint="the other end may have IPv6 turned off")
    return res
