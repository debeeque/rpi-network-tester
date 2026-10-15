import argparse
import ipaddress
import os
import subprocess
import sys
import time

from scapy.layers.inet6 import ICMPv6EchoReply, ICMPv6EchoRequest, IPv6
from scapy.layers.l2 import Ether
from scapy.sendrecv import AsyncSniffer, sendp

from ra_audit import iface_mac, link_local, local_macs

ALL_NODES = "ff02::1"
ALL_NODES_MAC = "33:33:00:00:00:01"


def eui64(mac):
    b = [int(part, 16) for part in mac.split(":")]
    return "%02x%02x:%02xff:fe%02x:%02x%02x" % (b[0] ^ 0x02, b[1], b[2], b[3], b[4], b[5])


def global_prefixes(name):
    static, dynamic = [], []
    cmd = ["ip", "-6", "addr", "show", "dev", name, "scope", "global"]
    res = subprocess.run(cmd, capture_output=True, text=True)
    for line in res.stdout.splitlines():
        parts = line.split()
        if not parts or parts[0] != "inet6":
            continue
        net = ipaddress.IPv6Network(parts[1], strict=False)
        bucket = dynamic if "dynamic" in parts or "mngtmpaddr" in parts else static
        if net not in bucket:
            bucket.append(net)
    return static + [net for net in dynamic if net not in static]


def compose(net, iid):
    base = int(net.network_address)
    host = int(ipaddress.IPv6Address("::" + iid))
    return str(ipaddress.IPv6Address(base | host))


def reachable(addr, name):
    cmd = ["ping6", "-c", "1", "-W", "1", "-I", name, addr]
    return subprocess.run(cmd, capture_output=True).returncode == 0


def neigh_table(name):
    table = {}
    cmd = ["ip", "-6", "neigh", "show", "dev", name]
    res = subprocess.run(cmd, capture_output=True, text=True)
    for line in res.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1] == "lladdr":
            table.setdefault(parts[2].lower(), []).append(parts[0])
    return table


def probe(name, count, timeout):
    sniffer = AsyncSniffer(
        iface=name,
        filter="icmp6",
        lfilter=lambda p: ICMPv6EchoReply in p,
        store=True,
    )
    sniffer.start()
    time.sleep(0.3)

    src = link_local(name)
    echo = (Ether(dst=ALL_NODES_MAC) /
            IPv6(src=src or "::", dst=ALL_NODES, hlim=255) /
            ICMPv6EchoRequest(id=os.getpid() & 0xFFFF))
    for _ in range(count):
        sendp(echo, iface=name, verbose=0)
        time.sleep(0.3)

    time.sleep(timeout)
    sniffer.stop()

    nodes = {}
    for pkt in sniffer.results or []:
        mac = pkt[Ether].src.lower()
        nodes.setdefault(mac, set()).add(pkt[IPv6].src)
    return nodes


def report(name, nodes, own, prefixes, verify):
    local = iface_mac(name)
    table = neigh_table(name)
    for mac in table:
        nodes.setdefault(mac, set())

    peers = [mac for mac in nodes if mac != local]
    print("Neighbours   : %d" % len(peers))
    if not peers:
        print("")
        print("No neighbour answered on %s." % name)
        return None

    target = None
    for index, mac in enumerate(sorted(peers), 1):
        kind = "OWN DEVICE" if mac in own else "FOREIGN"
        iid = eui64(mac)
        seen = set(nodes[mac]) | set(table.get(mac, []))
        link = sorted(a for a in seen if a.lower().startswith("fe80"))

        print("")
        print("--- Neighbour %d [%s] ---" % (index, kind))
        print("MAC          : %s" % mac)
        print("Link-local   : %s" % (", ".join(link) if link else "unknown"))
        print("IID from MAC : %s" % iid)

        expected = str(ipaddress.IPv6Address("fe80::" + iid))
        if link and expected in link:
            print("Addressing   : EUI-64, link-local matches the MAC")
        elif link:
            print("Addressing   : opaque identifier, link-local not derived from MAC (RFC 7217)")

        for net in prefixes:
            candidate = compose(net, iid)
            if not verify:
                state = "not verified"
            elif reachable(candidate, name):
                state = "reachable"
                if target is None:
                    target = candidate
            else:
                state = "no answer"
            print("SLAAC in %-12s: %s  (%s)" % (str(net), candidate, state))

        extra = sorted(a for a in seen if not a.lower().startswith("fe80"))
        for addr in extra:
            print("Also known   : %s  (neighbour table)" % addr)
            if target is None:
                target = addr

    return target


def main():
    parser = argparse.ArgumentParser(description="IPv6 neighbour enumeration")
    parser.add_argument("iface")
    parser.add_argument("-c", "--count", type=int, default=3)
    parser.add_argument("-t", "--timeout", type=int, default=2)
    parser.add_argument("--own", default="")
    parser.add_argument("--no-verify", action="store_true")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("Error: root privileges required")
        return 1
    if not os.path.exists("/sys/class/net/%s" % args.iface):
        print("Error: interface %s not found in this namespace" % args.iface)
        return 1

    own = local_macs()
    for mac in args.own.split(","):
        mac = mac.strip().lower()
        if mac:
            own.add(mac)

    prefixes = global_prefixes(args.iface)

    print("=== IPv6 neighbour enumeration ===")
    print("Interface    : %s (%s)" % (args.iface, iface_mac(args.iface)))
    print("Link-local   : %s" % (link_local(args.iface) or "none"))
    print("Prefixes     : %s" % (", ".join(str(p) for p in prefixes) or "none"))
    print("Probe        : %d echo requests to %s" % (args.count, ALL_NODES))

    nodes = probe(args.iface, args.count, args.timeout)
    target = report(args.iface, nodes, own, prefixes, not args.no_verify)

    print("")
    print("TARGET6      : %s" % (target or "none"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
