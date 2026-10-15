import argparse
import ipaddress
import os
import sys
import time

from scapy.layers.inet6 import (
    ICMPv6ND_RA,
    ICMPv6ND_RS,
    ICMPv6NDOptDNSSL,
    ICMPv6NDOptMTU,
    ICMPv6NDOptPrefixInfo,
    ICMPv6NDOptRDNSS,
    ICMPv6NDOptSrcLLAddr,
    IPv6,
)
from scapy.layers.l2 import Ether
from scapy.packet import NoPayload
from scapy.sendrecv import AsyncSniffer, sendp

INFINITE = 0xFFFFFFFF
ALL_ROUTERS = "ff02::2"
ALL_ROUTERS_MAC = "33:33:00:00:00:02"
PREFERENCE = {0: "Medium", 1: "High", 2: "Reserved", 3: "Low"}


def iface_mac(name):
    try:
        with open("/sys/class/net/%s/address" % name) as fd:
            return fd.read().strip().lower()
    except OSError:
        return None


def local_macs():
    macs = set()
    try:
        names = os.listdir("/sys/class/net")
    except OSError:
        return macs
    for name in names:
        mac = iface_mac(name)
        if mac and mac != "00:00:00:00:00:00":
            macs.add(mac)
    return macs


def link_local(name):
    try:
        fd = open("/proc/net/if_inet6")
    except OSError:
        return None
    with fd:
        for line in fd:
            parts = line.split()
            if len(parts) >= 6 and parts[5] == name and parts[3] == "20":
                raw = parts[0]
                grouped = ":".join(raw[i:i + 4] for i in range(0, 32, 4))
                return str(ipaddress.IPv6Address(grouped))
    return None


def options(ra):
    layer = ra.payload
    while not isinstance(layer, NoPayload):
        yield layer
        layer = layer.payload


def lifetime(value):
    if value == INFINITE:
        return "infinite"
    return "%d s" % value


def solicit(name):
    src = link_local(name)
    mac = iface_mac(name)
    pkt = Ether(dst=ALL_ROUTERS_MAC) / IPv6(src=src or "::", dst=ALL_ROUTERS, hlim=255) / ICMPv6ND_RS()
    if src and mac:
        pkt = pkt / ICMPv6NDOptSrcLLAddr(lladdr=mac)
    sendp(pkt, iface=name, verbose=0)
    return src or "::"


def collect(name, seconds, send_rs):
    sniffer = AsyncSniffer(
        iface=name,
        filter="icmp6",
        lfilter=lambda p: ICMPv6ND_RA in p,
        store=True,
    )
    sniffer.start()
    time.sleep(0.3)
    if send_rs:
        print("Solicitation : sent to %s from %s" % (ALL_ROUTERS, solicit(name)))
    else:
        print("Solicitation : skipped, passive listening")
    time.sleep(seconds)
    sniffer.stop()
    return sniffer.results or []


def group(packets):
    routers = {}
    order = []
    for pkt in packets:
        key = (pkt[Ether].src.lower(), pkt[IPv6].src)
        if key not in routers:
            routers[key] = [0, pkt]
            order.append(key)
        routers[key][0] += 1
    return [(key, routers[key][0], routers[key][1]) for key in order]


def origin(eth_src, own, local):
    if eth_src == local:
        return "LOCAL TX"
    if eth_src in own:
        return "OWN DEVICE"
    return "FOREIGN"


def audit(pkt, own, local):
    notes = []
    eth_src = pkt[Ether].src.lower()
    ip6 = pkt[IPv6]
    ra = pkt[ICMPv6ND_RA]

    kind = origin(eth_src, own, local)
    if kind == "LOCAL TX":
        notes.append(("OK", "sent by this interface, own configuration check"))
    elif kind == "OWN DEVICE":
        notes.append(("OK", "another port of this device, received over the wire"))
    else:
        notes.append(("ALERT", "router is not this device, possible rogue RA"))

    if ip6.hlim != 255:
        notes.append(("ALERT", "hop limit %d, RFC 4861 requires 255" % ip6.hlim))
    if not ip6.src.lower().startswith("fe80"):
        notes.append(("WARN", "source %s is not link-local, RFC 4861" % ip6.src))
    if ra.routerlifetime == 0:
        notes.append(("INFO" if kind != "FOREIGN" else "WARN", "router lifetime 0, prefixes only, not a default router"))

    lladdr = None
    prefixes = []
    for opt in options(ra):
        if isinstance(opt, ICMPv6NDOptSrcLLAddr):
            lladdr = opt.lladdr.lower()
        elif isinstance(opt, ICMPv6NDOptPrefixInfo):
            prefixes.append(opt)
        elif isinstance(opt, ICMPv6NDOptMTU) and opt.mtu < 1280:
            notes.append(("ALERT", "MTU %d below IPv6 minimum 1280" % opt.mtu))

    if lladdr and lladdr != eth_src:
        notes.append(("ALERT", "frame MAC %s differs from option %s" % (eth_src, lladdr)))

    autoconf = False
    for opt in prefixes:
        name = "%s/%d" % (opt.prefix, opt.prefixlen)
        if opt.A:
            autoconf = True
            if opt.prefixlen != 64:
                notes.append(("ALERT", "%s: A flag set but length is not 64, RFC 4862" % name))
        else:
            notes.append(("WARN", "%s: A flag clear, SLAAC disabled" % name))
        if opt.preferredlifetime > opt.validlifetime:
            notes.append(("ALERT", "%s: preferred lifetime above valid, RFC 4861" % name))
        if opt.prefix.lower().startswith("fe80"):
            notes.append(("WARN", "%s: link-local prefix advertised" % name))

    if not prefixes:
        notes.append(("WARN", "no prefix information option, no global address for hosts"))
    if ra.M and autoconf:
        notes.append(("WARN", "M flag set together with A flag, mixed DHCPv6 and SLAAC"))
    if ra.M == 0 and ra.O == 0 and not autoconf:
        notes.append(("ALERT", "no autoconfiguration source announced"))

    return notes


def report(name, seconds, packets, own):
    local = iface_mac(name)
    found = group(packets)
    print("Routers      : %d" % len(found))
    if not found:
        print("")
        print("No Router Advertisement received on %s in %d s." % (name, seconds))
        print("Either no router is present or RA is filtered on this segment.")
        return

    for index, (key, count, pkt) in enumerate(found, 1):
        eth_src, ip_src = key
        ra = pkt[ICMPv6ND_RA]

        print("")
        print("--- Router %d [%s] ---" % (index, origin(eth_src, own, local)))
        print("Source       : %s" % ip_src)
        print("Source MAC   : %s" % eth_src)
        print("RA received  : %d" % count)
        print("Cur hop limit: %d" % ra.chlim)
        print("Flags        : M=%d O=%d   preference=%s" % (ra.M, ra.O, PREFERENCE.get(ra.prf, "?")))
        print("Router life  : %s" % lifetime(ra.routerlifetime))
        print("Reachable    : %d ms   Retrans: %d ms" % (ra.reachabletime, ra.retranstimer))

        for opt in options(ra):
            if isinstance(opt, ICMPv6NDOptPrefixInfo):
                print("Prefix       : %s/%d   L=%d A=%d R=%d" % (opt.prefix, opt.prefixlen, opt.L, opt.A, opt.R))
                print("               valid %s, preferred %s"
                      % (lifetime(opt.validlifetime), lifetime(opt.preferredlifetime)))
            elif isinstance(opt, ICMPv6NDOptMTU):
                print("MTU          : %d" % opt.mtu)
            elif isinstance(opt, ICMPv6NDOptRDNSS):
                print("RDNSS        : %s   lifetime %s" % (", ".join(opt.dns), lifetime(opt.lifetime)))
            elif isinstance(opt, ICMPv6NDOptDNSSL):
                names = [str(entry) for entry in opt.searchlist]
                print("DNSSL        : %s   lifetime %s" % (", ".join(names), lifetime(opt.lifetime)))
            elif isinstance(opt, ICMPv6NDOptSrcLLAddr):
                print("Src LL addr  : %s" % opt.lladdr)

        print("Audit:")
        for level, text in audit(pkt, own, local):
            print("  [%-5s] %s" % (level, text))

    remote = [key for key, _, _ in found if key[0] != local]
    foreign = [key for key in remote if key[0] not in own]
    print("")
    print("--- Segment summary ---")
    print("Sent by this port : %d" % (len(found) - len(remote)))
    print("Heard on the wire : %d, of them foreign %d" % (len(remote), len(foreign)))
    if len(remote) > 1:
        print("  [WARN ] more than one router advertises on %s" % name)
    for mac, ip_src in foreign:
        print("  [ALERT] unknown router %s at %s" % (ip_src, mac))
    if not remote:
        print("  [INFO ] no advertisement received from the segment")


def main():
    parser = argparse.ArgumentParser(description="IPv6 Router Advertisement audit")
    parser.add_argument("iface")
    parser.add_argument("-t", "--timeout", type=int, default=5)
    parser.add_argument("--own", default="")
    parser.add_argument("--passive", action="store_true")
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

    print("=== IPv6 Router Advertisement audit ===")
    print("Interface    : %s (%s)" % (args.iface, iface_mac(args.iface)))
    print("Link-local   : %s" % (link_local(args.iface) or "none"))
    print("Own MACs     : %s" % ", ".join(sorted(own)))

    packets = collect(args.iface, args.timeout, not args.passive)
    report(args.iface, args.timeout, packets, own)
    return 0


if __name__ == "__main__":
    sys.exit(main())
