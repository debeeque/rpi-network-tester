import argparse
import ipaddress
import json
import os
import random
import resource
import signal
import socket
import subprocess
import sys
import time

BENCH = [ipaddress.ip_network(n) for n in ("10.0.1.0/24", "10.0.2.0/24", "fd00:1::/64", "fd00:2::/64",
                                             "fe80::/10", "ff02::/16")]
PROTOS = ("icmp", "icmp6", "udp", "tcp-syn", "arp", "rs")
SIZED = ("icmp", "icmp6", "udp")
MAX_DISTINCT = 4096


def result(data):
    print("RESULT pkt_gen " + json.dumps(data, separators=(",", ":")), flush=True)


def iface_mac(name):
    with open("/sys/class/net/%s/address" % name) as f:
        return f.read().strip()


def iface_addr(name, family, link_local):
    r = subprocess.run(["ip", "-j", "-%d" % family, "addr", "show", "dev", name], capture_output=True, text=True)
    for info in json.loads(r.stdout or "[]"):
        for a in info.get("addr_info", []):
            ll = a["local"].startswith("fe80")
            if family == 4 or ll == link_local:
                return a["local"]
    return None


def multicast_mac(dst):
    if dst.version == 6 and dst.is_multicast:
        return "33:33:" + ":".join("%02x" % b for b in dst.packed[-4:])
    if dst.version == 4 and dst == ipaddress.ip_address("255.255.255.255"):
        return "ff:ff:ff:ff:ff:ff"
    if dst.version == 4 and dst.is_multicast:
        b = dst.packed
        return "01:00:5e:%02x:%02x:%02x" % (b[1] & 0x7F, b[2], b[3])
    return None


def resolve_mac(dst, src, iface):
    from scapy.all import ARP, Ether, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr, IPv6, srp1
    mac = iface_mac(iface)
    if dst.version == 4:
        q = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac) / ARP(op=1, hwsrc=mac, psrc=src, pdst=str(dst))
        a = srp1(q, iface=iface, timeout=1, retry=1, verbose=0)
        return a[ARP].hwsrc if a is not None else None
    solicited = ipaddress.ip_address("ff02::1:ff00:0").packed[:13] + dst.packed[13:]
    group = ipaddress.ip_address(solicited)
    q = (Ether(dst=multicast_mac(group), src=mac) / IPv6(src=src, dst=str(group), hlim=255) /
         ICMPv6ND_NS(tgt=str(dst)) / ICMPv6NDOptSrcLLAddr(lladdr=mac))
    a = srp1(q, iface=iface, timeout=1, retry=1, verbose=0)
    return a.src if a is not None else None


def build(args, src, dst, src_mac, dst_mac):
    from scapy.all import ARP, Ether, ICMP, ICMPv6EchoRequest, ICMPv6ND_RS, ICMPv6NDOptSrcLLAddr, IP, IPv6, Raw, TCP, UDP
    eth = Ether(src=src_mac, dst=dst_mac)
    ip = (IP(src=src, dst=str(dst)) if dst.version == 4 else IPv6(src=src, dst=str(dst))) if dst else None
    ident = os.getpid() & 0xFFFF
    sport = random.randint(49152, 65535)

    def one(i):
        if args.proto == "icmp":
            return eth / ip / ICMP(id=ident, seq=i & 0xFFFF)
        if args.proto == "icmp6":
            return eth / ip / ICMPv6EchoRequest(id=ident, seq=i & 0xFFFF)
        if args.proto == "udp":
            return eth / ip / UDP(sport=sport, dport=args.dport)
        if args.proto == "tcp-syn":
            return eth / ip / TCP(sport=49152 + i % 16384, dport=args.dport, flags="S", seq=random.getrandbits(32))
        if args.proto == "arp":
            return Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=src_mac, psrc=src, pdst=str(dst))
        return (Ether(src=src_mac, dst="33:33:00:00:00:02") / IPv6(src=src, dst="ff02::2", hlim=255) /
                ICMPv6ND_RS() / ICMPv6NDOptSrcLLAddr(lladdr=src_mac))

    header = len(bytes(one(0)))
    pad = max(0, args.size - header) if args.proto in SIZED and args.size else 0
    frames = []
    for i in range(min(args.count, MAX_DISTINCT) if args.count else MAX_DISTINCT):
        p = one(i)
        if pad:
            p = p / Raw(b"\x00" * pad)
        frames.append(bytes(p))
    return frames, header


def main():
    p = argparse.ArgumentParser(description="Packet generator for the test ports")
    p.add_argument("iface")
    p.add_argument("--proto", choices=PROTOS, required=True)
    p.add_argument("--dst", help="target address; for rs the all-routers group is used")
    p.add_argument("--dst-mac")
    p.add_argument("--count", type=int, default=100, help="0 = until stopped")
    p.add_argument("--rate", type=float, default=10, help="packets per second, 0 = as fast as possible")
    p.add_argument("--size", type=int, default=0, help="frame length without FCS, icmp/icmp6/udp only")
    p.add_argument("--dport", type=int, default=9)
    p.add_argument("--force", action="store_true", help="allow a target outside the test bench")
    args = p.parse_args()

    base = {"iface": args.iface, "proto": args.proto, "dst": args.dst, "count": args.count, "rate_req": args.rate}
    if os.geteuid() != 0:
        print("Error: root privileges required")
        result(dict(base, error="not root"))
        return 1
    if not os.path.exists("/sys/class/net/%s" % args.iface):
        print("Error: interface %s not found in this namespace" % args.iface)
        result(dict(base, error="no interface"))
        return 2

    if args.proto == "rs":
        args.dst = "ff02::2"
    if not args.dst:
        print("Error: --dst is required for %s" % args.proto)
        result(dict(base, error="no destination"))
        return 1
    dst = ipaddress.ip_address(args.dst.split("%")[0])
    if not any(dst in n for n in BENCH) and not args.force:
        print("Error: %s is outside the test bench; RFC 6815 forbids load tests on production networks. "
              "Use --force only with the network owner's consent." % dst)
        result(dict(base, error="outside bench"))
        return 1
    if args.proto in ("icmp", "arp") and dst.version != 4 or args.proto in ("icmp6", "rs") and dst.version != 6:
        print("Error: %s needs an IPv%d destination" % (args.proto, 4 if args.proto in ("icmp", "arp") else 6))
        result(dict(base, error="address family"))
        return 1

    t0 = time.monotonic()
    link_local = dst.version == 6 and (dst.is_link_local or dst.is_multicast)
    src = iface_addr(args.iface, dst.version, link_local)
    if src is None:
        print("Error: %s has no IPv%d address to send from" % (args.iface, dst.version))
        result(dict(base, error="no source address"))
        return 2
    src_mac = iface_mac(args.iface)
    dst_mac = args.dst_mac or multicast_mac(dst)
    if dst_mac is None and args.proto not in ("arp", "rs"):
        dst_mac = resolve_mac(dst, src, args.iface)
        if dst_mac is None:
            print("Error: no answer from %s on %s, give --dst-mac" % (dst, args.iface))
            result(dict(base, error="mac not resolved"))
            return 2
    frames, header = build(args, src, dst if args.proto != "rs" else None, src_mac, dst_mac)
    build_s = time.monotonic() - t0
    frame_len = len(frames[0])
    if args.proto in SIZED and args.size and args.size < header:
        print("Note: --size %d is below the header length, frames are %d B" % (args.size, frame_len))
    print("Sending      : %s from %s (%s) to %s (%s), %d B frames, %s pkt/s, count %s"
          % (args.proto, src, src_mac, dst, dst_mac or "broadcast", frame_len,
             args.rate or "max", args.count or "until stopped"), flush=True)

    stop = {"flag": False}
    signal.signal(signal.SIGTERM, lambda *_: stop.update(flag=True))
    signal.signal(signal.SIGINT, lambda *_: stop.update(flag=True))

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind((args.iface, 0))
    ru0 = resource.getrusage(resource.RUSAGE_SELF)
    sent = errors = 0
    n = len(frames)
    gap = 1.0 / args.rate if args.rate else 0
    start = time.perf_counter()
    next_report = start + 1
    while not stop["flag"] and (not args.count or sent < args.count):
        if gap:
            due = start + sent * gap
            now = time.perf_counter()
            if due > now:
                time.sleep(due - now)
        try:
            sock.send(frames[sent % n])
            sent += 1
        except OSError:
            errors += 1
            time.sleep(0.001)
        now = time.perf_counter()
        if now >= next_report:
            print("PROGRESS %d %s %.1f" % (sent, args.count or "-", now - start), flush=True)
            next_report += 1
    duration = time.perf_counter() - start
    ru1 = resource.getrusage(resource.RUSAGE_SELF)
    cpu = (ru1.ru_utime - ru0.ru_utime) + (ru1.ru_stime - ru0.ru_stime)
    sock.close()

    print("Sent         : %d frames in %.2f s, %d send errors" % (sent, duration, errors))
    result(dict(base, src=src, src_mac=src_mac, dst_mac=dst_mac, sent=sent, errors=errors,
                rate_real=round(sent / duration) if duration else 0, frame_len=frame_len,
                header_len=header, distinct=n, duration_s=round(duration, 2), build_s=round(build_s, 2),
                cpu_pct=round(100 * cpu / duration, 1) if duration >= 1 else None, aborted=stop["flag"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
