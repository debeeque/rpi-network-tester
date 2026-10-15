import argparse
import ipaddress
import json
import os
import random
import re
import signal
import socket
import subprocess
import sys
import time

import port_info
from ra_audit import audit, iface_mac, options, solicit
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import ICMPv6ND_RA, ICMPv6NDOptPrefixInfo, ICMPv6NDOptRDNSS, IPv6
from scapy.layers.l2 import Ether
from scapy.sendrecv import AsyncSniffer, sendp

PROFILE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "profiles")
STEPS = ("LINK", "DHCPv4", "IPv6", "GATEWAY", "DNS", "TARGETS")
PARAMS = [1, 3, 6, 15, 51, 54]
RCODES = {1: "format error", 2: "server failure", 3: "name not found", 4: "not implemented", 5: "refused"}

stop = {"flag": False}


def log(text):
    print(text, flush=True)


def run(cmd, timeout=10):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def wait(seconds, until=None):
    end = time.monotonic() + seconds
    while time.monotonic() < end and not stop["flag"]:
        if until and until():
            return
        time.sleep(0.05)


class Steps:
    def __init__(self):
        self.data = {}
        self.t = time.monotonic()

    def begin(self, name):
        self.t = time.monotonic()
        log("")
        log("== %s" % name)
        print("STEP " + json.dumps({"step": name, "verdict": "RUNNING", "line1": "", "line2": ""}), flush=True)

    def done(self, name, verdict, line1, line2="", **extra):
        item = {"step": name, "verdict": verdict, "line1": line1, "line2": line2,
                "ms": int((time.monotonic() - self.t) * 1000)}
        self.data[name] = dict(item, **extra)
        log("%s %s: %s%s" % (name, verdict, line1, " / " + line2 if line2 else ""))
        print("STEP " + json.dumps(item), flush=True)

    def skip(self, name, why):
        self.t = time.monotonic()
        self.done(name, "SKIP", why)


def dhcp_options(pkt):
    out = {}
    for opt in pkt[DHCP].options:
        if isinstance(opt, tuple) and len(opt) >= 2:
            out[opt[0]] = list(opt[1:])
    return out


def first(opts, key):
    values = opts.get(key)
    return values[0] if values else None


def dhcp_exchange(iface, mac, frame, xid, wait_s, enough=None):
    got = []
    sniffer = AsyncSniffer(iface=iface, filter="udp and (port 67 or port 68)", store=False,
                           prn=got.append, lfilter=lambda p: BOOTP in p and p[BOOTP].xid == xid)
    sniffer.start()
    time.sleep(0.3)
    sendp(frame, iface=iface, verbose=False)
    wait(wait_s, lambda: enough and enough(got))
    try:
        sniffer.stop()
    except Exception:
        pass
    sent = [p for p in got if p[Ether].src.lower() == mac]
    t0 = float(sent[0].time) if sent else None
    replies = []
    for p in got:
        if p[Ether].src.lower() == mac or DHCP not in p:
            continue
        opts = dhcp_options(p)
        replies.append((p, opts, int((float(p.time) - t0) * 1000) if t0 else None))
    return replies


def dhcp_frame(mac, xid, kind, extra=()):
    chaddr = bytes.fromhex(mac.replace(":", ""))
    opts = [("message-type", kind)] + list(extra) + [("param_req_list", PARAMS), "end"]
    return (Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) / BOOTP(chaddr=chaddr, xid=xid, flags=0x8000) / DHCP(options=opts))


def offer_info(pkt, opts, ms, own):
    src = pkt[Ether].src.lower()
    return {"server": first(opts, "server_id") or pkt[IP].src, "addr": pkt[BOOTP].yiaddr,
            "mask": first(opts, "subnet_mask"), "router": first(opts, "router"),
            "dns": opts.get("name_server", []), "lease_s": first(opts, "lease_time"),
            "relay": pkt[BOOTP].giaddr if pkt[BOOTP].giaddr != "0.0.0.0" else None,
            "mac": src, "origin": "THIS DEVICE" if src in own else "FOREIGN", "ms": ms}


def duration(seconds):
    if not seconds:
        return "?"
    if seconds >= 3600 and seconds % 3600 == 0:
        return "%d h" % (seconds // 3600)
    if seconds >= 60:
        return "%d min" % (seconds // 60)
    return "%d s" % seconds


def step_dhcp(st, iface, mac, own, wait_s, take):
    st.begin("DHCPv4")
    xid = random.getrandbits(32)
    replies = dhcp_exchange(iface, mac, dhcp_frame(mac, xid, "discover"), xid, wait_s)
    offers = [offer_info(p, o, ms, own) for p, o, ms in replies if first(o, "message-type") == 2]
    for o in offers:
        log("  OFFER %s from %s (%s, %s)%s in %s ms: mask %s, router %s, DNS %s, lease %s" % (
            o["addr"], o["server"], o["mac"], o["origin"], " via relay " + o["relay"] if o["relay"] else "",
            o["ms"], o["mask"], o["router"] or "none", ", ".join(o["dns"]) or "none", duration(o["lease_s"])))
    servers = []
    for o in offers:
        if o["server"] not in servers:
            servers.append(o["server"])
    if stop["flag"]:
        st.done("DHCPv4", "SKIP", "stopped", offers=offers)
        return None
    if not offers:
        st.done("DHCPv4", "FAIL", "no DHCP server answered in %d s" % wait_s, offers=offers)
        return None
    o = min(offers, key=lambda x: x["ms"] if x["ms"] is not None else 1e9)
    who = o["server"] + (" (this device)" if o["origin"] == "THIS DEVICE" else "")
    if len(servers) > 1:
        verdict, line1 = "WARN", "%d servers answered: %s" % (len(servers), ", ".join(servers[:3]))
    else:
        verdict, line1 = "PASS", "offer %s from %s in %s ms" % (o["addr"], who, o["ms"])
    lease = None
    if not take:
        st.done("DHCPv4", verdict, line1, "address not taken (--no-lease)", offers=offers, servers=servers)
        return None
    # Like a real client: the first offer, and the next one if that server does not confirm
    tried = []
    answer = None
    for o in sorted(offers, key=lambda x: x["ms"] if x["ms"] is not None else 1e9):
        if o["server"] in tried or stop["flag"]:
            continue
        tried.append(o["server"])
        xid = random.getrandbits(32)
        extra = [("requested_addr", o["addr"]), ("server_id", o["server"])]
        replies = dhcp_exchange(iface, mac, dhcp_frame(mac, xid, "request", extra), xid, 3,
                                lambda got: any(DHCP in p and p[Ether].src.lower() != mac for p in got))
        found = [(p, op, ms) for p, op, ms in replies if first(op, "message-type") in (5, 6)]
        if not found:
            log("  no answer to REQUEST from %s" % o["server"])
            continue
        if first(found[0][1], "message-type") == 6:
            log("  NAK from %s" % o["server"])
            continue
        answer = found[0]
        break
    if answer is None:
        st.done("DHCPv4", "FAIL", line1 if verdict == "WARN" else "%s did not confirm the address" % who,
                "REQUEST unanswered or refused by %s" % ", ".join(tried), offers=offers, servers=servers)
        return None
    p, op, ms = answer
    who = o["server"] + (" (this device)" if o["origin"] == "THIS DEVICE" else "")
    mask = first(op, "subnet_mask") or o["mask"] or "255.255.255.0"
    prefix = ipaddress.IPv4Network("0.0.0.0/%s" % mask).prefixlen
    lease = {"addr": p[BOOTP].yiaddr, "prefix": prefix, "server": first(op, "server_id") or o["server"],
             "router": first(op, "router"), "dns": op.get("name_server", []), "lease_s": first(op, "lease_time"),
             "ms": ms, "route_added": False}
    run(["ip", "addr", "add", "%s/%d" % (lease["addr"], prefix), "dev", iface])
    if lease["router"] and "default" not in run(["ip", "-4", "route", "show", "default"]):
        run(["ip", "route", "add", "default", "via", lease["router"], "dev", iface])
        lease["route_added"] = True
    log("  ACK %s/%d from %s in %s ms, router %s, DNS %s, lease %s" % (
        lease["addr"], prefix, lease["server"], ms, lease["router"] or "none", ", ".join(lease["dns"]) or "none",
        duration(lease["lease_s"])))
    line2 = "took %s/%d%s, lease %s" % (lease["addr"], prefix, "" if len(servers) == 1 else " from " + lease["server"],
                                        duration(lease["lease_s"]))
    st.done("DHCPv4", verdict, line1, line2, offers=offers, servers=servers, lease=lease)
    return lease


def release(iface, mac, lease):
    try:
        chaddr = bytes.fromhex(mac.replace(":", ""))
        msg = BOOTP(chaddr=chaddr, xid=random.getrandbits(32), ciaddr=lease["addr"]) / DHCP(
            options=[("message-type", "release"), ("server_id", lease["server"]), "end"])
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode())
        s.bind((lease["addr"], 68))
        s.sendto(bytes(msg), (lease["server"], 67))
        s.close()
        sent = True
    except OSError as e:
        log("  RELEASE failed: %s" % e)
        sent = False
    if lease.get("route_added"):
        run(["ip", "route", "del", "default", "via", lease["router"], "dev", iface])
    run(["ip", "addr", "del", "%s/%d" % (lease["addr"], lease["prefix"]), "dev", iface])
    log("Lease %s %s, address removed from %s" % (lease["addr"], "released" if sent else "NOT released", iface))
    return sent


def global6(iface):
    try:
        data = json.loads(run(["ip", "-6", "-j", "addr", "show", "dev", iface, "scope", "global"]) or "[]")
    except ValueError:
        return []
    return [(a["local"], a.get("tentative", False)) for d in data for a in d.get("addr_info", []) if "local" in a]


def step_ipv6(st, iface, mac, own, wait_s):
    st.begin("IPv6")
    got = []
    sniffer = AsyncSniffer(iface=iface, filter="icmp6", store=False, prn=got.append,
                           lfilter=lambda p: ICMPv6ND_RA in p and p[Ether].src.lower() != mac)
    sniffer.start()
    time.sleep(0.3)
    solicit(iface)
    first_at = []
    wait(wait_s, lambda: got and (first_at or first_at.append(time.monotonic())) and
         time.monotonic() - first_at[0] > 0.8)
    try:
        sniffer.stop()
    except Exception:
        pass
    if stop["flag"]:
        st.done("IPv6", "SKIP", "stopped")
        return None
    routers = {}
    for p in got:
        routers.setdefault((p[Ether].src.lower(), p[IPv6].src), p)
    if not routers:
        st.done("IPv6", "INFO", "no Router Advertisement in %d s" % wait_s, "no IPv6 router on this segment")
        return None
    (rmac, rsrc), pkt = sorted(routers.items(), key=lambda kv: kv[0][0] in own)[0]
    ra = pkt[ICMPv6ND_RA]
    prefixes, dns6 = [], []
    for opt in options(ra):
        if isinstance(opt, ICMPv6NDOptPrefixInfo):
            prefixes.append({"prefix": "%s/%d" % (opt.prefix, opt.prefixlen), "A": opt.A, "L": opt.L})
        elif isinstance(opt, ICMPv6NDOptRDNSS):
            dns6 += list(opt.dns)
    notes = audit(pkt, own, iface_mac(iface))
    alerts = [t for level, t in notes if level == "ALERT" and "possible rogue RA" not in t]
    info = {"router": rsrc, "router_mac": rmac, "origin": "THIS DEVICE" if rmac in own else "FOREIGN",
            "M": ra.M, "O": ra.O, "lifetime_s": ra.routerlifetime, "prefixes": prefixes, "dns": dns6,
            "routers": len(routers), "notes": notes, "slaac": []}
    log("  RA from %s (%s, %s): M=%d O=%d lifetime %d s, prefixes %s, RDNSS %s" % (
        rsrc, rmac, info["origin"], ra.M, ra.O, ra.routerlifetime,
        ", ".join("%s A=%d" % (x["prefix"], x["A"]) for x in prefixes) or "none", ", ".join(dns6) or "none"))
    for level, text in notes:
        if "possible rogue RA" not in text:
            log("  [%s] %s" % (level, text))
    auto = [ipaddress.IPv6Network(x["prefix"], strict=False) for x in prefixes if x["A"]]
    if auto:
        def formed():
            info["slaac"] = [a for a, t in global6(iface) if any(ipaddress.IPv6Address(a) in n for n in auto)]
            return info["slaac"]
        wait(2.0, formed)
    flags = ", ".join("%s=1" % f for f in ("M", "O") if getattr(ra, f))
    line1 = "RA: prefix %s" % (", ".join(
        "%s%s" % (x["prefix"], " A=1" if x["A"] else " A=0") for x in prefixes[:2]) or "none")
    if flags:
        line1 += ", " + flags
    if info["slaac"]:
        line2 = "SLAAC address %s" % info["slaac"][0]
    elif auto:
        line2 = "no SLAAC address formed yet"
    else:
        line2 = "no SLAAC: A flag clear" + (", addresses from DHCPv6 (M=1)" if ra.M else "")
    if not ra.routerlifetime:
        line2 += "; lifetime 0, not a default router"
    verdict = "PASS"
    if len(routers) > 1:
        verdict, line1 = "WARN", "%d routers advertise: %s" % (len(routers), ", ".join(s for _, s in routers))
    elif alerts:
        verdict, line2 = "WARN", alerts[0]
    st.done("IPv6", verdict, line1, line2, **info)
    return info


def ping(target, family, iface):
    dest = target + ("%" + iface if family == 6 and target.lower().startswith("fe80") else "")
    out = run(["ping", "-%d" % family, "-n", "-c", "3", "-i", "0.2", "-W", "1", dest], timeout=8)
    m = re.search(r"(\d+) received", out)
    rtt = re.search(r"= [\d.]+/([\d.]+)/", out)
    return int(m.group(1)) if m else 0, float(rtt.group(1)) if rtt else None


def step_gateway(st, iface, lease, v6):
    st.begin("GATEWAY")
    gw4 = lease and lease.get("router")
    gw6 = v6["router"] if v6 and v6.get("lifetime_s") else None
    if not gw4 and not gw6:
        why = "no IPv4 address" if not lease else "DHCP gave no router"
        st.done("GATEWAY", "SKIP", "no gateway announced", "%s; %s" % (
            why, "RA lifetime 0" if v6 else "no IPv6 router"))
        return
    lines, verdicts, data = [], [], {}
    for fam, gw in ((4, gw4), (6, gw6)):
        if not gw or stop["flag"]:
            continue
        got, avg = ping(gw, fam, iface)
        data["v%d" % fam] = {"gateway": gw, "received": got, "sent": 3, "rtt_avg": avg}
        if got == 3:
            lines.append("%s: 3/3, %.1f ms" % (gw, avg))
            verdicts.append("PASS")
        elif got:
            lines.append("%s: %d/3, %.1f ms" % (gw, got, avg))
            verdicts.append("WARN")
        else:
            neigh = run(["ip", "neigh", "show", gw, "dev", iface])
            if "lladdr" in neigh:
                lines.append("%s answers ARP/ND, not ping" % gw)
                verdicts.append("WARN")
            else:
                lines.append("%s: no answer" % gw)
                verdicts.append("FAIL")
        log("  ping %s: %d/3%s" % (gw, got, ", avg %.2f ms" % avg if avg else ""))
    verdict = "FAIL" if "FAIL" in verdicts else "WARN" if "WARN" in verdicts else "PASS"
    st.done("GATEWAY", verdict, lines[0] if lines else "stopped", lines[1] if len(lines) > 1 else "", **data)


def dns_query(server, name, qtype, iface):
    fam = socket.AF_INET6 if ":" in server else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode())
    s.settimeout(2)
    q = DNS(id=random.getrandbits(16), rd=1, qd=DNSQR(qname=name, qtype=qtype))
    t = time.monotonic()
    try:
        s.sendto(bytes(q), (server, 53))
        data, _ = s.recvfrom(4096)
    finally:
        s.close()
    ms = (time.monotonic() - t) * 1000
    r = DNS(data)
    want = 1 if qtype == "A" else 28
    found = [str(rr.rdata) for rr in (r.an or []) if getattr(rr, "type", None) == want]
    return r.rcode, found, ms


def step_dns(st, iface, lease, v6, name):
    st.begin("DNS")
    servers = list((lease or {}).get("dns") or [])
    if v6 and v6.get("slaac"):
        servers += v6.get("dns") or []
    if not servers:
        st.done("DNS", "SKIP", "no DNS server announced", "DHCP and RA gave no DNS server")
        return {}
    server = servers[0]
    res = {"server": server, "qname": name, "A": [], "AAAA": []}
    try:
        rcode, res["A"], ms = dns_query(server, name, "A", iface)
        rcode6, res["AAAA"], ms6 = dns_query(server, name, "AAAA", iface)
    except OSError as e:
        reason = "no answer in 2 s" if isinstance(e, socket.timeout) else str(e)
        st.done("DNS", "FAIL", "%s via %s: %s" % (name, server, reason), **res)
        return res
    res.update(rcode=rcode, ms_a=round(ms, 1), ms_aaaa=round(ms6, 1))
    log("  %s via %s: A %s (%.1f ms), AAAA %s (%.1f ms), rcode %d" % (
        name, server, ", ".join(res["A"]) or "none", ms, ", ".join(res["AAAA"]) or "none", ms6, rcode))
    if rcode or not (res["A"] or res["AAAA"]):
        why = "%s (rcode %d)" % (RCODES.get(rcode, "error"), rcode) if rcode else "no address in the answer"
        st.done("DNS", "FAIL", "%s via %s: %s" % (name, server, why), **res)
        return res
    line2 = ", ".join(p for p in ("A " + res["A"][0] if res["A"] else "", "AAAA " + res["AAAA"][0]
                                  if res["AAAA"] else "") if p)
    st.done("DNS", "PASS", "%s in %.0f ms via %s" % (name, ms, server), line2, **res)
    return res


def connect(addr, port, iface):
    fam = socket.AF_INET6 if ":" in addr else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode())
    s.settimeout(3)
    t = time.monotonic()
    try:
        s.connect((addr, port))
        return "connected", (time.monotonic() - t) * 1000
    except socket.timeout:
        return "timeout", None
    except ConnectionRefusedError:
        return "refused", None
    except OSError as e:
        return e.strerror or str(e), None
    finally:
        s.close()


def step_targets(st, iface, lease, v6, dns, targets):
    st.begin("TARGETS")
    if not targets:
        st.done("TARGETS", "SKIP", "no targets in the profile")
        return
    lines, verdicts, data = [], [], []
    for t in targets:
        if stop["flag"]:
            break
        host, port = t["host"], t.get("tcp", 443)
        try:
            ipaddress.ip_address(host)
            addrs = [host]
        except ValueError:
            addrs = (dns.get("A", []) if lease else []) + (dns.get("AAAA", []) if v6 and v6.get("slaac") else []) \
                if dns.get("qname") == host else []
        if not addrs:
            lines.append("%s port %d: name not resolved" % (host, port))
            verdicts.append("SKIP")
            data.append({"host": host, "port": port, "state": "not resolved"})
            continue
        state, ms = connect(addrs[0], port, iface)
        data.append({"host": host, "addr": addrs[0], "port": port, "state": state, "ms": round(ms, 1) if ms else None})
        log("  TCP %s (%s) port %d: %s%s" % (host, addrs[0], port, state, " in %.1f ms" % ms if ms else ""))
        if state == "connected":
            lines.append("%s port %d: connected in %.0f ms" % (host, port, ms))
            verdicts.append("PASS")
        else:
            lines.append("%s port %d: %s" % (host, port, state))
            verdicts.append("FAIL")
    if not verdicts:
        st.done("TARGETS", "SKIP", "stopped")
        return
    verdict = "FAIL" if "FAIL" in verdicts else "PASS" if "PASS" in verdicts else "SKIP"
    st.done("TARGETS", verdict, lines[0], lines[1] if len(lines) > 1 else "", targets=data)


def load_profile(name):
    path = name if name.endswith(".json") else os.path.join(PROFILE_DIR, name + ".json")
    with open(path) as f:
        prof = json.load(f)
    prof.setdefault("dns_name", "www.vsb.cz")
    prof.setdefault("targets", [])
    # dnsmasq pings an address for 3 s before offering it, a 3 s window misses that offer
    prof.setdefault("dhcp_wait_s", 4)
    prof.setdefault("ra_wait_s", 3)
    return prof


def main():
    ap = argparse.ArgumentParser(description="AutoTest of a network socket: link, DHCPv4, IPv6, gateway, DNS, targets")
    ap.add_argument("iface")
    ap.add_argument("--profile", default="default")
    ap.add_argument("--no-lease", action="store_true", help="only ask DHCP servers, do not take an address")
    ap.add_argument("--own", default="", help="MAC addresses of this device, comma separated")
    args = ap.parse_args()
    iface = args.iface
    try:
        prof = load_profile(args.profile)
    except (OSError, ValueError) as e:
        print("Profile %s: %s" % (args.profile, e))
        return 1
    signal.signal(signal.SIGINT, lambda *_: stop.update(flag=True))
    signal.signal(signal.SIGTERM, lambda *_: stop.update(flag=True))

    start = time.monotonic()
    st = Steps()
    mac = iface_mac(iface)
    own = {m.strip().lower() for m in args.own.split(",") if m.strip()} - {mac}
    log("=== AutoTest on %s (%s), profile %s ===" % (iface, mac, args.profile))
    st.begin("LINK")
    link = port_info.read(iface, keep=False)
    lease = v6 = None
    dns = {}
    rc = 0
    if not link["link"]:
        st.done("LINK", "FAIL", link["short"], **{"port": link})
        for name in STEPS[1:]:
            st.skip(name, "no link")
        rc = 2
    else:
        st.done("LINK", link["verdict"], "%s Mb/s %s duplex, autoneg %s" % (
            link["speed"], (link["duplex"] or "?").lower(), "on" if link["autoneg"] else "off"),
            "partner " + port_info.short_modes(link["partner"]) if link["partner"] else "partner advertised nothing",
            port=link)
        try:
            lease = step_dhcp(st, iface, mac, own, prof["dhcp_wait_s"], not args.no_lease)
            if not stop["flag"]:
                v6 = step_ipv6(st, iface, mac, own, prof["ra_wait_s"])
            if not stop["flag"]:
                step_gateway(st, iface, lease, v6)
            if not stop["flag"]:
                dns = step_dns(st, iface, lease, v6, prof["dns_name"])
            if not stop["flag"]:
                step_targets(st, iface, lease, v6, dns, prof["targets"])
        except Exception as e:
            failed = next((n for n in STEPS if n not in st.data), "TARGETS")
            st.done(failed, "FAIL", "internal error: %s" % e)
            for name in STEPS:
                if name not in st.data:
                    st.skip(name, "not run after an error")
        finally:
            if lease:
                lease["released"] = release(iface, mac, lease)
                d = st.data.get("DHCPv4")
                if d and lease["released"]:
                    d["line2"] += ", returned"
                    print("STEP " + json.dumps({k: d[k] for k in ("step", "verdict", "line1", "line2", "ms")}),
                          flush=True)
    for name in STEPS:
        if name not in st.data:
            st.skip(name, "stopped")
    seconds = time.monotonic() - start
    verdicts = [st.data[n]["verdict"] for n in STEPS]
    overall = "FAIL" if "FAIL" in verdicts else "WARN" if "WARN" in verdicts else "PASS"
    bad = [n for n in STEPS if st.data[n]["verdict"] == overall] if overall != "PASS" else []
    short = ("%s: %s" % (bad[0], st.data[bad[0]]["line1"])) if bad else "all steps passed"
    if stop["flag"]:
        overall = "STOPPED"
        cut = [n for n in STEPS if st.data[n]["line1"] == "stopped"]
        short = "stopped at %s" % cut[0] if cut else "stopped"
    res = {"iface": iface, "profile": args.profile, "lease_taken": bool(lease), "aborted": stop["flag"],
           "seconds": round(seconds, 1), "verdict": overall, "short": short,
           "steps": [st.data[n] for n in STEPS]}
    log("")
    log("Verdict   : %s %s, %.1f s" % (overall, short, seconds))
    print("RESULT autotest " + json.dumps(res), flush=True)
    return rc


if __name__ == "__main__":
    sys.exit(main())
