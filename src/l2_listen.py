import argparse
import ctypes
import fcntl
import ipaddress
import json
import signal
import socket
import struct
import subprocess
import sys
import time

from scapy.config import conf
from scapy.contrib.cdp import CDPv2_HDR
from scapy.contrib.lldp import (
    LLDPDU,
    LLDPDUChassisID,
    LLDPDUEndOfLLDPDU,
    LLDPDUGenericOrganisationSpecific,
    LLDPDUManagementAddress,
    LLDPDUPortDescription,
    LLDPDUPortID,
    LLDPDUSystemCapabilities,
    LLDPDUSystemDescription,
    LLDPDUSystemName,
    LLDPDUTimeToLive,
)
from scapy.arch.linux import L2ListenSocket
from scapy.layers.l2 import STP, Dot1Q, Dot3, Ether
from scapy.sendrecv import AsyncSniffer, sendp

LLDP_MAC = "01:80:c2:00:00:0e"
BPF = ("ether proto 0x88cc or ether dst 01:00:0c:cc:cc:cc or ether dst 01:80:c2:00:00:00 "
       "or ether proto 0x8809 or vlan")
CAPS = ("other", "repeater", "mac_bridge", "wlan_access_point", "router", "telephone",
        "docsis_cable_device", "station_only", "c_vlan_component", "s_vlan_component", "two_port_mac_relay")
STP_VERSION = {0: "STP", 2: "RSTP", 3: "MSTP"}
SO_ATTACH_FILTER = 26

stop = {"flag": False}


def iface_mac(name):
    try:
        with open("/sys/class/net/%s/address" % name) as f:
            return f.read().strip().lower()
    except OSError:
        return None


def iface_ipv4(name):
    try:
        fd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        packed = fcntl.ioctl(fd.fileno(), 0x8915, struct.pack("256s", name.encode()[:15]))
        return socket.inet_ntoa(packed[20:24])
    except OSError:
        return None


# The adapter strips 802.1Q tags (rx-vlan-offload) and the kernel passes them aside; a filter
# compiled by tcpdump on the live interface tests that side field, Scapy's offline compile does not
def attach_bpf(sock, iface, expr):
    out = subprocess.run(["tcpdump", "-i", iface, "-ddd", expr], capture_output=True, text=True,
                         timeout=10).stdout.split()
    count = int(out[0])
    code = b"".join(struct.pack("HBBI", *map(int, out[1 + 4 * i:5 + 4 * i])) for i in range(count))
    buf = ctypes.create_string_buffer(code, len(code))
    sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, struct.pack("HL", count, ctypes.addressof(buf)))


def text(value):
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    return "".join(ch if 32 <= ord(ch) < 127 else "?" for ch in str(value)).strip()


def mac_text(value):
    if isinstance(value, bytes) and len(value) == 6:
        return ":".join("%02x" % b for b in value)
    return text(value).lower()


def address(subtype, raw):
    try:
        if subtype == 1:
            return str(ipaddress.IPv4Address(raw if isinstance(raw, bytes) else raw.encode("latin-1")))
        if subtype == 2:
            return str(ipaddress.IPv6Address(raw if isinstance(raw, bytes) else raw.encode("latin-1")))
    except (ValueError, UnicodeEncodeError):
        pass
    return text(raw)


def tlvs(pkt):
    layer = pkt.getlayer(LLDPDU)
    while layer is not None and isinstance(layer, LLDPDU):
        yield layer
        layer = layer.payload if isinstance(layer.payload, LLDPDU) else None


def parse_lldp(pkt):
    n = {"proto": "LLDP", "mgmt": []}
    for t in tlvs(pkt):
        if isinstance(t, LLDPDUChassisID):
            n["chassis_id"] = mac_text(t.id) if t.subtype == 4 else text(t.id)
        elif isinstance(t, LLDPDUPortID):
            n["port_id"] = mac_text(t.id) if t.subtype == 3 else text(t.id)
        elif isinstance(t, LLDPDUTimeToLive):
            n["ttl"] = t.ttl
        elif isinstance(t, LLDPDUPortDescription):
            n["port_descr"] = text(t.description)
        elif isinstance(t, LLDPDUSystemName):
            n["system_name"] = text(t.system_name)
        elif isinstance(t, LLDPDUSystemDescription):
            n["system_descr"] = text(t.description)
        elif isinstance(t, LLDPDUSystemCapabilities):
            n["caps"] = [c for c in CAPS if getattr(t, c + "_enabled", 0)]
        elif isinstance(t, LLDPDUManagementAddress):
            n["mgmt"].append(address(t.management_address_subtype, t.management_address))
        elif isinstance(t, LLDPDUGenericOrganisationSpecific) and t.org_code == 0x0080C2:
            data = bytes(t.data)
            # IEEE 802.1 TLVs: 1 Port VLAN ID, 3 VLAN name
            if t.subtype == 1 and len(data) >= 2:
                n["vlan"] = int.from_bytes(data[:2], "big")
            elif t.subtype == 3 and len(data) >= 3:
                n.setdefault("vlan_names", []).append("%d %s" % (int.from_bytes(data[:2], "big"),
                                                                 text(data[3:3 + data[2]])))
    return n


def parse_cdp(pkt):
    hdr = pkt.getlayer(CDPv2_HDR)
    n = {"proto": "CDP", "ttl": hdr.ttl, "mgmt": []}
    for msg in hdr.msg or []:
        name = type(msg).__name__
        if name == "CDPMsgDeviceID":
            n["system_name"] = text(msg.val)
        elif name == "CDPMsgPortID":
            n["port_id"] = text(msg.iface)
        elif name == "CDPMsgPlatform":
            n["platform"] = text(msg.val)
        elif name == "CDPMsgSoftwareVersion":
            n["system_descr"] = text(msg.val).splitlines()[0] if text(msg.val) else ""
        elif name == "CDPMsgNativeVLAN":
            n["vlan"] = msg.vlan
        elif name in ("CDPMsgAddr", "CDPMsgMgmtAddr"):
            for rec in getattr(msg, "addr", []) or []:
                a = getattr(rec, "addr", None)
                if a and a not in n["mgmt"]:
                    n["mgmt"].append(str(a))
        elif name == "CDPMsgVTPMgmtDomain":
            n["vtp_domain"] = text(msg.val)
        elif name == "CDPMsgDuplex":
            n["duplex"] = "full" if msg.duplex else "half"
    return n


def summary(n):
    parts = [n.get("system_name") or n.get("chassis_id") or "?"]
    if n.get("port_id"):
        parts.append("port " + n["port_id"] + (" (%s)" % n["port_descr"] if n.get("port_descr") else ""))
    if n.get("vlan") is not None:
        parts.append("VLAN %s" % n["vlan"])
    if n.get("mgmt"):
        parts.append("mgmt " + n["mgmt"][0])
    if n.get("ttl") is not None:
        parts.append("TTL %s" % n["ttl"])
    return ", ".join(parts)


def hello(iface):
    mac = iface_mac(iface)
    ip = iface_ipv4(iface)
    frame = (Ether(dst=LLDP_MAC, src=mac, type=0x88CC) /
             LLDPDUChassisID(subtype=4, id=mac) /
             LLDPDUPortID(subtype=5, id=iface) /
             LLDPDUTimeToLive(ttl=120) /
             LLDPDUPortDescription(description="test port " + iface) /
             LLDPDUSystemName(system_name=socket.gethostname()) /
             LLDPDUSystemDescription(description="Portable Network Analyzer") /
             LLDPDUSystemCapabilities(station_only_available=1, station_only_enabled=1))
    if ip:
        frame = frame / LLDPDUManagementAddress(management_address_subtype=1,
                                                management_address=socket.inet_aton(ip),
                                                interface_numbering_subtype=2,
                                                interface_number=socket.if_nametoindex(iface))
    frame = frame / LLDPDUEndOfLLDPDU()
    sendp(frame, iface=iface, verbose=False)
    sent = {"chassis_id": mac, "port_id": iface, "ttl": 120, "system_name": socket.gethostname(), "mgmt": ip}
    print("Sent one LLDP frame from %s: %s, port %s, TTL 120%s" % (
        iface, sent["system_name"], iface, ", mgmt " + ip if ip else ""), flush=True)
    return sent


def main():
    ap = argparse.ArgumentParser(description="Passive L2 listener: LLDP, CDP, STP, LACP, 802.1Q tags")
    ap.add_argument("iface")
    ap.add_argument("-t", "--timeout", type=float, default=65.0, help="seconds to listen, 0 = do not listen")
    ap.add_argument("--all", action="store_true", help="listen the whole time instead of stopping at the first LLDP/CDP")
    ap.add_argument("--own", default="", help="MAC addresses of this device, comma separated")
    ap.add_argument("--hello", action="store_true", help="send one LLDP frame first (the only frame this script sends)")
    args = ap.parse_args()

    iface = args.iface
    res = {"iface": iface, "timeout_s": args.timeout, "listened_s": 0, "aborted": False, "stopped_early": False,
           "hello": None, "frames": 0, "neighbors": [], "stp": [], "lacp": [], "vlans": {}}
    local = iface_mac(iface)
    if not local:
        res.update(verdict="FAIL", short="no interface %s" % iface)
        print("RESULT l2_listen " + json.dumps(res))
        return 2
    try:
        with open("/sys/class/net/%s/carrier" % iface) as f:
            carrier = f.read().strip() == "1"
    except OSError:
        carrier = False
    if not carrier:
        res.update(verdict="FAIL", short="no link on %s" % iface)
        print("No link on %s: nothing to listen to" % iface)
        print("RESULT l2_listen " + json.dumps(res))
        return 2
    own = {m.strip().lower() for m in args.own.split(",") if m.strip()} - {local}

    signal.signal(signal.SIGINT, lambda *_: stop.update(flag=True))
    signal.signal(signal.SIGTERM, lambda *_: stop.update(flag=True))
    conf.verb = 0

    if args.timeout <= 0:
        if args.hello:
            res["hello"] = hello(iface)
        res.update(verdict="INFO", short="LLDP hello sent from %s" % iface)
        print("RESULT l2_listen " + json.dumps(res))
        return 0

    seen = {}
    start = time.monotonic()

    def handle(pkt):
        res["frames"] += 1
        l2 = pkt.getlayer(Ether) or pkt.getlayer(Dot3)
        if l2 is None:
            return
        src = l2.src.lower()
        if src == local:
            return
        if Dot1Q in pkt:
            vid = str(pkt[Dot1Q].vlan)
            res["vlans"][vid] = res["vlans"].get(vid, 0) + 1
        at = round(time.monotonic() - start, 1)
        origin = "THIS DEVICE" if src in own else "FOREIGN"
        if LLDPDU in pkt:
            n = parse_lldp(pkt)
        elif CDPv2_HDR in pkt:
            n = parse_cdp(pkt)
        elif STP in pkt:
            s = pkt[STP]
            key = ("STP", src)
            if key not in seen:
                seen[key] = {"bridge": s.bridgemac.lower(), "root": s.rootmac.lower(), "root_priority": s.rootid,
                             "version": STP_VERSION.get(s.version, str(s.version)), "from": src, "at_s": at}
                res["stp"].append(seen[key])
                print("HEARD %s %s %s root %s, priority %s" % (seen[key]["version"], src, origin,
                                                               seen[key]["root"], s.rootid), flush=True)
            return
        elif Ether in pkt and pkt[Ether].type == 0x8809 and bytes(pkt[Ether].payload)[:1] == b"\x01":
            key = ("LACP", src)
            if key not in seen:
                seen[key] = {"from": src, "at_s": at}
                res["lacp"].append(seen[key])
                print("HEARD LACP %s %s port is in a link aggregation" % (src, origin), flush=True)
            return
        else:
            return
        key = (n["proto"], src)
        n.update(mac=src, origin=origin, at_s=at)
        if key not in seen:
            seen[key] = n
            res["neighbors"].append(n)
            print("HEARD %s %s %s %s" % (n["proto"], src, origin, summary(n)), flush=True)

    sock = L2ListenSocket(iface=iface)
    attach_bpf(sock.ins, iface, BPF)
    sniffer = AsyncSniffer(opened_socket=sock, prn=handle, store=False)
    sniffer.start()
    time.sleep(0.3)
    if args.hello:
        res["hello"] = hello(iface)
    print("Listening on %s for up to %d s: LLDP, CDP, STP, LACP, VLAN tags%s" % (
        iface, args.timeout, "" if args.hello else "; sending nothing"), flush=True)
    deadline = start + args.timeout
    while time.monotonic() < deadline and not stop["flag"]:
        if res["neighbors"] and not args.all:
            res["stopped_early"] = True
            break
        time.sleep(0.2)
    try:
        sniffer.stop()
    except Exception:
        pass
    res["listened_s"] = round(time.monotonic() - start, 1)
    res["aborted"] = stop["flag"]

    foreign = [n for n in res["neighbors"] if n["origin"] == "FOREIGN"]
    best = (foreign or res["neighbors"] or [None])[0]
    if best:
        who = "this device" if best["origin"] == "THIS DEVICE" else "neighbour"
        res.update(verdict="PASS", short="%s %s via %s" % (who, summary(best), best["proto"]))
    elif res["stp"]:
        res.update(verdict="INFO", short="no LLDP or CDP in %d s, but STP: a switch is there" % res["listened_s"])
    else:
        res.update(verdict="INFO", short="no LLDP, CDP or STP in %d s" % res["listened_s"])
    print("Frames    : %d in %.1f s" % (res["frames"], res["listened_s"]))
    print("Verdict   : %s %s" % (res["verdict"], res["short"]))
    print("RESULT l2_listen " + json.dumps(res))
    return 0


if __name__ == "__main__":
    sys.exit(main())
