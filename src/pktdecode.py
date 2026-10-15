import socket
import struct

VLAN = (0x8100, 0x88A8)
ETHER_NAMES = {0x0800: "IPv4", 0x86DD: "IPv6", 0x0806: "ARP", 0x8100: "802.1Q", 0x88A8: "802.1ad",
               0x88CC: "LLDP", 0x8809: "slow protocols", 0x888E: "EAPOL"}
L4_CAT = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6"}
CATEGORIES = ("TCP", "UDP", "ICMP", "ICMPv6", "ARP", "other")
V6_EXT = (0, 43, 44, 51, 60)
ICMP4 = {0: "echo reply", 3: "destination unreachable", 5: "redirect", 8: "echo request",
         11: "time exceeded", 12: "parameter problem"}
ICMP6 = {1: "destination unreachable", 2: "packet too big", 3: "time exceeded", 4: "parameter problem",
         128: "echo request", 129: "echo reply", 130: "MLD query", 131: "MLD report", 132: "MLD done",
         133: "Router Solicitation", 134: "Router Advertisement", 135: "Neighbor Solicitation",
         136: "Neighbor Advertisement", 137: "Redirect", 143: "MLDv2 report"}
ND_OPTS = {1: "source link-layer", 2: "target link-layer", 3: "prefix", 4: "redirected header",
           5: "MTU", 25: "RDNSS", 31: "DNSSL"}
DHCP4_TYPES = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE", 5: "ACK", 6: "NAK",
               7: "RELEASE", 8: "INFORM"}
DHCP6_TYPES = {1: "SOLICIT", 2: "ADVERTISE", 3: "REQUEST", 4: "CONFIRM", 5: "RENEW", 6: "REBIND",
               7: "REPLY", 8: "RELEASE", 9: "DECLINE", 10: "RECONFIGURE", 11: "INFORMATION-REQUEST"}
PREFERENCE = {0: "Medium", 1: "High", 2: "Reserved", 3: "Low"}
INFINITE = 0xFFFFFFFF

_services = {}


def service(proto, port):
    key = (proto, port)
    if key not in _services:
        try:
            _services[key] = socket.getservbyport(port, "tcp" if proto == 6 else "udp")
        except OSError:
            _services[key] = ""
    return _services[key]


def service_port(sport, dport):
    return min(sport, dport)


def mac(b):
    return ":".join("%02x" % x for x in b)


def ip4(b):
    return socket.inet_ntop(socket.AF_INET, b)


def ip6(b):
    return socket.inet_ntop(socket.AF_INET6, b)


def addr(b):
    return ip4(b) if len(b) == 4 else ip6(b)


def is_host(b):
    if len(b) == 4:
        return b[0] not in (0, 127) and b[0] < 224 and b != b"\xff\xff\xff\xff"
    return b[0] != 0xFF and any(b)


def v6_payload(data, off):
    """Walk the extension header chain: (upper protocol, its offset, headers, fragment offset in bytes)."""
    nh = data[off + 6]
    p = off + 40
    exts = []
    frag = 0
    while nh in V6_EXT and len(data) >= p + 8:
        exts.append(nh)
        if nh == 44:
            frag = struct.unpack_from("!H", data, p + 2)[0] & 0xFFF8
            length = 8
        elif nh == 51:
            length = (data[p + 1] + 2) * 4
        else:
            length = (data[p + 1] + 1) * 8
        nh = data[p]
        p += length
    return nh, p, exts, frag


def parse(data):
    """Fast path for statistics: (category, src, dst, l4 proto, sport, dport)."""
    n = len(data)
    if n < 14:
        return "other", None, None, 0, 0, 0
    etype = data[12] << 8 | data[13]
    off = 14
    while etype in VLAN and n >= off + 4:
        etype = data[off + 2] << 8 | data[off + 3]
        off += 4
    if etype == 0x0800 and n >= off + 20:
        proto = data[off + 9]
        src, dst = data[off + 12:off + 16], data[off + 16:off + 20]
        l4 = off + (data[off] & 0x0F) * 4
        frag = (data[off + 6] & 0x1F) << 8 | data[off + 7]
    elif etype == 0x86DD and n >= off + 40:
        src, dst = data[off + 8:off + 24], data[off + 24:off + 40]
        proto, l4, _, frag = v6_payload(data, off)
    elif etype == 0x0806 and n >= off + 28:
        return "ARP", data[off + 14:off + 18], data[off + 24:off + 28], 0, 0, 0
    else:
        return "other", None, None, 0, 0, 0
    cat = L4_CAT.get(proto, "other")
    if cat == "ICMP" and len(src) == 16:
        cat = "other"
    sport = dport = 0
    if proto in (6, 17) and not frag and n >= l4 + 4:
        sport, dport = struct.unpack_from("!HH", data, l4)
    return cat, src, dst, proto, sport, dport


def info(data):
    """One short word or phrase for the packet feed."""
    cat, src, dst, proto, sport, dport = parse(data)
    if proto in (6, 17) and (sport or dport):
        port = service_port(sport, dport)
        return service(proto, port) or str(port)
    lines = describe(data)
    for layer, text in lines:
        if layer in ("ICMP", "ICMPv6", "ARP"):
            return text.split("   ")[0].replace("type ", "").lstrip("0123456789 ")
    return ""


def describe(data):
    """Layer by layer text for the packet detail page: [(layer, text), ...]."""
    out = []
    n = len(data)
    if n < 14:
        return [("Frame", "truncated, %d B" % n)]
    etype = data[12] << 8 | data[13]
    out.append(("Ethernet", "%s > %s   type 0x%04x %s" % (mac(data[6:12]), mac(data[0:6]), etype,
                                                        ETHER_NAMES.get(etype, ""))))
    off = 14
    while etype in VLAN and n >= off + 4:
        tci = data[off] << 8 | data[off + 1]
        etype = data[off + 2] << 8 | data[off + 3]
        out.append(("802.1Q", "VLAN %d   priority %d   type 0x%04x %s"
                    % (tci & 0x0FFF, tci >> 13, etype, ETHER_NAMES.get(etype, ""))))
        off += 4
    try:
        if etype == 0x0800:
            _ipv4(data, off, out)
        elif etype == 0x86DD:
            _ipv6(data, off, out)
        elif etype == 0x0806:
            _arp(data, off, out)
    except (IndexError, struct.error, ValueError):
        out.append(("", "truncated"))
    return out


def _ipv4(data, off, out):
    ihl = (data[off] & 0x0F) * 4
    tos, total, ident, frag, ttl, proto = struct.unpack_from("!xBHHHBB", data, off)
    flags = []
    if frag & 0x4000:
        flags.append("DF")
    if frag & 0x2000:
        flags.append("MF")
    offset = (frag & 0x1FFF) * 8
    out.append(("IPv4", "%s > %s" % (ip4(data[off + 12:off + 16]), ip4(data[off + 16:off + 20]))))
    extra = "   fragment offset %d B" % offset if offset else ""
    out.append(("", "ttl %d   length %d   id 0x%04x   %s   proto %d %s%s"
                % (ttl, total, ident, " ".join(flags) or "-", proto, L4_CAT.get(proto, ""), extra)))
    if offset:
        return
    _l4(data, off + ihl, proto, out, 4)


def _ipv6(data, off, out):
    first, plen, nh, hlim = struct.unpack_from("!IHBB", data, off)
    tc = (first >> 20) & 0xFF
    flow = first & 0xFFFFF
    out.append(("IPv6", "%s > %s" % (ip6(data[off + 8:off + 24]), ip6(data[off + 24:off + 40]))))
    proto, l4, exts, frag = v6_payload(data, off)
    ext = "   ext %s" % ",".join(str(e) for e in exts) if exts else ""
    out.append(("", "hop limit %d   payload %d B   next header %d %s%s"
                % (hlim, plen, proto, L4_CAT.get(proto, ""), ext)))
    if tc or flow:
        out.append(("", "traffic class 0x%02x   flow label 0x%05x" % (tc, flow)))
    if frag:
        out.append(("", "fragment offset %d B, no upper-layer header in this fragment" % frag))
        return
    _l4(data, l4, proto, out, 6)


def _l4(data, off, proto, out, family):
    if proto == 6:
        sport, dport, seq, ack, offflags, win = struct.unpack_from("!HHIIHH", data, off)
        names = "FSRPAUEC"
        flags = "".join(names[i] for i in range(8) if offflags & (1 << i))
        out.append(("TCP", "%d > %d   flags [%s]   seq %d   ack %d   win %d"
                    % (sport, dport, flags, seq, ack, win)))
        _service_line(proto, sport, dport, out)
    elif proto == 17:
        sport, dport, length = struct.unpack_from("!HHH", data, off)
        out.append(("UDP", "%d > %d   length %d" % (sport, dport, length)))
        _service_line(proto, sport, dport, out)
        payload = off + 8
        if {sport, dport} & {67, 68}:
            _dhcp4(data, payload, out)
        elif {sport, dport} & {546, 547} and len(data) > payload:
            out.append(("DHCPv6", "%s" % DHCP6_TYPES.get(data[payload], "type %d" % data[payload])))
        elif 53 in (sport, dport):
            _dns(data, payload, out)
    elif proto == 1 and family == 4:
        t, code = data[off], data[off + 1]
        text = "type %d %s   code %d" % (t, ICMP4.get(t, ""), code)
        if t in (0, 8):
            ident, seq = struct.unpack_from("!HH", data, off + 4)
            text += "   id %d   seq %d" % (ident, seq)
        out.append(("ICMP", text))
        if t in (3, 11, 12) and len(data) >= off + 28:
            inner = off + 8
            out.append(("", "original: %s > %s   proto %d" % (
                ip4(data[inner + 12:inner + 16]), ip4(data[inner + 16:inner + 20]), data[inner + 9])))
    elif proto == 58:
        _icmp6(data, off, out)


def _service_line(proto, sport, dport, out):
    port = service_port(sport, dport)
    name = service(proto, port)
    if name:
        out.append(("", "service %s (port %d, /etc/services)" % (name, port)))


def _dhcp4(data, off, out):
    if len(data) < off + 240 or data[off + 236:off + 240] != b"\x63\x82\x53\x63":
        return
    op = "request" if data[off] == 1 else "reply"
    yiaddr = ip4(data[off + 16:off + 20])
    client = mac(data[off + 28:off + 34])
    p = off + 240
    kind = ""
    while p + 2 <= len(data) and data[p] != 255:
        if data[p] == 0:
            p += 1
            continue
        code, length = data[p], data[p + 1]
        if code == 53 and length >= 1:
            kind = DHCP4_TYPES.get(data[p + 2], str(data[p + 2]))
        p += 2 + length
    out.append(("DHCP", "%s %s   client %s   your address %s" % (kind or "BOOTP", op, client, yiaddr)))


def _dns(data, off, out):
    if len(data) < off + 12:
        return
    ident, flags, qd = struct.unpack_from("!HHH", data, off)
    p = off + 12
    labels = []
    while p < len(data) and data[p] and len(labels) < 32:
        if data[p] & 0xC0:
            labels.append("...")
            p += 2
            break
        labels.append(data[p + 1:p + 1 + data[p]].decode("ascii", "replace"))
        p += 1 + data[p]
    qtype = struct.unpack_from("!H", data, p + 1)[0] if qd and p + 3 <= len(data) else 0
    kind = "response" if flags & 0x8000 else "query"
    out.append(("DNS", "%s   %s   type %d   id 0x%04x" % (kind, ".".join(labels) or ".", qtype, ident)))


def _icmp6(data, off, out):
    t, code = data[off], data[off + 1]
    name = ICMP6.get(t, "")
    text = "type %d %s   code %d" % (t, name, code)
    if t in (128, 129):
        ident, seq = struct.unpack_from("!HH", data, off + 4)
        text += "   id %d   seq %d" % (ident, seq)
    elif t == 2:
        text += "   MTU %d" % struct.unpack_from("!I", data, off + 4)[0]
    out.append(("ICMPv6", text))
    if t in (1, 2, 3, 4) and len(data) >= off + 48:
        inner = off + 8
        out.append(("", "original: %s > %s   next header %d" % (
            ip6(data[inner + 8:inner + 24]), ip6(data[inner + 24:inner + 40]), data[inner + 6])))
    opts = None
    if t == 133:
        opts = off + 8
    elif t == 134:
        chlim, flags, life, reach, retrans = struct.unpack_from("!BBHII", data, off + 4)
        out.append(("", "M=%d O=%d   preference %s   cur hop limit %d"
                    % (flags >> 7 & 1, flags >> 6 & 1, PREFERENCE[flags >> 3 & 3], chlim)))
        out.append(("", "router lifetime %d s   reachable %d ms   retrans %d ms" % (life, reach, retrans)))
        opts = off + 16
    elif t in (135, 136):
        target = ip6(data[off + 8:off + 24])
        if t == 136:
            f = data[off + 4]
            out.append(("", "target %s   R=%d S=%d O=%d" % (target, f >> 7 & 1, f >> 6 & 1, f >> 5 & 1)))
        else:
            out.append(("", "target %s" % target))
        opts = off + 24
    if opts is not None:
        _nd_options(data, opts, out)


def _lifetime(v):
    return "infinite" if v == INFINITE else "%d s" % v


def _nd_options(data, p, out):
    while p + 2 <= len(data):
        kind, length = data[p], data[p + 1] * 8
        if length == 0 or p + length > len(data):
            break
        body = data[p:p + length]
        if kind in (1, 2):
            text = "%s %s" % (ND_OPTS[kind], mac(body[2:8]))
        elif kind == 3:
            plen, flags, valid, pref = struct.unpack_from("!BBII", body, 2)
            text = "prefix %s/%d   L=%d A=%d   valid %s   pref %s" % (
                ip6(body[16:32]), plen, flags >> 7 & 1, flags >> 6 & 1, _lifetime(valid), _lifetime(pref))
        elif kind == 5:
            text = "MTU %d" % struct.unpack_from("!I", body, 4)[0]
        elif kind == 25:
            servers = [ip6(body[i:i + 16]) for i in range(8, length, 16)]
            text = "RDNSS %s   lifetime %s" % (", ".join(servers), _lifetime(struct.unpack_from("!I", body, 4)[0]))
        else:
            text = "%s (type %d, %d B)" % (ND_OPTS.get(kind, "option"), kind, length)
        out.append(("option", text))
        p += length


def _arp(data, off, out):
    op = struct.unpack_from("!H", data, off + 6)[0]
    sha, spa = mac(data[off + 8:off + 14]), ip4(data[off + 14:off + 18])
    tpa = ip4(data[off + 24:off + 28])
    if op == 1:
        text = "who-has %s tell %s" % (tpa, spa)
    elif op == 2:
        text = "%s is-at %s" % (spa, sha)
    else:
        text = "operation %d" % op
    out.append(("ARP", text))
