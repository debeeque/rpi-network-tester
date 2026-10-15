import argparse
import collections
import json
import os
import re
import signal
import struct
import subprocess
import sys
import threading
import time
from datetime import datetime

from pktdecode import CATEGORIES, addr, describe, info, is_host, parse, service, service_port

TOP_N = 5


class Stats:
    def __init__(self, feed_len):
        self.lock = threading.Lock()
        self.packets = self.bytes = 0
        self.cats = {c: [0, 0] for c in CATEGORIES}
        self.fam = {"4": 0, "6": 0}
        self.hosts = set()
        self.talkers = collections.defaultdict(lambda: [0, 0])
        self.ports = collections.Counter()
        self.feed = collections.deque(maxlen=feed_len)
        self.first_ts = None

    def add(self, ts, length, data):
        cat, src, dst, proto, sport, dport = parse(data)
        with self.lock:
            self.packets += 1
            self.bytes += length
            c = self.cats[cat]
            c[0] += 1
            c[1] += length
            if src is not None:
                if cat != "ARP":
                    self.fam["4" if len(src) == 4 else "6"] += 1
                for a in (src, dst):
                    if is_host(a):
                        self.hosts.add(a)
                if is_host(src):
                    t = self.talkers[src]
                    t[0] += length
                    t[1] += 1
            if sport or dport:
                self.ports[(proto, service_port(sport, dport))] += 1
            if self.first_ts is None:
                self.first_ts = ts
            self.feed.append((self.packets, ts, length, cat, src, dst, data))

    def top(self):
        rows = sorted(self.talkers.items(), key=lambda kv: kv[1][0], reverse=True)[:TOP_N]
        return [[addr(a), b, p] for a, (b, p) in rows]

    def top_ports(self):
        return [["tcp" if proto == 6 else "udp", port, service(proto, port), n]
                for (proto, port), n in self.ports.most_common(TOP_N)]


def packet_view(num, ts, length, cat, src, dst, data):
    stamp = datetime.fromtimestamp(ts).astimezone()
    frame = "#%d   %s   %d B" % (num, stamp.strftime("%H:%M:%S.%f")[:-3], length)
    if len(data) < length:
        frame += "   captured %d B" % len(data)
    return {"n": num, "ts": round(ts, 6), "cat": cat, "len": length,
            "src": addr(src) if src is not None else "", "dst": addr(dst) if dst is not None else "",
            "info": info(data), "detail": [["Frame", frame]] + [list(x) for x in describe(data)]}


class PcapTee:
    def __init__(self, path, limit):
        self.path, self.limit = path, limit
        self.file = open(path, "wb", buffering=1 << 20) if path else None
        self.written = self.packets = 0
        self.full = False

    def header(self, raw):
        if self.file:
            self.file.write(raw)
            self.written += len(raw)

    def record(self, raw):
        if not self.file or self.full:
            return
        if self.written + len(raw) > self.limit:
            self.full = True
            return
        self.file.write(raw)
        self.written += len(raw)
        self.packets += 1

    def close(self):
        if self.file:
            self.file.close()


def read_exact(stream, n):
    data = stream.read(n)
    return data if data is not None and len(data) == n else None


def reader(proc, stats, tee, done):
    try:
        head = read_exact(proc.stdout, 24)
        if head is None:
            return
        magic = struct.unpack("<I", head[:4])[0]
        order = "<" if magic in (0xA1B2C3D4, 0xA1B23C4D) else ">"
        nano = magic in (0xA1B23C4D, 0x4D3CB2A1)
        rec = struct.Struct(order + "IIII")
        tee.header(head)
        while True:
            h = read_exact(proc.stdout, 16)
            if h is None:
                break
            sec, frac, incl, orig = rec.unpack(h)
            data = read_exact(proc.stdout, incl)
            if data is None:
                break
            tee.record(h + data)
            stats.add(sec + frac / (1e9 if nano else 1e6), orig, data)
    finally:
        done.set()


# GRO and TSO hand the capture merged segments far above the MTU; off while capturing
OFFLOADS = {"generic-receive-offload": "gro", "generic-segmentation-offload": "gso",
            "tcp-segmentation-offload": "tso"}


def offloads(iface):
    r = subprocess.run(["ethtool", "-k", iface], capture_output=True, text=True)
    state = {}
    for line in r.stdout.splitlines():
        key, _, value = line.partition(":")
        if key.strip() in OFFLOADS and "[fixed]" not in value and value.split():
            state[OFFLOADS[key.strip()]] = value.split()[0]
    return state


def set_offloads(iface, state):
    args = [x for kv in state.items() for x in kv]
    if args:
        subprocess.run(["ethtool", "-K", iface] + args, capture_output=True)


def tcpdump_counts(text):
    counts = {}
    for key, pattern in (("captured", r"(\d+) packets? captured"),
                         ("received", r"(\d+) packets? received by filter"),
                         ("dropped", r"(\d+) packets? dropped by kernel")):
        m = re.search(pattern, text)
        counts[key] = int(m.group(1)) if m else None
    return counts


def main():
    p = argparse.ArgumentParser(description="Passive traffic statistics with a kernel BPF filter")
    p.add_argument("iface")
    p.add_argument("--bpf", default="")
    p.add_argument("--pcap")
    p.add_argument("--max-mb", type=float, default=50)
    p.add_argument("--csv")
    p.add_argument("--interval", type=float, default=1.0)
    p.add_argument("--duration", type=float, default=0)
    p.add_argument("--feed", type=int, default=8)
    p.add_argument("--snaplen", type=int, default=2048)
    p.add_argument("--buffer-kb", type=int, default=4096)
    p.add_argument("--keep-offload", action="store_true")
    args = p.parse_args()

    def result(extra):
        print("RESULT sniff_stats " + json.dumps(extra, separators=(",", ":")), flush=True)

    if os.geteuid() != 0:
        print("Error: root privileges required")
        result({"iface": args.iface, "error": "not root"})
        return 1
    if not os.path.exists("/sys/class/net/%s" % args.iface):
        print("Error: interface %s not found in this namespace" % args.iface)
        result({"iface": args.iface, "error": "no interface"})
        return 2

    saved = offloads(args.iface)
    if not args.keep_offload:
        set_offloads(args.iface, {k: "off" for k in saved})

    cmd = ["tcpdump", "-i", args.iface, "-U", "-w", "-", "-s", str(args.snaplen), "-B", str(args.buffer_kb)]
    if args.bpf:
        cmd.append(args.bpf)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=1 << 20)

    stats = Stats(args.feed)
    tee = PcapTee(args.pcap, int(args.max_mb * 1e6))
    done = threading.Event()
    threading.Thread(target=reader, args=(proc, stats, tee, done), daemon=True).start()

    stop = {"why": None}

    def on_signal(signum, frame):
        stop["why"] = "signal"

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)

    csv = None
    if args.csv:
        csv = open(args.csv, "w", buffering=1)
        csv.write("# sniff_stats %s, filter '%s'; separator ';', integers only, time ISO 8601\n"
                  % (args.iface, args.bpf))
        csv.write("time;t_s;packets;bytes;pps;bps;avg_B;" + ";".join(CATEGORIES) + "\n")

    started = time.monotonic()
    start_wall = datetime.now().astimezone()
    print("Capture      : %s, filter '%s', snaplen %d" % (args.iface, args.bpf or "none", args.snaplen), flush=True)
    last_pk = last_by = last_sent = 0
    last_cats = {c: 0 for c in CATEGORIES}
    next_t = started + args.interval
    while stop["why"] is None:
        if done.wait(max(0.0, next_t - time.monotonic())):
            stop["why"] = "tcpdump exited"
            break
        now = time.monotonic()
        elapsed = now - started
        span = args.interval
        next_t += args.interval
        with stats.lock:
            pk, by = stats.packets, stats.bytes
            cats = {c: v[:] for c, v in stats.cats.items()}
            fam = dict(stats.fam)
            hosts = len(stats.hosts)
            top = stats.top()
            ports = stats.top_ports()
            fresh = [x for x in stats.feed if x[0] > last_sent]
        feed = [packet_view(*x) for x in reversed(fresh)]
        if fresh:
            last_sent = fresh[-1][0]
        dp, db = pk - last_pk, by - last_by
        line = {"t": round(elapsed, 1), "packets": pk, "bytes": by, "pps": round(dp / span),
                "bps": round(db * 8 / span), "avg": round(by / pk) if pk else 0, "hosts": hosts,
                "cats": cats, "fam": fam, "top": top, "ports": ports, "feed": feed,
                "pcap": {"bytes": tee.written, "full": tee.full}}
        print("STATS " + json.dumps(line, separators=(",", ":")), flush=True)
        if csv:
            csv.write("%s;%d;%d;%d;%d;%d;%d;%s\n" % (
                datetime.now().astimezone().isoformat(timespec="seconds"), round(elapsed), dp, db,
                round(dp / span), round(db * 8 / span), round(db / dp) if dp else 0,
                ";".join(str(cats[c][0] - last_cats[c]) for c in CATEGORIES)))
        last_pk, last_by = pk, by
        last_cats = {c: cats[c][0] for c in CATEGORIES}
        if args.duration and elapsed >= args.duration:
            stop["why"] = "duration"

    if proc.poll() is None:
        proc.send_signal(signal.SIGINT)
    try:
        err = proc.communicate(timeout=5)[1]
    except subprocess.TimeoutExpired:
        proc.kill()
        err = proc.communicate()[1]
    done.wait(5)
    if not args.keep_offload:
        set_offloads(args.iface, saved)
    tee.close()
    if csv:
        csv.close()
    counts = tcpdump_counts(err.decode(errors="replace"))
    if stop["why"] == "tcpdump exited" and counts["captured"] is None:
        print("tcpdump: " + err.decode(errors="replace").strip()[-300:])

    duration = time.monotonic() - started
    with stats.lock:
        summary = {
            "iface": args.iface, "bpf": args.bpf, "start": start_wall.isoformat(timespec="seconds"),
            "duration_s": round(duration, 1), "packets": stats.packets, "bytes": stats.bytes,
            "avg": round(stats.bytes / stats.packets) if stats.packets else 0,
            "pps_avg": round(stats.packets / duration) if duration else 0,
            "bps_avg": round(stats.bytes * 8 / duration) if duration else 0,
            "hosts": len(stats.hosts), "cats": stats.cats, "fam": stats.fam,
            "top": stats.top(), "ports": stats.top_ports(), "tcpdump": counts,
            "pcap": {"path": args.pcap, "bytes": tee.written, "packets": tee.packets, "full": tee.full},
            "offload": {"before": saved, "disabled": not args.keep_offload},
            "stopped": stop["why"], "aborted": False,
        }
    if args.csv:
        with open(args.csv.rsplit(".", 1)[0] + "_top.csv", "w") as f:
            f.write("# sniff_stats %s top talkers and ports; separator ';', integers only\n" % args.iface)
            f.write("kind;rank;address_or_port;service;bytes;packets\n")
            for i, (a, b, n) in enumerate(summary["top"], 1):
                f.write("talker;%d;%s;;%d;%d\n" % (i, a, b, n))
            for i, (proto, port, name, n) in enumerate(summary["ports"], 1):
                f.write("port;%d;%s/%d;%s;;%d\n" % (i, proto, port, name, n))
    print("Packets      : %d, %d B, dropped by kernel %s" % (stats.packets, stats.bytes, counts["dropped"]))
    result(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
