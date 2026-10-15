import argparse
import json
import os
import signal
import subprocess
import sys
import time

from perf_test import out, rx_missed
from targets import own_nets

stop = {"flag": False, "proc": None}


def on_signal(signum, frame):
    stop["flag"] = True
    if stop["proc"] and stop["proc"].poll() is None:
        stop["proc"].send_signal(signal.SIGINT)


def session(start, end, missed):
    test = start.get("test_start", {})
    conn = (start.get("connected") or [{}])[0]
    recv, sent = end.get("sum_received", {}), end.get("sum_sent", {})
    # With -R the server is the sender and its receive sum is empty
    got = sent if test.get("reverse") else recv
    s = {"client": conn.get("remote_host"), "proto": test.get("protocol", "?").lower(),
         "reverse": bool(test.get("reverse")), "secs": test.get("duration"),
         "mbps": round(got.get("bits_per_second", 0) / 1e6, 1), "rx_missed": missed,
         "time": time.strftime("%H:%M:%S")}
    if s["proto"] == "udp":
        s.update(packets=sent.get("packets") or recv.get("packets"), lost=recv.get("lost_packets"),
                 lost_pct=round(recv.get("lost_percent", 0), 2), jitter_ms=round(recv.get("jitter_ms", 0), 3))
    return s


def main():
    p = argparse.ArgumentParser(description="iperf3 server on a test port until stopped")
    p.add_argument("iface")
    p.add_argument("-p", "--port", type=int, default=5201)
    args = p.parse_args()

    if os.geteuid() != 0:
        print("Error: root privileges required")
        return 1
    if not os.path.exists("/sys/class/net/%s" % args.iface):
        print("Error: interface %s not found in this namespace" % args.iface)
        return 2
    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    addrs = [str(n.ip) for fam in (4, 6) for n in sorted(own_nets(args.iface, fam), key=lambda n: len(str(n.ip)))
             if not n.ip.is_link_local]
    lls = [str(n.ip) for n in own_nets(args.iface, 6) if n.ip.is_link_local]
    print("=== iperf3 server on %s, port %d ===" % (args.iface, args.port))
    for a in addrs:
        print("Connect   : iperf3 -c %s" % a)
    for a in lls:
        print("Link-local: %s%%<interface of the client>" % a)
    out("ADDRS", {"addrs": addrs, "port": args.port})

    cmd = ["iperf3", "-s", "-p", str(args.port), "--json-stream", "--forceflush"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    stop["proc"] = proc
    sessions, start, before, error = [], None, None, None
    for line in proc.stdout:
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        kind, data = ev.get("event"), ev.get("data")
        if kind == "start":
            start, before = data, rx_missed(args.iface)
            conn = (data.get("connected") or [{}])[0]
            print("%s  client %s, %s" % (time.strftime("%H:%M:%S"), conn.get("remote_host"),
                                          data.get("test_start", {}).get("protocol")), flush=True)
        elif kind == "end" and data and start:
            after = rx_missed(args.iface)
            missed = (after - before) % 65536 if None not in (after, before) else None
            s = session(start, data, missed)
            sessions.append(s)
            out("SESSION", s)
            start = None
        elif kind == "error" and not stop["flag"]:
            error = data
            print("iperf3: %s" % data, flush=True)
    proc.wait()
    res = {"iface": args.iface, "port": args.port, "addrs": addrs, "served": len(sessions),
           "sessions": sessions, "aborted": False, "verdict": "INFO"}
    if error and not stop["flag"]:
        res.update(verdict="FAIL", reason=str(error)[:120])
    out("RESULT perf_server", res)
    return 0


if __name__ == "__main__":
    sys.exit(main())
