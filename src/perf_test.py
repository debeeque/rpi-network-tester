import argparse
import csv
import json
import os
import re
import signal
import subprocess
import sys
import time

from targets import bare, device_ports, in_stand, mac_of, own_port, resolve

# RFC 2544 sec. 9.1 and RFC 5180 sec. 5.1.1; frame length includes the 4-byte FCS
FRAMES = [64, 128, 256, 512, 1024, 1280, 1518]
OVERHEAD = {4: 14 + 20 + 8 + 4, 6: 14 + 40 + 8 + 4}
MIN_PAYLOAD = 16
PORT = 5201

stop = {"flag": False, "proc": None}


def on_signal(signum, frame):
    stop["flag"] = True
    if stop["proc"] and stop["proc"].poll() is None:
        stop["proc"].send_signal(signal.SIGINT)


def out(kind, data):
    print("%s %s" % (kind, json.dumps(data, separators=(",", ":"))), flush=True)


def cpu_times():
    with open("/proc/stat") as f:
        v = [int(x) for x in f.readline().split()[1:]]
    return v[3] + v[4], sum(v)


def vcgencmd(arg):
    try:
        return subprocess.run(["vcgencmd", arg], capture_output=True, text=True, timeout=3).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def temp():
    m = re.search(r"([\d.]+)", vcgencmd("measure_temp"))
    return float(m.group(1)) if m else None


def throttled():
    m = re.search(r"0x([0-9a-fA-F]+)", vcgencmd("get_throttled"))
    return int(m.group(1), 16) if m else None


# The r8152 hardware counter of frames the adapter had to drop; 16 bits wide
def rx_missed(iface):
    try:
        text = subprocess.run(["ethtool", "-S", iface], capture_output=True, text=True, timeout=3).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"rx_missed:\s*(\d+)", text)
    return int(m.group(1)) if m else None


def health_start(iface):
    return {"cpu": cpu_times(), "temp": temp(), "thr": throttled(), "missed": rx_missed(iface)}


def health_end(h, iface):
    idle, total = cpu_times()
    didle, dtotal = idle - h["cpu"][0], total - h["cpu"][1]
    missed = rx_missed(iface)
    thr = throttled()
    return {"cpu_pct": round(100.0 * (1 - didle / dtotal), 1) if dtotal else None,
            "temp_start": h["temp"], "temp_end": temp(),
            "throttled_start": hex(h["thr"]) if h["thr"] is not None else None,
            "throttled_end": hex(thr) if thr is not None else None,
            "throttled_now": bool(thr & 0xF) if thr is not None else None,
            "rx_missed": (missed - h["missed"]) % 65536 if None not in (missed, h["missed"]) else None}


def iperf(target, family, proto, rate, length, secs, reverse):
    cmd = ["iperf3", "-c", target, "-%d" % family, "-p", str(PORT), "-t", str(secs), "--json-stream",
           "--connect-timeout", "3000"]
    if proto == "udp":
        cmd += ["-u", "-b", "%dM" % rate if rate else "0"]
    if length:
        cmd += ["-l", str(length)]
    if reverse:
        cmd.append("-R")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    stop["proc"] = proc
    end, error = None, None
    for line in proc.stdout:
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if ev.get("event") == "interval":
            s = ev["data"]["sum"]
            out("PROGRESS", {"t": round(s["end"]), "mbps": round(s["bits_per_second"] / 1e6, 1)})
        elif ev.get("event") == "end" and ev.get("data"):
            end = ev["data"]
        elif ev.get("event") == "error":
            error = ev.get("data")
    proc.wait()
    stop["proc"] = None
    return end, error


def summary(end, proto, secs):
    sent, recv = end.get("sum_sent", {}), end.get("sum_received", {})
    res = {"mbps": round(recv.get("bits_per_second", 0) / 1e6, 1),
           "mbps_sent": round(sent.get("bits_per_second", 0) / 1e6, 1)}
    cpu = end.get("cpu_utilization_percent", {})
    res.update(cpu_iperf_local=round(cpu.get("host_total", 0), 1), cpu_iperf_remote=round(cpu.get("remote_total", 0), 1))
    if proto == "udp":
        packets = sent.get("packets") or recv.get("packets", 0)
        dur = sent.get("seconds") or secs
        res.update(packets=packets, pps=round(packets / dur) if dur else None, lost=recv.get("lost_packets"),
                   lost_pct=round(recv.get("lost_percent", 0), 2), jitter_ms=round(recv.get("jitter_ms", 0), 3))
    elif "retransmits" in sent:
        res["retransmits"] = sent["retransmits"]
    return res


# On the loop the other port of this device is the target: start its receiver for the test
def peer_server(res, keep):
    port = own_port(res.get("mac"))
    ns = device_ports().get(port, {}).get("ns") if port else None
    if not ns:
        return None
    cmd = ["ip", "netns", "exec", ns, "iperf3", "-s", "-p", str(PORT)] + ([] if keep else ["-1"])
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.7)
    print("Receiver  : iperf3 server started on %s for this test" % port, flush=True)
    return proc


def verdict(res):
    if res.get("error"):
        loop = str(res.get("peer", "")).endswith("(loop)")
        res.update(verdict="FAIL", short="no iperf3 receiver at the target",
                   reason="iperf3 could not reach %s: %s" % (res["target"], res["error"][:80]),
                   hint="the receiver on the other port did not start" if loop else
                   "run iperf3 -s on the host and allow port 5201 in its firewall")
        # The server's UDP socket is unbound and a host with several IPv6 addresses (Windows prefers its
        # temporary one) answers from another address, which the connected client socket ignores
        if res.get("proto") == "udp" and res["family"] == "v6" and "read from stream socket" in res["error"]:
            res.update(short="UDP answer came from another IPv6 address",
                       hint="the host has several IPv6 addresses; start its server as iperf3 -s -B %s"
                            % bare(res["target"]))
        return
    notes = []
    if res.get("proto") == "udp" and res.get("lost_pct", 0) >= 1:
        res["verdict"] = "WARN"
        missed = res.get("rx_missed") or 0
        if res.get("reverse") and missed >= 0.5 * (res.get("lost") or 0) > 0:
            notes.append("%d frames dropped by this device's adapter: the sender bursts faster than USB 2.0"
                         % missed)
        else:
            notes.append("%s %% lost on the way or at the receiver" % res["lost_pct"])
    else:
        res["verdict"] = "PASS"
    if res.get("throttled_now"):
        res["verdict"] = "WARN"
        notes.append("the SoC was throttled, the number is not comparable")
    if notes:
        res["reason"] = "; ".join(notes)


def single(args, res):
    secs, length = args.time, args.length
    h = health_start(args.iface)
    server = peer_server(res, False) if args.peer_server else None
    print("Test      : %s %s, %s, %d s%s" % (args.proto.upper(), res["family"],
          "%d Mbit/s" % args.rate if args.proto == "udp" and args.rate else "as fast as possible",
          secs, ", target sends (-R)" if args.reverse else ""), flush=True)
    end, error = iperf(res["target"], args.family, args.proto, args.rate, length, secs, args.reverse)
    if server and server.poll() is None:
        server.terminate()
    res.update(health_end(h, args.iface))
    res["loop_server"] = bool(server)
    if end and end.get("sum_received"):
        res.update(summary(end, args.proto, secs))
    else:
        res["error"] = error or "no result from iperf3"


def sweep(args, res):
    fam = args.family
    rows = []
    server = peer_server(res, True) if args.peer_server else None
    h = health_start(args.iface)
    for frame in FRAMES:
        payload = max(frame - OVERHEAD[fam], MIN_PAYLOAD)
        frame = payload + OVERHEAD[fam]
        if stop["flag"]:
            break
        print("Frame     : %d B (UDP data %d B)" % (frame, payload), flush=True)
        end, error = iperf(res["target"], fam, "udp", args.rate, payload, args.time, args.reverse)
        if not end or not end.get("sum_received"):
            res["error"] = error or "no result from iperf3"
            break
        row = {"frame": frame, "payload": payload}
        row.update(summary(end, "udp", args.time))
        # iperf3 counts UDP data; the frame rate includes Ethernet, IP and UDP headers and the FCS
        row["frame_mbps"] = round((row["pps"] or 0) * frame * 8 / 1e6, 1)
        rows.append(row)
        out("SWEEP", row)
        time.sleep(1)
    if server and server.poll() is None:
        server.terminate()
    res.update(health_end(h, args.iface))
    res.update(sweep=rows, loop_server=bool(server))
    if rows:
        res.update(mbps=max(r["mbps"] for r in rows), lost_pct=max(r["lost_pct"] for r in rows), proto="udp")
    if args.csv and rows:
        with open(args.csv, "w", newline="") as f:
            f.write("# perf_test sweep %s %s to %s; ';' separated, '.' decimal\n"
                    % (res["family"], args.iface, res["target"]))
            w = csv.writer(f, delimiter=";")
            keys = ["frame", "payload", "mbps", "frame_mbps", "mbps_sent", "pps", "packets", "lost", "lost_pct",
                    "jitter_ms"]
            w.writerow(keys)
            for r in rows:
                w.writerow([r.get(k) for k in keys])


def main():
    p = argparse.ArgumentParser(description="Throughput, loss and jitter with iperf3")
    p.add_argument("iface")
    p.add_argument("target", nargs="?", default="auto")
    p.add_argument("-4", dest="family", action="store_const", const=4, default=4)
    p.add_argument("-6", dest="family", action="store_const", const=6)
    p.add_argument("--proto", choices=["tcp", "udp"], default="tcp")
    p.add_argument("-b", "--rate", type=int, default=100, help="UDP Mbit/s, 0 = as fast as possible")
    p.add_argument("-l", "--length", type=int, default=0, help="UDP payload bytes")
    p.add_argument("-t", "--time", type=int, default=10)
    p.add_argument("-R", "--reverse", action="store_true")
    p.add_argument("--sweep", action="store_true", help="UDP over the RFC 2544 frame sizes")
    p.add_argument("--peer-server", action="store_true", help="start the receiver on the other port on the loop")
    p.add_argument("--force", action="store_true", help="measure a target outside the test bench")
    p.add_argument("--csv")
    args = p.parse_args()

    if os.geteuid() != 0:
        print("Error: root privileges required")
        return 1
    if not os.path.exists("/sys/class/net/%s" % args.iface):
        print("Error: interface %s not found in this namespace" % args.iface)
        return 2
    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    print("=== Performance test%s, IPv%d ===" % (" sweep" if args.sweep else "", args.family), flush=True)
    res = resolve(args.iface, args.family, None if args.target == "auto" else args.target)
    res.update(proto="udp" if args.sweep else args.proto, reverse=args.reverse, rate_mbps=args.rate,
               secs=args.time, mode="sweep" if args.sweep else "single", aborted=False)
    print("Interface : %s" % args.iface)
    if not res["target"]:
        res["verdict"] = "FAIL"
    elif not in_stand(res["target"]) and (args.sweep or not args.force):
        res.update(verdict="FAIL", short="target outside the test bench",
                   reason="%s is not a test bench address; RFC 6815: benchmarks only on an isolated network"
                          % bare(res["target"]),
                   hint="the sweep never runs there; a single test needs confirmation")
    else:
        print("Target    : %s" % res["target"])
        print("Found by  : %s" % res["source"])
        print("Peer      : %s" % res["peer"], flush=True)
        (sweep if args.sweep else single)(args, res)
        if not res.get("mac"):
            res["mac"] = mac_of(args.iface, args.family, res["target"])
        if stop["flag"]:
            res["verdict"] = "STOPPED"
        else:
            verdict(res)
    res["aborted"] = stop["flag"]
    for key in ("reason", "hint"):
        if res.get(key):
            print("%-10s: %s" % (key.capitalize(), res[key]))
    out("RESULT perf_test", res)
    return 2 if str(res.get("reason", "")).startswith("no link") else 0


if __name__ == "__main__":
    sys.exit(main())
