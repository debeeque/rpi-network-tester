import argparse
import json
import os
import re
import signal
import subprocess
import sys

from targets import mac_of, resolve

stop = {"flag": False, "proc": None}


def on_signal(signum, frame):
    stop["flag"] = True
    if stop["proc"] and stop["proc"].poll() is None:
        stop["proc"].send_signal(signal.SIGINT)


def ping(res, count):
    fam = res["family"][1]
    cmd = ["ping", "-" + fam, "-n", "-c", str(count), "-i", "0.5", "-W", "2", res["target"]]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    stop["proc"] = proc
    lines = []
    for line in proc.stdout:
        lines.append(line)
        print(line.rstrip(), flush=True)
    proc.wait()
    out = "".join(lines)
    got = re.search(r"(\d+) packets transmitted, (\d+) received", out)
    rtt = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)/", out)
    sent, recv = (int(got.group(1)), int(got.group(2))) if got else (0, 0)
    res.update(sent=sent, received=recv, loss_pct=round(100.0 * (sent - recv) / sent, 1) if sent else None)
    if rtt:
        res.update(rtt_min=float(rtt.group(1)), rtt_avg=float(rtt.group(2)), rtt_max=float(rtt.group(3)))
    if recv and recv == sent:
        res["verdict"] = "PASS"
    elif recv:
        res["verdict"] = "WARN"
        res["reason"] = res["short"] = "%d of %d replies lost" % (sent - recv, sent)
    else:
        res["verdict"] = "FAIL"
        res["reason"] = "%s did not answer" % res["target"]
        res["short"] = "no reply from the %s" % ("other port" if res.get("peer", "").endswith("(loop)") else "target")
        mac = res.get("mac") or mac_of(res["iface"], int(fam), res["target"])
        if res.get("peer", "").endswith("(loop)"):
            res["hint"] = "the other port of this device always answers: check its link"
        elif mac:
            res.update(mac=mac, short="host is there, ping is blocked",
                       reason="%s is on the cable (answered %s as %s) but not ping" % (
                           res["target"], "ARP" if fam == "4" else "ND", mac),
                       hint="a firewall blocks ping; Windows does so on a new network by default")
        else:
            res["hint"] = "the host may be off, or block ping as Windows does on a new network"


def main():
    parser = argparse.ArgumentParser(description="Reachability of a host on a test port")
    parser.add_argument("iface")
    parser.add_argument("target", nargs="?", default="auto")
    parser.add_argument("-4", dest="family", action="store_const", const=4, default=6)
    parser.add_argument("-6", dest="family", action="store_const", const=6)
    parser.add_argument("--mode", choices=["ping"], default="ping")
    parser.add_argument("-c", "--count", type=int, default=4)
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("Error: root privileges required")
        return 1
    if not os.path.exists("/sys/class/net/%s" % args.iface):
        print("Error: interface %s not found in this namespace" % args.iface)
        print("RESULT path_test " + json.dumps({"iface": args.iface, "verdict": "FAIL",
                                                  "reason": "no interface %s" % args.iface}))
        return 2
    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    print("=== Path test: %s, IPv%d ===" % (args.mode, args.family))
    res = resolve(args.iface, args.family, None if args.target == "auto" else args.target)
    res.update(mode=args.mode, aborted=False)
    print("Interface : %s" % args.iface)
    if res["target"]:
        print("Target    : %s" % res["target"])
        print("Found by  : %s" % res["source"])
        print("Peer      : %s" % res["peer"])
        if not stop["flag"]:
            ping(res, args.count)
    else:
        res["verdict"] = "FAIL"
        print("Target    : none")
    res["aborted"] = stop["flag"]
    if res.get("reason"):
        print("Reason    : %s" % res["reason"])
    if res.get("hint"):
        print("Hint      : %s" % res["hint"])
    print("RESULT path_test " + json.dumps(res, separators=(",", ":")))
    return 2 if res.get("reason", "").startswith("no link") else 0


if __name__ == "__main__":
    sys.exit(main())
