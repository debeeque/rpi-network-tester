import re
import subprocess
import threading
import time
import tkinter as tk

import results
from screens import FunctionScreen
from ui_kit import BOTTOM, C, ELL, G, M, PORTS, W, font

LISTEN_S = 65
HEARD = re.compile(r"^HEARD (\S+) (\S+) (\S+) (.*)")


def clip(value, n=26):
    value = str(value)
    return value if len(value) <= n else value[:n - 1] + ELL


def modes(names):
    out = []
    for name in names or []:
        speed, _, duplex = name.partition("/")
        digits = "".join(ch for ch in speed.split("base")[0] if ch.isdigit())
        if digits:
            out.append((int(digits), duplex[:1]))
    return " ".join("%d%s" % m for m in sorted(set(out), key=lambda m: (-m[0], m[1] != "F"))) or "--"


class PortScreen(FunctionScreen):
    def __init__(self, app):
        super().__init__(app, "PORT")
        y = self.body
        h = BOTTOM - y
        pw = (W - 2 * M - G) // 2
        self.ph = h
        self.left = tk.Canvas(self, width=pw, height=h, bg=C["panel"], highlightthickness=0, cursor="none")
        self.left.place(x=M, y=y)
        self.rw = W - 2 * M - pw - G
        self.right = tk.Canvas(self, width=self.rw, height=h, bg=C["panel"], highlightthickness=0, cursor="none")
        self.right.place(x=M + pw + G, y=y)
        self.link = {}
        self.read_at = {}
        self.neigh = {}
        self.heard = {p: [] for p in PORTS}
        self.listening = None
        self.listen_start = 0
        self.reading = set()
        self.sending = False
        self.sent = {}
        self.last_state = {}
        self.watching = False
        self.bottom([("check", "CHECK", C["go"], self.check, 100),
                     ("listen", "LISTEN", C["action"], self.listen, 100),
                     ("hello", "HELLO", "#EF6C00", self.hello, 100)])

    # --- link ------------------------------------------------------------

    def shown(self):
        self.render()
        for port in sorted(PORTS, key=lambda p: p != self.port):
            self.read(port)
        if not self.watching:
            self.watching = True
            self.watch()

    def select_port(self, name):
        super().select_port(name)
        if hasattr(self, "left"):
            self.render()

    # Plug and unplug events come through ports.json from analyzer-status.service
    def watch(self):
        if self.app.current != "PORT":
            self.watching = False
            return
        ports = self.app.port_state().get("ports", {})
        for port in PORTS:
            p = ports.get(port, {})
            key = (p.get("present"), p.get("carrier"), p.get("speed"), p.get("duplex"))
            if port in self.last_state and self.last_state[port] != key:
                self.read(port)
            self.last_state[port] = key
        if self.listening and self.listening not in self.app.jobs:
            self.listening = None
            self.render()
        elif self.listening == self.port:
            self.draw_right()
        self.after(500, self.watch)

    def read(self, port, save=False):
        if port in self.reading:
            return
        self.reading.add(port)
        cfg = self.app.PORTS[port]
        cmd = ["sudo", "ip", "netns", "exec", cfg["ns"], "python3", "port_info.py", cfg["iface"]]

        def task():
            try:
                out = subprocess.run(cmd, capture_output=True, text=True, timeout=15).stdout
            except (OSError, subprocess.SubprocessError):
                out = ""
            res = results.parse_result(out, "port_info")
            if res is None:
                res = {"iface": port, "present": False, "link": False, "verdict": "FAIL",
                       "short": "adapter not plugged in"}
            self.app.ui(self.got_link, port, res, save)

        threading.Thread(target=task, daemon=True).start()

    def got_link(self, port, res, save):
        self.reading.discard(port)
        self.link[port] = res
        self.read_at[port] = time.strftime("%H:%M:%S")
        if save:
            self.app.save_result("port_info.py", port, res)
        if port == self.port:
            self.render()

    def check(self):
        self.read(self.port, save=True)

    # --- L2 neighbours -----------------------------------------------------

    def listen(self):
        port = self.port
        cfg = self.app.PORTS[port]
        cmd = ["python3", "l2_listen.py", cfg["iface"], "-t", str(LISTEN_S)]
        own = self.app.device_macs()
        if own:
            cmd += ["--own", own]
        self.heard[port] = []
        self.neigh.pop(port, None)
        if self.launch("listen", self.netns(cmd), "listening for LLDP and CDP on %s, up to %d s" % (port, LISTEN_S),
                       lambda rc, out, res: self.listen_done(port, res), script="l2_listen.py"):
            self.listening = port
            self.listen_start = time.monotonic()
            self.render()

    def show_line(self, line):
        m = HEARD.match(line.strip())
        if m and self.listening:
            self.heard[self.listening].append(m.groups())
            if self.listening == self.port:
                self.draw_right()

    def listen_done(self, port, res):
        self.listening = None
        if res:
            res["end_wall"] = time.time()
            self.neigh[port] = res
        else:
            self.set_verdict("FAIL", "listener gave no result on %s" % port)
        self.render()

    def hello(self):
        if self.sending:
            return
        port = self.port
        cfg = self.app.PORTS[port]
        cmd = self.netns(["python3", "l2_listen.py", cfg["iface"], "--hello", "-t", "0"])
        self.sending = True
        self.set_verdict("RUNNING", "sending one LLDP frame from %s" % port)

        def task():
            try:
                out = subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout
            except (OSError, subprocess.SubprocessError):
                out = ""
            self.app.ui(self.hello_done, port, results.parse_result(out, "l2_listen"))

        threading.Thread(target=task, daemon=True).start()

    def hello_done(self, port, res):
        self.sending = False
        if not res or not res.get("hello"):
            self.set_verdict("FAIL", (res or {}).get("short") or "LLDP frame not sent from %s" % port)
            return
        self.app.save_result("l2_listen.py", port, res)
        h = res["hello"]
        self.sent[port] = "Sent LLDP at %s, kept %d s" % (time.strftime("%H:%M:%S"), h["ttl"])
        if port == self.port:
            self.draw_right()
        self.set_verdict("INFO", "LLDP sent from %s: %s, port %s, TTL %d" % (port, h["system_name"], h["port_id"],
                                                                           h["ttl"]))

    # --- drawing -----------------------------------------------------------

    def render(self):
        self.draw_left()
        self.draw_right()
        if self.port in self.app.jobs or self.sending:
            return
        r = self.link.get(self.port)
        if r is None:
            self.set_verdict("RUNNING", "reading %s" % self.port)
            return
        word = r.get("verdict", "FAIL")
        if r.get("link") and word == "PASS":
            text = "%s %s on %s" % (r.get("speed"), (r.get("duplex") or "").lower(), self.port)
        else:
            text = "%s on %s" % (r.get("short", ""), self.port)
        n = self.best(self.port)
        if n and r.get("link") and word == "PASS":
            text += ", %s %s port %s" % ("this device" if n["origin"] == "THIS DEVICE" else "switch",
                                         clip(n.get("system_name") or n.get("chassis_id") or "?", 18),
                                         clip(n.get("port_id", "?"), 14))
        self.set_verdict(word, clip(text, 58))
        tile = "%s %s" % (r.get("speed"), (r.get("duplex") or "")[:4].lower()) if r.get("link") else "no link"
        self.app.note("PORT", word, " " + tile, "")

    def rows(self, c, title, rows, kx):
        c.delete("all")
        c.create_text(14, 8, text=title, font=font(14, True), fill=C["muted"], anchor="nw")
        for i, (k, v, color) in enumerate(rows):
            y = 36 + i * 30
            if k:
                c.create_text(14, y, text=k, font=font(16), fill=C["muted"], anchor="nw")
                c.create_text(kx, y, text=v, font=font(16, color != "muted"), fill=C[color], anchor="nw")
            else:
                c.create_text(14, y, text=v, font=font(16), fill=C[color], anchor="nw")

    def draw_left(self):
        r = self.link.get(self.port)
        title = "LINK  read from the adapter"
        if r is None:
            self.rows(self.left, title, [("", "reading " + ELL, "muted")], 110)
            return
        title += " at %s" % self.read_at.get(self.port, "")
        if not r.get("present"):
            self.rows(self.left, title, [("Link", "adapter not plugged in", "bad")], 110)
            return
        if not r.get("link"):
            link, color = "down: no cable or other end off", "bad"
        else:
            link = "up, %s Mb/s, %s duplex" % (r.get("speed"), (r.get("duplex") or "?").lower())
            color = "good" if r.get("duplex") == "Full" else "warn"
        best = r.get("best_common")
        slow = bool(best and r.get("speed") and r["speed"] < best[0])
        if not r.get("autoneg"):
            auto, acolor = "off", "warn"
        elif r.get("partner_autoneg") is False:
            auto, acolor = "on, other end fixed", "warn"
        elif r.get("link"):
            auto, acolor = "on, both sides", "text"
        else:
            auto, acolor = "on", "text"
        err = r.get("errors_new") or 0
        missed = r.get("missed_new") or 0
        errors = "%d new, %d missed" % (err, missed) if err or missed else "0 new since last check"
        fw = (r.get("firmware") or "").split(" ")[0]
        rows = [("Link", clip(link, 30), color),
                ("Autoneg", auto, acolor),
                ("Partner", modes(r.get("partner")) if r.get("link") else "--", "warn" if slow else "text"),
                ("This port", modes(r.get("advertised")), "text"),
                ("Link drops", "%s new, %s since boot" % (r.get("drops_new"), r.get("carrier_down_count")), "text"),
                ("Errors", errors, "warn" if err or missed else "text"),
                ("Adapter", clip("%s, %s" % (r.get("driver"), fw), 28), "muted"),
                ("MAC", r.get("mac") or "--", "muted")]
        self.rows(self.left, title, rows, 110)

    def best(self, port):
        res = self.neigh.get(port) or {}
        found = res.get("neighbors") or []
        foreign = [n for n in found if n.get("origin") == "FOREIGN"]
        return (foreign or found or [None])[0]

    def own_port(self, mac):
        for name, p in self.app.port_state().get("ports", {}).items():
            if p.get("mac") == mac:
                return name
        return "other port"

    def also(self, res):
        out = []
        if res.get("stp"):
            s = res["stp"][0]
            out.append("%s, root %s" % (s["version"], s["root"]))
        if res.get("lacp"):
            out.append("LACP")
        if res.get("vlans"):
            out.append("tagged VLAN " + ",".join(sorted(res["vlans"], key=int)[:4]))
        return out

    def draw_right(self):
        c = self.right
        port = self.port
        if self.listening == port:
            heard = self.heard.get(port, [])
            lines = [("LLDP comes every 30 s,", "text"), ("CDP every 60 s.", "text"), ("", "text"),
                     ("Heard so far:", "muted")]
            lines += [(clip("%s %s" % (h[0], h[3]), 30), "muted") for h in heard[-3:]]
            if not heard:
                lines.append(("no LLDP or CDP yet", "muted"))
            self.rows(c, "SWITCH  listening, sending nothing", [("", t, col) for t, col in lines], 100)
            frac = min(1.0, (time.monotonic() - self.listen_start) / LISTEN_S)
            c.create_rectangle(14, self.ph - 20, 14 + int((self.rw - 28) * frac), self.ph - 12,
                               fill=C["accent"], width=0)
            return
        res = self.neigh.get(port)
        if res is None:
            lines = ["Press LISTEN: the device listens", "up to %d s and sends nothing." % LISTEN_S, "",
                     "HELLO sends one LLDP frame:", "the switch learns this device", "and may answer sooner."]
            if self.heard.get(port):
                lines = ["Stopped. Heard before STOP:"] + [clip("%s %s" % (h[0], h[3]), 30)
                                                        for h in self.heard[port][-4:]]
            rows = [("", t, "muted") for t in lines]
            if port in self.sent:
                rows += [("", "", "text"), ("", self.sent[port], "warn")]
            self.rows(c, "SWITCH", rows, 100)
            return
        n = self.best(port)
        if n is None:
            lines = [("No LLDP or CDP in %d s:" % res.get("listened_s", LISTEN_S), "text"),
                     ("the switch does not send them", "text"), ("or they are turned off.", "text"), ("", "text")]
            lines += [(clip("Heard: " + a, 30), "muted") for a in self.also(res)]
            self.rows(c, "SWITCH  nothing heard", [("", t, col) for t, col in lines], 100)
            return
        ago = max(0, res.get("listened_s", 0) - n.get("at_s", 0))
        at = time.strftime("%H:%M:%S", time.localtime(res["end_wall"] - ago))
        if n["origin"] == "THIS DEVICE":
            title = "NEIGHBOUR  this device, %s, %s" % (self.own_port(n["mac"]), n["proto"])
        else:
            title = "SWITCH  %s, heard at %s" % (n["proto"], at)
        port_text = n.get("port_id", "--")
        if n.get("port_descr") and n["port_descr"] != port_text:
            port_text += " (%s)" % n["port_descr"]
        rows = [("Name", clip(n.get("system_name") or "--"), "text"),
                ("Port", clip(port_text), "text"),
                ("VLAN", str(n["vlan"]) if n.get("vlan") is not None else "not sent", "text"),
                ("Mgmt IP", clip(", ".join(n.get("mgmt") or []) or "not sent"), "text"),
                ("Model", clip(n.get("platform") or n.get("system_descr") or "--", 28), "muted"),
                ("Chassis", clip(n.get("chassis_id") or n.get("mac") or "--", 28), "muted"),
                ("TTL", "%s s" % n.get("ttl", "--"), "muted")]
        also = self.also(res)
        if also:
            rows.append(("Also", clip("; ".join(also), 28), "muted"))
        self.rows(c, title, rows, 100)
