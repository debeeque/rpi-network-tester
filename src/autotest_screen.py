import json
import tkinter as tk

from screens import FunctionScreen
from ui_kit import BOTTOM, C, ELL, G, M, MID, PORTS, W, Screen, font

STEPS = ("LINK", "DHCPv4", "IPv6", "GATEWAY", "DNS", "TARGETS")
COLORS = {"PASS": "good", "WARN": "warn", "FAIL": "bad", "SKIP": "dim", "INFO": "text", "RUNNING": "accent"}
PROFILE = "/home/muk0015/diploma_project/profiles/default.json"


def clip(value, n):
    value = str(value)
    return value if len(value) <= n else value[:n - 1] + ELL


def profile_hint():
    try:
        with open(PROFILE) as f:
            prof = json.load(f)
    except (OSError, ValueError):
        prof = {}
    name = prof.get("dns_name", "www.vsb.cz")
    targets = prof.get("targets") or []
    target = "TCP to %s port %s" % (targets[0]["host"], targets[0].get("tcp", 443)) if targets else "none in profile"
    return name, target


class AutotestScreen(FunctionScreen):
    def __init__(self, app):
        super().__init__(app, "AUTOTEST")
        self.ch = BOTTOM - self.body
        self.canvas = tk.Canvas(self, width=W - 2 * M, height=self.ch, bg=C["panel"], highlightthickness=0,
                                cursor="none")
        self.canvas.place(x=M, y=self.body)
        self.steps = {p: {} for p in PORTS}
        self.lines = {p: [] for p in PORTS}
        self.result = {}
        self.active = None
        self.bottom([("start", "START", C["go"], self.start, 200),
                     ("details", "DETAILS", C["panel2"], lambda: app.open("AUTOTEST_LOG"), 120)])
        self.draw()

    def shown(self):
        self.draw()
        if self.port not in self.app.jobs:
            self.show_verdict()

    def select_port(self, name):
        super().select_port(name)
        if hasattr(self, "canvas"):
            self.draw()
            if name not in self.app.jobs:
                self.show_verdict()

    def start(self):
        port = self.port
        cfg = self.app.PORTS[port]
        cmd = ["python3", "autotest.py", cfg["iface"]]
        own = self.app.device_macs()
        if own:
            cmd += ["--own", own]
        self.steps[port] = {}
        self.lines[port] = []
        self.result.pop(port, None)
        if self.launch("start", self.netns(cmd), "autotest on %s" % port,
                       lambda rc, out, res: self.done(port, res), script="autotest.py"):
            self.active = port
            self.draw()

    def show_line(self, line):
        port = self.active
        if port is None:
            return
        line = line.rstrip("\n")
        if line.startswith("STEP "):
            try:
                item = json.loads(line[5:])
            except ValueError:
                return
            self.steps[port][item["step"]] = item
            job = self.app.jobs.get(port)
            if job and item["verdict"] == "RUNNING" and item["step"] in STEPS:
                job["label"] = "autotest on %s, step %d of %d" % (port, STEPS.index(item["step"]) + 1, len(STEPS))
            if port == self.port:
                self.draw()
        elif not line.startswith("RESULT "):
            self.lines[port].append(line)

    def done(self, port, res):
        self.active = None
        if res:
            self.result[port] = res
            for item in res.get("steps", []):
                self.steps[port][item["step"]] = item
            word = res.get("verdict", "FAIL")
            bad = [s for s in res.get("steps", []) if s.get("verdict") == word] if word != "PASS" else []
            self.app.note("AUTOTEST", word, " 6 steps" if word == "PASS" else " " + bad[0]["step"] if bad else "", "")
        if port == self.port:
            self.draw()
            self.show_verdict()

    def show_verdict(self):
        res = self.result.get(self.port)
        if self.active and self.active not in self.app.jobs:
            self.active = None
        if self.active and self.active != self.port:
            return
        if res is None:
            if not self.steps[self.port]:
                self.set_verdict("IDLE", "press START to test the socket on %s" % self.port)
            return
        word = res.get("verdict", "FAIL")
        if word == "PASS":
            text = "all steps passed on %s in %.1f s" % (self.port, res.get("seconds", 0))
        else:
            text = "%s on %s; %.1f s" % (res.get("short", ""), self.port, res.get("seconds", 0))
        self.set_verdict(word, clip(text, 58))

    def draw(self):
        c = self.canvas
        c.delete("all")
        rh = self.ch // len(STEPS)
        steps = self.steps.get(self.port, {})
        name, target = profile_hint()
        hints = {"LINK": "cable, speed, duplex", "DHCPv4": "who gives addresses; takes one and returns it",
                 "IPv6": "Router Advertisement, SLAAC address", "GATEWAY": "ping the gateway over IPv4 and IPv6",
                 "DNS": "ask the network's DNS server for %s" % name, "TARGETS": target}
        started = bool(steps) or self.active == self.port
        for i, step in enumerate(STEPS):
            y = i * rh
            if i:
                c.create_line(10, y, W - 2 * M - 10, y, fill=C["line"])
            item = steps.get(step)
            if item:
                word, color = item["verdict"], C[COLORS.get(item["verdict"], "text")]
                line1, line2, name_color = item.get("line1", ""), item.get("line2", ""), C["text"]
            elif started:
                word, color, line1, line2, name_color = "waiting", C["dim"], "", "", C["dim"]
            else:
                word, color, line1, line2, name_color = "", C["dim"], hints[step], "", C["muted"]
            c.create_text(14, y + 8, text=step, font=font(17, True), fill=name_color, anchor="nw")
            c.create_text(120, y + 8, text=word, font=font(17, True), fill=color, anchor="nw")
            c.create_text(232, y + 7, text=clip(line1, 56), font=font(16),
                          fill=C["text"] if item else C["muted"], anchor="nw")
            c.create_text(232, y + 27, text=clip(line2, 66), font=font(14), fill=C["muted"], anchor="nw")


class AutotestLogScreen(Screen):
    def __init__(self, app):
        super().__init__(app, "AUTOTEST " + MID + " DETAILS", ports=False)
        self.make_log(self.body)
        self.logbox.config(wrap="char")
        self.bottom([], back=lambda: app.open("AUTOTEST"))

    def shown(self):
        main = self.app.screens.get("AUTOTEST")
        port = main.active or main.port if main else None
        lines = main.lines.get(port, []) if main else []
        self.logbox.config(state="normal")
        self.logbox.delete("1.0", "end")
        self.logbox.config(state="disabled")
        for line in lines:
            self.log(line)
        self.logbox.see("1.0")
        res = main.result.get(port) if main else None
        if res:
            self.set_verdict(res.get("verdict", "INFO"), clip("%s: %s" % (port, res.get("short", "")), 58))
        else:
            self.set_verdict("INFO", "%s: %s" % (port, "running" if main and main.active else "no run yet"))
