import json
import os
import time
import tkinter as tk

import results
from screens import FunctionScreen
from ui_kit import BOTTOM, C, G, M, MID, PORTS, RIGHT, TOP, VERDICT_H, W, button, font, short

RATES = [(10, "10 Mbit/s"), (100, "100 Mbit/s"), (200, "200 Mbit/s"), (400, "400 Mbit/s"), (0, "max")]
TIMES = [5, 10, 30]
MONO = "DejaVu Sans Mono"


def num(n, digits=0):
    if n is None:
        return "--"
    return "{:,.{}f}".format(n, digits).replace(",", " ")


class SpeedScreen(FunctionScreen):
    """iperf3 through perf_test.py and perf_server.py; the numbers come from iperf3's JSON."""

    def __init__(self, app):
        super().__init__(app, "SPEED")
        self.proto, self.family, self.rate, self.secs, self.reverse = "udp", "v4", 1, 1, False
        self.to_found = False
        self.res, self.live, self.server, self.confirm = None, None, None, None
        y = self.body
        bw = (W - 2 * M - 3 * G) // 4
        self.sel = {}
        for i, (key, text) in enumerate((("tcp", "TCP"), ("udp", "UDP"), ("v4", "IPv4"), ("v6", "IPv6"))):
            self.sel[key] = button(self, M + i * (bw + G), y, bw, 64, text, C["panel2"],
                                   lambda k=key: self.pick(k), "secondary", 17)
        y += 64 + G
        self.params = {}
        for i, key in enumerate(("rate", "time", "dir", "to")):
            self.params[key] = button(self, M + i * (bw + G), y, bw, 64, "", C["panel"],
                                      lambda k=key: self.cycle(k), "secondary", 16)
        y += 64 + G
        self.canvas = tk.Canvas(self, width=W - 2 * M, height=BOTTOM - y, bg=C["panel"], highlightthickness=0,
                                cursor="none")
        self.canvas.place(x=M, y=y)
        self.bottom([("start", "START", C["go"], self.start, 120),
                     ("sweep", "SWEEP", C["action"], lambda: app.open("SWEEP"), 110),
                     ("server", "SERVER", "#546E7A", self.toggle_server, 110)])
        self.set_verdict("IDLE", "choose the test and tap START")
        self.refresh()

    # --- parameters -------------------------------------------------------

    def busy(self):
        return self.live is not None or self.server is not None

    def pick(self, key):
        if self.busy():
            return
        if key in ("tcp", "udp"):
            self.proto = key
        else:
            self.family = key
        self.to_found = False
        self.refresh()

    def found(self):
        return self.app.found.get(self.port, {}).get(self.family)

    def cycle(self, key):
        if self.busy():
            return
        if key == "rate" and self.proto == "udp":
            self.rate = (self.rate + 1) % len(RATES)
        elif key == "time":
            self.secs = (self.secs + 1) % len(TIMES)
        elif key == "dir":
            self.reverse = not self.reverse
        elif key == "to":
            self.to_found = not self.to_found and bool(self.found())
        self.confirm = None
        self.refresh()

    def select_port(self, name):
        if self.busy():
            return
        super().select_port(name)
        self.to_found = False
        if hasattr(self, "params"):
            self.refresh()

    def shown(self):
        self.refresh()

    def refresh(self):
        for key, b in self.sel.items():
            on = key in (self.proto, self.family)
            b.config(bg=C["sel"] if on else C["panel2"], activebackground=C["sel"] if on else C["panel2"])
        udp = self.proto == "udp"
        self.params["rate"].config(text="RATE\n" + (RATES[self.rate][1] if udp else "max (TCP)"),
                                   fg="white" if udp else C["dim"])
        self.params["time"].config(text="TIME\n%d s" % TIMES[self.secs])
        self.params["dir"].config(text="DIRECTION\n" + ("host %s device" if self.reverse else "device %s host")
                                  % RIGHT)
        target = self.found() if self.to_found else None
        self.params["to"].config(text="TO\n" + (short(target) if target else "auto"))
        if not self.busy():
            self.draw()

    # --- test -------------------------------------------------------------

    def target(self):
        return self.found() if self.to_found and self.found() else "auto"

    def command(self, force=None):
        cfg = self.app.PORTS[self.port]
        cmd = ["python3", "perf_test.py", cfg["iface"], force or self.target(), "-" + self.family[1],
               "--proto", self.proto, "-t", str(TIMES[self.secs]), "--peer-server"]
        if self.proto == "udp":
            cmd += ["-b", str(RATES[self.rate][0])]
        if self.reverse:
            cmd.append("-R")
        if force:
            cmd.append("--force")
        return self.netns(cmd)

    def start(self):
        force = None
        if self.confirm and time.monotonic() < self.confirm[1]:
            force = self.confirm[0]
        self.confirm = None
        desc = "%s %s, %s" % (self.proto.upper(), self.family, self.target() if not force else force)
        self.res, self.live, self.last_server = None, {"t": 0, "mbps": None, "desc": desc}, None
        self.draw()
        if not self.launch("start", self.command(force), "iperf3 " + desc, self.done, script="perf_test.py"):
            self.live = None

    def show_line(self, line):
        if line.startswith("PROGRESS ") and self.live is not None:
            try:
                p = json.loads(line[9:])
            except ValueError:
                return
            self.live.update(p)
            job = self.app.jobs.get(self.port)
            if job:
                job["label"] = "%s, %s Mbit/s" % (self.live["desc"], num(p["mbps"], 1))
            self.draw()
            return
        super().show_line(line)

    def idle(self, key):
        super().idle(key)
        if key == "start":
            self.live = None
            self.draw()

    def done(self, rc, out, res):
        self.res = res
        if not res:
            self.set_verdict("FAIL", "no result, see the log")
            self.app.note("SPEED", "FAIL", "", "")
            return
        word = res.get("verdict", "FAIL")
        fam = res.get("family", "")
        if res.get("short") == "target outside the test bench" and res.get("target"):
            self.confirm = (res["target"], time.monotonic() + 6)
            self.set_verdict("WARN", "%s is outside the test bench: tap START again" % short(res["target"]))
        elif res.get("mbps") is not None and not res.get("error"):
            text = "%s Mbit/s %s %s" % (num(res["mbps"], 1), res["proto"].upper(), fam)
            if res["proto"] == "udp":
                text += ", %s %% lost, jitter %s ms" % (num(res.get("lost_pct"), 2 if res.get("lost_pct") else 0),
                                                         num(res.get("jitter_ms"), 2))
            self.set_verdict(word, text)
            self.app.note("SPEED", word, " %s Mbit/s" % num(res["mbps"], 1), " %s %s" % (res["proto"].upper(), fam))
        else:
            self.set_verdict(word, res.get("short") or res.get("reason") or "no result")
            self.app.note("SPEED", word, "", " " + fam)
        self.draw()

    # --- server -----------------------------------------------------------

    def toggle_server(self):
        if self.server is not None:
            self.app.stop(self.server["port"])
            return
        if self.live is not None:
            return
        port = self.port
        busy = self.app.jobs.get(port)
        if busy:
            self.set_verdict("BUSY", "%s is running %s" % (port, busy["label"]))
            return
        cfg = self.app.PORTS[port]
        self.server = {"port": port, "addrs": [], "sessions": []}
        self.running("server", lambda: self.app.stop(port))
        for key in ("start", "sweep"):
            self.actions[key].config(bg=C["dim"], activebackground=C["dim"], command=lambda: None)
        self.log("-" * 60)
        self.log("%s  iperf3 server on %s" % (time.strftime("%H:%M:%S"), port))
        self.draw()
        self.app.run(port, self.netns(["python3", "perf_server.py", cfg["iface"]]), "server on " + port, self,
                     on_line=self.server_line, on_done=self.server_done, keep=200)

    def server_line(self, line):
        s = self.server
        if s is None:
            return
        kind, _, data = line.partition(" ")
        if kind in ("ADDRS", "SESSION"):
            try:
                d = json.loads(data)
            except ValueError:
                return
            if kind == "ADDRS":
                s["addrs"] = d["addrs"]
            else:
                s["sessions"].append(d)
                job = self.app.jobs.get(s["port"])
                if job:
                    job["label"] = "server on %s, %d test%s served" % (s["port"], len(s["sessions"]),
                                                                       "" if len(s["sessions"]) == 1 else "s")
            self.draw()
        elif not line.startswith("RESULT "):
            self.log(line)

    def server_done(self, rc, out, stopped):
        s, self.server = self.server, None
        self.idle("server")
        for key in ("start", "sweep"):
            self.idle(key)
        res = results.parse_result(out, "perf_server")
        if res is not None:
            path = self.app.save_result("perf_server.py", s["port"], res)
            if path:
                self.log("Saved %s" % path.replace("/home/muk0015/", "~/"))
        n = len(s["sessions"])
        if res and res.get("verdict") == "FAIL":
            self.set_verdict("FAIL", res.get("reason", "server failed"))
        else:
            self.set_verdict("INFO", "server on %s stopped, %d test%s served" % (s["port"], n, "" if n == 1 else "s"))
        self.app.note("SPEED", "INFO", " server", ", %d served" % n)
        self.res = None
        self.last_server = s
        self.draw()

    # --- drawing ----------------------------------------------------------

    def draw(self):
        c = self.canvas
        c.delete("all")
        h = int(c.cget("height"))
        if self.server is not None or (getattr(self, "last_server", None) and self.res is None and not self.live):
            self.draw_server(c, self.server or self.last_server)
            return
        res = self.res or {}
        live = self.live
        if res.get("mbps") is None and res.get("verdict") in ("FAIL", "WARN") and not live:
            c.create_text(14, 10, text=res.get("reason") or res.get("short") or "", font=font(16), fill=C["text"],
                          anchor="nw", width=W - 2 * M - 28)
            if res.get("hint"):
                c.create_text(14, 66, text=res["hint"], font=font(16), fill=C["warn"], anchor="nw",
                              width=W - 2 * M - 28)
            return
        udp = (res.get("proto") or self.proto) == "udp"
        mbps = live["mbps"] if live else res.get("mbps")
        if udp:
            cells = (("THROUGHPUT", num(mbps, 1), "Mbit/s"), ("PACKETS", num(res.get("pps")), "pkt/s"),
                     ("LOST", num(res.get("lost")), "%s %%" % num(res.get("lost_pct"), 2) if res else ""),
                     ("JITTER", num(res.get("jitter_ms"), 2), "ms"))
        else:
            cells = (("THROUGHPUT", num(mbps, 1), "Mbit/s"), ("SENT", num(res.get("mbps_sent"), 1), "Mbit/s"),
                     ("RETRANSMITS", num(res.get("retransmits")), "segments"),
                     ("CPU", num(res.get("cpu_pct")), "% of the device"))
        cw = (W - 2 * M - 28) // 4
        for i, (label, value, unit) in enumerate(cells):
            x = 14 + i * cw
            c.create_text(x, 8, text=label, font=font(14, True), fill=C["muted"], anchor="nw")
            c.create_text(x, 28, text=value, font=font(30, True), fill=C["text"], anchor="nw")
            c.create_text(x, 66, text=unit, font=font(14), fill=C["muted"], anchor="nw")
        if res.get("target"):
            thr = "throttled!" if res.get("throttled_now") else "no throttling"
            tail = "   CPU %s %%   SoC %s %s %s C, %s" % (num(res.get("cpu_pct")), num(res.get("temp_start")), RIGHT,
                                                          num(res.get("temp_end")), thr)
            line = "to %s %s (%s)" % (res.get("peer") or "", short(res["target"]), res.get("source", "").split(" of ")[0])
            if len(line + tail) > 92:
                line = "to %s %s" % (res.get("peer") or "", short(res["target"]))
            line += tail
            c.create_text(14, 100, text=line, font=font(14), fill=C["muted"], anchor="nw", width=W - 2 * M - 28)
        if live:
            total = TIMES[self.secs]
            c.create_rectangle(14, h - 12, W - 2 * M - 14, h - 6, fill=C["line"], width=0)
            c.create_rectangle(14, h - 12, 14 + (W - 2 * M - 28) * min(1, live["t"] / total), h - 6,
                               fill=C["accent"], width=0)

    def draw_server(self, c, s):
        running = self.server is not None
        c.create_text(14, 8, text="Waiting for iperf3 clients on %s. On the other computer run:" % s["port"]
                      if running else "Server on %s stopped. Tests it served:" % s["port"],
                      font=font(16), fill=C["muted"], anchor="nw")
        if running:
            addrs = [a for a in s["addrs"] if ":" not in a][:1] + [a for a in s["addrs"] if ":" in a][:1]
            c.create_text(14, 34, text="      ".join("iperf3 -c " + a for a in addrs), font=font(22, True, MONO),
                          fill=C["text"], anchor="nw")
        for i, d in enumerate(reversed(s["sessions"][-2:])):
            text = "%s: %s  %s%s  %s Mbit/s  %s s" % ("last" if i == 0 else "before", d.get("client"),
                                                      d.get("proto", "").upper(), " -R" if d.get("reverse") else "",
                                                      num(d.get("mbps"), 1), d.get("secs"))
            if d.get("proto") == "udp":
                text += "  %s %% lost" % num(d.get("lost_pct"), 2 if d.get("lost_pct") else 0)
            c.create_text(14, 76 + i * 26 if running else 40 + i * 26, text=text, font=font(16),
                          fill=C["text"] if i == 0 else C["muted"], anchor="nw")


class SweepScreen(FunctionScreen):
    """UDP over the RFC 2544 frame sizes, device to host, as fast as possible, 10 s per size."""

    def __init__(self, app):
        super().__init__(app, "SPEED " + MID + " SWEEP")
        self.rows, self.running_fam, self.frame = [], None, None
        self.canvas = tk.Canvas(self, width=W - 2 * M, height=BOTTOM - self.body, bg=C["panel"],
                                highlightthickness=0, cursor="none")
        self.canvas.place(x=M, y=self.body)
        self.bottom([("v4", "SWEEP v4", C["action"], lambda: self.start("v4"), 130),
                     ("v6", "SWEEP v6", "#00695C", lambda: self.start("v6"), 130)],
                    back=lambda: app.open("SPEED"))
        self.set_verdict("IDLE", "7 frame sizes, about 1 min 20 s")
        self.draw()

    def shown(self):
        speed = self.app.screens.get("SPEED")
        if speed is not None and not self.running_fam:
            self.select_port(speed.port)
        self.draw()

    def select_port(self, name):
        if not getattr(self, "running_fam", None):
            super().select_port(name)

    def start(self, fam):
        if self.running_fam:
            return
        speed = self.app.screens.get("SPEED")
        target = "auto"
        if speed is not None and speed.to_found and speed.family == fam and speed.found():
            target = speed.found()
        cfg = self.app.PORTS[self.port]
        cmd = self.netns(["python3", "perf_test.py", cfg["iface"], target, "-" + fam[1], "--sweep", "-b", "0",
                          "-t", "10", "--peer-server"])
        self.rows, self.frame, self.t0 = [], None, time.monotonic()
        if self.launch(fam, cmd, "sweep UDP %s to %s" % (fam, target), lambda rc, out, res: self.done(fam, res),
                       script="perf_test.py"):
            self.running_fam = fam
        self.draw()

    def show_line(self, line):
        if line.startswith("SWEEP "):
            try:
                self.rows.append(json.loads(line[6:]))
            except ValueError:
                pass
            self.draw()
        elif line.startswith("Frame "):
            self.frame = line.split(":", 1)[1].strip()
            job = self.app.jobs.get(self.port)
            if job:
                job["label"] = "frame %s, %d of 7" % (self.frame.split(" (")[0], len(self.rows) + 1)
            super().show_line(line)
            self.draw()
        elif not line.startswith("PROGRESS "):
            super().show_line(line)

    def done(self, fam, res):
        self.running_fam = None
        if not res:
            self.set_verdict("FAIL", "no result, see the log")
            return
        rows = res.get("sweep") or []
        if rows:
            self.save_csv(res, rows)
        secs = int(time.monotonic() - self.t0)
        if res.get("verdict") in ("PASS", "WARN") and rows:
            self.set_verdict(res["verdict"], "UDP %s, %d frame sizes in %d min %02d s" % (fam, len(rows), secs // 60,
                                                                                     secs % 60))
        else:
            self.set_verdict(res.get("verdict", "FAIL"), res.get("short") or res.get("reason") or "no result")
        self.app.note("SPEED", res.get("verdict", "FAIL"), " sweep", " " + fam)
        self.draw()

    def idle(self, key):
        super().idle(key)
        self.running_fam = None

    def save_csv(self, res, rows):
        day = time.strftime("%Y%m%d")
        folder = os.path.join(results.RESULTS_DIR, day)
        path = os.path.join(folder, "%s_perf_sweep_%s_%s.csv" % (time.strftime("%H%M%S"), self.port, res["family"]))
        keys = ["frame", "payload", "mbps", "frame_mbps", "pps", "lost", "lost_pct", "jitter_ms"]
        try:
            os.makedirs(folder, exist_ok=True)
            with open(path, "w") as f:
                f.write("# UDP sweep %s %s to %s; ';' separated, '.' decimal\n" % (res["family"], self.port,
                                                                                  res.get("target")))
                f.write(";".join(keys) + "\n")
                for r in rows:
                    f.write(";".join(str(r.get(k, "")) for k in keys) + "\n")
            self.log("Saved %s" % path.replace("/home/muk0015/", "~/"))
        except OSError as e:
            self.log("CSV not saved: %s" % e)

    def draw(self):
        c = self.canvas
        c.delete("all")
        cols = [(14, "FRAME B"), (130, "UDP DATA"), (270, "Mbit/s"), (400, "pkt/s"), (540, "LOST"),
                (650, "JITTER ms")]
        for x, t in cols:
            c.create_text(x, 10, text=t, font=font(14, True), fill=C["muted"], anchor="nw")
        for r, row in enumerate(self.rows[:7]):
            lost = "%s %%" % num(row.get("lost_pct"), 2) if row.get("lost_pct") else "0"
            vals = (row["frame"], row["payload"], num(row.get("mbps"), 1), num(row.get("pps")), lost,
                    num(row.get("jitter_ms"), 2))
            for (x, _), val in zip(cols, vals):
                color = C["warn"] if val == lost and lost != "0" else C["text"]
                c.create_text(x, 38 + r * 31, text=str(val), font=font(19, family=MONO), fill=color, anchor="nw")
        if self.running_fam and self.frame:
            c.create_text(14, 38 + len(self.rows) * 31, text="%s %s" % (self.frame, chr(0x2026)),
                          font=font(19, family=MONO), fill=C["accent"], anchor="nw")
        c.create_text(14, 38 + 7 * 31 + 6, text="device %s host, as fast as possible, 10 s per size; saved as CSV "
                      "and JSON" % RIGHT, font=font(14), fill=C["muted"], anchor="nw")
