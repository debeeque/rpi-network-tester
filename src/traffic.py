import collections
import hashlib
import json
import os
import shutil
import subprocess
import time
import tkinter as tk
from datetime import datetime

from ui_kit import (ARR, BOTTOM, BTN_H, BTN_Y, C, DOT, DOWN, G, LEFT, M, MID, MONO, PROTO, RIGHT, SIDE_W, TOP, UP,
                    W, Screen, button, font, short)

CAPTURE_DIR = "/tmp/traffic"
RESULTS_DIR = "/home/muk0015/results"
KEEP = 200
PER_PAGE = 5
# name, BPF expression (None: chosen host), text on the card
FILTERS = [
    ("ALL", "", "no filter"),
    ("TCP", "tcp", "tcp"),
    ("UDP", "udp", "udp"),
    ("ICMP", "icmp or icmp6", "icmp or icmp6"),
    ("ARP", "arp", "arp"),
    ("DHCP", "udp and (port 67 or port 68 or port 546 or port 547)", "udp port 67, 68, 546, 547"),
    ("ND / RA", "icmp6 and ip6[40] >= 133 and ip6[40] <= 137", "icmp6 types 133 to 137"),
    ("DNS", "port 53", "port 53"),
    ("HOST", None, "pick from top talkers"),
]
LAYER = {"Frame": "dim", "Ethernet": "accent", "802.1Q": "accent", "IPv4": "text", "IPv6": "text",
         "ARP": "text", "TCP": "text", "UDP": "text", "ICMP": "text", "ICMPv6": "text"}


def spaced(n):
    return "{:,}".format(n).replace(",", " ")


def human(n):
    for unit, div in (("GB", 1e9), ("MB", 1e6), ("KB", 1e3)):
        if n >= div:
            return "%.1f %s" % (n / div, unit)
    return "%d B" % n


def mbit(bps):
    v = bps / 1e6
    return "%.1f" % v if v < 100 else "%.0f" % v


def clip(text, n):
    return text if len(text) <= n else text[:n - 1] + chr(0x2026)


def tail(address):
    return chr(0x2026) + ":".join(address.split(":")[-2:]) if ":" in address else address


# Live feed column is narrow; the paused list and the detail page keep the full names
ABBREV = {"Router Advertisement": "RA", "Router Solicitation": "RS", "Neighbor Solicitation": "NS",
          "Neighbor Advertisement": "NA", "echo request": "echo", "echo reply": "reply", "Redirect": "redirect",
          "destination unreachable": "unreach", "time exceeded": "ttl exc"}


def pair_text(p, n):
    if not p["src"]:
        return ""
    text = "%s > %s" % (short(p["src"]), short(p["dst"]))
    return text if len(text) <= n else clip("%s > %s" % (tail(p["src"]), tail(p["dst"])), n)


def md5(path):
    with open(path, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()


def ntp_synced():
    try:
        return subprocess.run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"],
                              capture_output=True, text=True, timeout=3).stdout.strip() == "yes"
    except (OSError, subprocess.SubprocessError):
        return None


class TrafficScreen(Screen):
    """Live capture through sniff_stats.py; one JSON line per second, never one line per packet."""

    def __init__(self, app):
        self.running_port = self.cap_port = None
        super().__init__(app, "TRAFFIC")
        self.verdict_canvas.place_forget()
        self.canvas = tk.Canvas(self, width=W, height=BOTTOM - TOP, bg=C["bg"], highlightthickness=0, cursor="none")
        self.canvas.place(x=0, y=TOP)
        self.filter, self.host = FILTERS[0], None
        self.stats, self.last, self.message, self.after_stop = None, None, None, None
        self.last_top = []
        self.packets = collections.deque(maxlen=KEEP)
        self.bottom([("run", "START", C["go"], self.start, 118),
                     ("pause", "PAUSE", "#546E7A", lambda: app.open("PAUSED"), 108),
                     ("filter", "FILTER", C["action"], lambda: app.open("FILTER"), 108),
                     ("save", "SAVE", "#2E7D32", self.save, 100)])
        self.draw()

    def shown(self):
        self.draw()

    # --- capture control --------------------------------------------------

    def bpf(self):
        return "host " + self.host if self.filter[0] == "HOST" else self.filter[1]

    def filter_text(self):
        if self.filter[0] == "ALL":
            return "all traffic"
        return "host " + short(self.host) if self.filter[0] == "HOST" else self.filter[0]

    def start(self):
        port = self.port
        busy = self.app.jobs.get(port)
        if busy:
            self.message = ("BUSY", "warn", "%s: %s" % (port, clip(busy["label"], 16)))
            self.draw()
            return
        os.makedirs(CAPTURE_DIR, exist_ok=True)
        cfg = self.app.PORTS[port]
        base = os.path.join(CAPTURE_DIR, port)
        cmd = ["sudo", "ip", "netns", "exec", cfg["ns"], "python3", "sniff_stats.py", cfg["iface"],
               "--pcap", base + ".pcap", "--max-mb", "20", "--csv", base + ".csv", "--interval", "1", "--feed", "8"]
        if self.bpf():
            cmd += ["--bpf", self.bpf()]
        self.stats, self.message = None, None
        self.packets.clear()
        self.running_port = self.cap_port = port
        self.running("run", self.stop)
        self.app.note("TRAFFIC", "LIVE", "", " on %s" % port)
        self.app.run(port, cmd, "live capture on %s" % port, self, on_line=self.line, on_done=self.done, keep=20)
        self.sync_pages()
        self.draw()

    def stop(self):
        if self.running_port:
            self.app.stop(self.running_port)

    def restart(self):
        if self.running_port:
            self.after_stop = self.start
            self.stop()

    def select_port(self, name):
        super().select_port(name)
        if self.running_port and self.running_port != name:
            self.restart()

    def set_filter(self, entry, host=None):
        self.filter, self.host = entry, host
        self.restart()
        self.app.open("TRAFFIC")

    def line(self, text):
        if not text.startswith("STATS "):
            return
        try:
            st = json.loads(text[6:])
        except ValueError:
            return
        self.stats = st
        if st.get("top"):
            self.last_top = st["top"]
        for p in reversed(st.get("feed", [])):
            self.packets.append(p)
        if self.app.current == "TRAFFIC":
            self.draw()

    def done(self, rc, out, stopped):
        self.running_port = None
        self.idle("run")
        result = None
        for ln in reversed(out.splitlines()):
            if ln.startswith("RESULT sniff_stats "):
                try:
                    result = json.loads(ln[len("RESULT sniff_stats "):])
                except ValueError:
                    pass
                break
        self.last = {"port": self.cap_port, "result": result}
        if result is None or result.get("error"):
            self.message = ("FAIL", "bad", clip((result or {}).get("error") or out.strip()[-40:] or "no result", 18))
            self.app.note("TRAFFIC", "FAIL", "", " capture")
        else:
            self.app.note("TRAFFIC", "INFO", " %s packets" % spaced(result["packets"]), " on %s" % self.cap_port)
        after, self.after_stop = self.after_stop, None
        if after:
            after()
        self.sync_pages()
        self.draw()

    def sync_pages(self):
        page = self.app.screens.get("PAUSED")
        if page is not None:
            page.sync()

    # --- saving -----------------------------------------------------------

    def save(self):
        if self.running_port:
            self.after_stop = self.save_last
            self.stop()
        else:
            self.save_last()

    def save_last(self):
        if not self.last or not self.last.get("result") or self.last["result"].get("error"):
            self.message = ("INFO", "text", "nothing to save")
            self.draw()
            return
        port, res = self.last["port"], self.last["result"]
        now = datetime.now().astimezone()
        day, stamp = now.strftime("%Y%m%d"), now.strftime("%H%M%S")
        folder = os.path.join(RESULTS_DIR, day)
        os.makedirs(folder, exist_ok=True)
        base, name = os.path.join(CAPTURE_DIR, port), "%s_traffic_%s" % (stamp, port)
        for ext in (".pcap", ".csv", "_top.csv"):
            if os.path.exists(base + ext):
                shutil.copyfile(base + ext, os.path.join(folder, name + ext))
        record = {"script": "sniff_stats.py", "port": port, "time": now.isoformat(timespec="seconds"),
                  "ntp_synchronized": ntp_synced(), "script_md5": md5("sniff_stats.py"), "result": res}
        with open(os.path.join(folder, "%s_sniff_stats_%s.json" % (stamp, port)), "w") as f:
            json.dump(record, f, indent=1)
        self.message = ("SAVED", "good", "results " + now.strftime("%H:%M"))
        self.draw()

    # --- drawing ----------------------------------------------------------

    def draw(self):
        c = self.canvas
        c.delete("all")
        st = self.stats or {}
        cw = (W - 2 * M - 4 * G) // 5
        metrics = [(spaced(st["pps"]) if st else "--", "packets/s"), (mbit(st["bps"]) if st else "--", "Mbit/s"),
                   ("%d B" % st["avg"] if st else "--", "avg size"), (str(st["hosts"]) if st else "--", "hosts")]
        for i, (value, label) in enumerate(metrics):
            x = M + i * (cw + G)
            c.create_rectangle(x, 0, x + cw, 52, fill=C["panel"], width=0)
            c.create_text(x + 12, 4, text=value, font=font(25, True), fill=C["text"], anchor="nw")
            c.create_text(x + 12, 33, text=label, font=font(14), fill=C["muted"], anchor="nw")
        x = M + 4 * (cw + G)
        c.create_rectangle(x, 0, W - M, 52, fill=C["panel"], width=0)
        if self.message:
            word, color, sub = self.message
            c.create_text(x + 12, 4, text=word, font=font(23, True), fill=C[color], anchor="nw")
        elif self.running_port:
            t = int(st.get("t", 0))
            word, sub = DOT + " LIVE", "%s %s %02d:%02d" % (self.running_port, MID, t // 60, t % 60)
            c.create_text(x + 12, 4, text=word, font=font(23, True), fill=C["bad"], anchor="nw")
        elif self.last:
            res = self.last.get("result") or {}
            word, sub = "STOPPED", "%s %s %d s" % (self.last["port"], MID, res.get("duration_s", 0))
            c.create_text(x + 12, 4, text=word, font=font(21, True), fill=C["muted"], anchor="nw")
        else:
            word, sub = "IDLE", "tap START"
            c.create_text(x + 12, 4, text=word, font=font(23, True), fill=C["muted"], anchor="nw")
        c.create_text(x + 12, 33, text=sub, font=font(14), fill=C["muted"], anchor="nw")

        y1 = 60
        c.create_rectangle(M, y1, W - M, y1 + 60, fill=C["panel"], width=0)
        cats = st.get("cats", {})
        total = sum(v[0] for v in cats.values())
        names = ["TCP", "UDP", "ICMP", "ICMPv6", "ARP", "other"]
        bx, bw = M + 10, W - 2 * M - 20
        c.create_rectangle(bx, y1 + 7, bx + bw, y1 + 19, fill=C["line"], width=0)
        for name in names:
            n = cats.get(name, [0, 0])[0]
            if total and n:
                w = max(2, round(bw * n / total))
                c.create_rectangle(bx, y1 + 7, min(bx + w, M + 10 + bw), y1 + 19, fill=PROTO[name], width=0)
                bx += w
        iw = (W - 2 * M - 20) // len(names)
        for i, name in enumerate(names):
            n = cats.get(name, [0, 0])[0]
            lx = M + 10 + i * iw
            c.create_rectangle(lx, y1 + 28, lx + 10, y1 + 38, fill=PROTO[name], width=0)
            c.create_text(lx + 15, y1 + 33, text=name, font=font(14, True), fill=C["text"], anchor="w")
            c.create_text(lx + iw - 14, y1 + 33, text="%.0f%%" % (100 * n / total) if total else "--",
                          font=font(14, True), fill=C["text"], anchor="e")
            c.create_text(lx + 15, y1 + 50, text=spaced(n), font=font(13), fill=C["muted"], anchor="w")

        y2, y3, lw = y1 + 68, BOTTOM - TOP, 290
        c.create_rectangle(M, y2, M + lw, y3, fill=C["panel"], width=0)
        c.create_text(M + 10, y2 + 6, text="TOP TALKERS", font=font(14, True), fill=C["muted"], anchor="nw")
        c.create_text(M + lw - 10, y2 + 6, text="bytes", font=font(13), fill=C["dim"], anchor="ne")
        top = st.get("top", [])
        peak = top[0][1] if top else 1
        for i, (address, nbytes, _) in enumerate(top[:5]):
            ry = y2 + 27 + i * 35
            c.create_text(M + 10, ry, text=clip(short(address), 22), font=font(15), fill=C["text"], anchor="nw")
            c.create_text(M + lw - 10, ry, text=human(nbytes), font=font(15, True), fill=C["text"], anchor="ne")
            c.create_rectangle(M + 10, ry + 21, M + lw - 10, ry + 26, fill=C["line"], width=0)
            c.create_rectangle(M + 10, ry + 21, M + 10 + (lw - 20) * nbytes / peak, ry + 26, fill=C["accent"],
                               width=0)

        fx = M + lw + G
        c.create_rectangle(fx, y2, W - M, y3, fill=C["panel"], width=0)
        c.create_text(fx + 10, y2 + 6, text="PACKETS", font=font(14, True), fill=C["muted"], anchor="nw")
        c.create_text(W - M - 10, y2 + 6, text="filter: " + self.filter_text(), font=font(13), fill=C["accent"],
                      anchor="ne")
        for i, p in enumerate(list(self.packets)[-8:][::-1]):
            ry = y2 + 29 + i * 22
            stamp = datetime.fromtimestamp(p["ts"]).strftime("%S.%f")[:6]
            c.create_text(fx + 10, ry, text=stamp, font=font(13, family=MONO), fill=C["dim"], anchor="nw")
            c.create_text(fx + 66, ry, text=p["cat"], font=font(13, True, MONO), fill=PROTO[p["cat"]], anchor="nw")
            c.create_text(fx + 162, ry, text=str(p["len"]), font=font(13, family=MONO), fill=C["muted"], anchor="ne")
            c.create_text(fx + 174, ry, text=pair_text(p, 30), font=font(14), fill=C["text"], anchor="nw")
            c.create_text(W - M - 10, ry, text=clip(ABBREV.get(p["info"], p["info"]), 9), font=font(13),
                          fill=C["muted"], anchor="ne")


class PausedScreen(Screen):
    """Frozen copy of the retained packets; counting goes on in the background."""

    def __init__(self, app):
        super().__init__(app, "PAUSED", ports=True)
        self.verdict_canvas.place_forget()
        self.snapshot, self.page, self.rows = [], 0, []
        px, h2 = W - M - SIDE_W, (BOTTOM - TOP - G) // 2
        button(self, px, TOP, SIDE_W, h2, UP + "\nPAGE", C["panel2"], lambda: self.turn(-1), "secondary", 17)
        button(self, px, TOP + h2 + G, SIDE_W, h2, "PAGE\n" + DOWN, C["panel2"], lambda: self.turn(1), "secondary", 17)
        t = app.screens["TRAFFIC"]
        self.port = t.port
        self.bottom([("run", "START", C["go"], t.start, 118),
                     ("resume", "RESUME", "#2E7D32", lambda: app.open("TRAFFIC"), 108),
                     ("filter", "FILTER", C["action"], lambda: app.open("FILTER"), 108),
                     ("save", "SAVE", "#2E7D32", t.save, 100)])

    def select_port(self, name):
        super().select_port(name)
        t = self.app.screens.get("TRAFFIC")
        if t is not None and t.port != name:
            t.select_port(name)
            self.app.open("TRAFFIC")

    def shown(self):
        t = self.app.screens["TRAFFIC"]
        self.snapshot = list(t.packets)[::-1]
        self.page = 0
        super().select_port(t.port)
        self.sync()
        self.draw()

    def sync(self):
        t = self.app.screens["TRAFFIC"]
        if t.running_port:
            self.running("run", t.stop)
        else:
            self.idle("run")

    def turn(self, step):
        pages = max(1, (len(self.snapshot) + PER_PAGE - 1) // PER_PAGE)
        self.page = min(pages - 1, max(0, self.page + step))
        self.draw()

    def draw(self):
        for r in self.rows:
            r.destroy()
        self.rows = []
        pages = max(1, (len(self.snapshot) + PER_PAGE - 1) // PER_PAGE)
        self.bar.title = "PAUSED %s %d/%d" % (MID, self.page + 1, pages)
        self.bar.draw(self.app.status)
        lw = W - 2 * M - SIDE_W - G
        rh = (BOTTOM - TOP - (PER_PAGE - 1) * G) // PER_PAGE
        first = self.page * PER_PAGE
        for k, p in enumerate(self.snapshot[first:first + PER_PAGE]):
            y = TOP + k * (rh + G)
            f = tk.Frame(self, bg=C["panel"], cursor="none")
            f.place(x=M, y=y, width=lw, height=rh)
            f.role = "secondary"
            color = PROTO[p["cat"]]
            parts = [tk.Frame(f, bg=color)]
            parts[0].place(x=0, y=0, width=6, relheight=1)
            stamp = datetime.fromtimestamp(p["ts"]).strftime("%S.%f")[:6]
            parts.append(tk.Label(f, text=p["cat"], font=font(16, True), fg=color, bg=C["panel"]))
            parts[-1].place(x=16, y=6)
            parts.append(tk.Label(f, text=clip("#%d   %s   %d B   %s" % (p["n"], stamp, p["len"], p["info"]), 50),
                                  font=font(15), fg=C["muted"], bg=C["panel"]))
            parts[-1].place(x=104, y=7)
            pair = "%s  %s  %s" % (p["src"], ARR, p["dst"]) if p["src"] else "(no addresses)"
            parts.append(tk.Label(f, text=clip(pair, 60), font=font(15, family=MONO), fg=C["text"], bg=C["panel"]))
            parts[-1].place(x=16, y=32)
            for w in [f] + parts:
                w.bind("<Button-1>", lambda e, i=first + k: self.open_packet(i))
            self.rows.append(f)
        if not self.snapshot:
            f = tk.Label(self, text="no packets yet: START the capture first", font=font(17), fg=C["muted"],
                         bg=C["bg"])
            f.place(x=M, y=TOP + 10)
            self.rows.append(f)

    def open_packet(self, i):
        if "PACKET" not in self.app.screens:
            self.app.screens["PACKET"] = PacketScreen(self.app)
        self.app.screens["PACKET"].index = i
        self.app.open("PACKET")


class PacketScreen(Screen):
    LINES = 12

    def __init__(self, app):
        super().__init__(app, "PACKET", ports=False)
        self.verdict_canvas.place_forget()
        self.index, self.scroll_at = 0, 0
        pw = W - 2 * M - SIDE_W - G
        self.canvas = tk.Canvas(self, width=pw, height=BOTTOM - TOP, bg=C["panel"], highlightthickness=0,
                                cursor="none")
        self.canvas.place(x=M, y=TOP)
        px, h2 = W - M - SIDE_W, (BOTTOM - TOP - G) // 2
        button(self, px, TOP, SIDE_W, h2, UP, C["panel2"], lambda: self.scroll(-1), "secondary", 22)
        button(self, px, TOP + h2 + G, SIDE_W, h2, DOWN, C["panel2"], lambda: self.scroll(1), "secondary", 22)
        self.bottom([("prev", LEFT + "  PREV", C["panel2"], lambda: self.step(-1), 150),
                     ("next", "NEXT  " + RIGHT, C["panel2"], lambda: self.step(1), 150),
                     ("host", "FILTER\nTHIS HOST", C["action"], self.filter_host, 180)],
                    back=lambda: app.open("PAUSED"))

    def packet(self):
        snap = self.app.screens["PAUSED"].snapshot
        return snap[self.index] if 0 <= self.index < len(snap) else None

    def shown(self):
        self.scroll_at = 0
        self.draw()

    def step(self, d):
        snap = self.app.screens["PAUSED"].snapshot
        self.index = min(len(snap) - 1, max(0, self.index + d))
        self.scroll_at = 0
        self.draw()

    def scroll(self, d):
        self.scroll_at = max(0, self.scroll_at + d * self.LINES)
        self.draw()

    def lines(self, p):
        out = []
        for layer, text in p["detail"]:
            while len(text) > 66:
                cut = text.rfind("   ", 0, 66)
                cut = cut if cut > 20 else 66
                out.append((layer, text[:cut]))
                layer, text = "", text[cut:].strip()
            out.append((layer, text))
        return out

    def draw(self):
        c = self.canvas
        c.delete("all")
        p = self.packet()
        if p is None:
            self.bar.title = "PACKET"
            self.bar.draw(self.app.status)
            return
        self.bar.title = "PACKET #%d" % p["n"]
        self.bar.draw(self.app.status)
        rows = self.lines(p)
        self.scroll_at = min(self.scroll_at, max(0, len(rows) - self.LINES))
        pw = W - 2 * M - SIDE_W - G
        for i, (layer, text) in enumerate(rows[self.scroll_at:self.scroll_at + self.LINES]):
            y = 10 + i * 27
            if layer:
                if i:
                    c.create_line(8, y - 5, pw - 8, y - 5, fill=C["line"])
                color = C["dim"] if layer == "Frame" else PROTO.get(layer, C[LAYER.get(layer, "muted")])
                c.create_text(12, y, text=layer, font=font(15, True), fill=color, anchor="nw")
            c.create_text(100, y, text=text, font=font(14, family=MONO), fill=C["text"], anchor="nw")

    def filter_host(self):
        p = self.packet()
        if p and (p["src"] or p["dst"]):
            t = self.app.screens["TRAFFIC"]
            t.set_filter(FILTERS[-1], p["src"] or p["dst"])


class FilterScreen(Screen):
    def __init__(self, app):
        super().__init__(app, "TRAFFIC " + MID + " FILTER", ports=False)
        self.verdict_canvas.place_forget()
        tk.Label(self, text="The filter runs in the kernel as BPF: packets that do not match never reach the program.",
                 font=font(14), fg=C["muted"], bg=C["bg"]).place(x=M, y=TOP + 2)
        self.now = tk.Label(self, font=font(17, True), fg=C["muted"], bg=C["bg"], anchor="w")
        self.now.place(x=M, y=BTN_Y + BTN_H // 2 - 12)
        self.cards = {}
        self.bottom([], back=lambda: app.open("TRAFFIC"))

    def shown(self):
        for f in self.cards.values():
            f.destroy()
        t = self.app.screens["TRAFFIC"]
        cols = 3
        bw = (W - 2 * M - G * (cols - 1)) // cols
        bh = (BOTTOM - TOP - 26 - 2 * G) // 3
        for i, entry in enumerate(FILTERS):
            name, _, text = entry
            active = name == t.filter[0]
            bg = C["panel2"] if active else C["panel"]
            f = tk.Frame(self, bg=bg, highlightthickness=3 if active else 0, highlightbackground=C["accent"],
                         cursor="none")
            f.place(x=M + (i % cols) * (bw + G), y=TOP + 26 + (i // cols) * (bh + G), width=bw, height=bh)
            f.role = "main"
            title = tk.Label(f, text=name, font=font(22, True), fg=C["text"], bg=bg, anchor="w")
            title.place(x=16, y=10)
            sub = tk.Label(f, text=text, font=font(14), fg=C["muted"], bg=bg, anchor="nw", justify="left",
                           wraplength=bw - 28)
            sub.place(x=16, y=42)
            for w in (f, title, sub):
                w.bind("<Button-1>", lambda e, en=entry: self.pick(en))
            self.cards[name] = f
        now = t.filter[0] + (": " + t.host if t.filter[0] == "HOST" else "")
        self.now.config(text="now: " + ("ALL, no filter" if t.filter[0] == "ALL" else clip(now, 44)))

    def pick(self, entry):
        if entry[0] == "HOST":
            self.app.open("HOSTS")
        else:
            self.app.screens["TRAFFIC"].set_filter(entry)


class HostScreen(Screen):
    def __init__(self, app):
        super().__init__(app, "FILTER " + MID + " HOST", ports=False)
        self.set_verdict("INFO", "tap a host from the top talkers")
        self.items = []
        self.bottom([], back=lambda: app.open("FILTER"))

    def shown(self):
        for b in self.items:
            b.destroy()
        self.items = []
        t = self.app.screens["TRAFFIC"]
        hosts = [a for a, _, _ in t.last_top][:6]
        if not hosts:
            self.set_verdict("INFO", "no talkers yet: START the capture first")
            return
        self.set_verdict("INFO", "tap a host from the top talkers")
        bw = (W - 2 * M - G) // 2
        bh = (BOTTOM - self.body - 2 * G) // 3
        for i, a in enumerate(hosts):
            b = button(self, M + (i % 2) * (bw + G), self.body + (i // 2) * (bh + G), bw, bh, short(a),
                       C["panel"], lambda a=a: t.set_filter(FILTERS[-1], a), "main", 17)
            self.items.append(b)
