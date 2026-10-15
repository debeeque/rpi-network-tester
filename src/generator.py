import json
import re
import tkinter as tk

from ui_kit import ARR, BOTTOM, C, G, M, MID, PORTS, W, Screen, button, font, short

# label, pkt_gen proto, receiver BPF, IP version of the target (None: no target)
PROTOS = [
    ("ICMP", "icmp", "icmp and icmp[icmptype] == icmp-echo", 4),
    ("ICMPv6", "icmp6", "icmp6 and ip6[40] == 128", 6),
    ("UDP", "udp", "udp and dst port 9", 4),
    ("TCP SYN", "tcp-syn", "tcp and dst port 9", 4),
    ("ARP", "arp", "arp", 4),
    ("RS", "rs", "icmp6 and ip6[40] == 133", None),
]
SIZED = ("icmp", "icmp6", "udp")
COUNTS = [(100, "100"), (1000, "1000"), (10000, "10 000"), (0, "until STOP")]
RATES = [(10, "10 /s"), (100, "100 /s"), (1000, "1000 /s"), (0, "max")]
SIZES = [(0, "minimal"), (128, "128 B"), (512, "512 B"), (1514, "1514 B")]


class _Quiet:
    """Screen stand-in for the counting job: only the sending job reports progress in the verdict line."""

    def set_verdict(self, *args):
        pass


class GeneratorScreen(Screen):
    """Sends with pkt_gen.py from the selected port and counts the frames on the other port."""

    def __init__(self, app):
        self.state = None
        super().__init__(app, "GENERATOR")
        self.proto, self.count, self.rate, self.size = 1, 1, 1, 2
        y = self.body
        bw = (W - 2 * M - 5 * G) // 6
        self.proto_btns = []
        for i, p in enumerate(PROTOS):
            self.proto_btns.append(button(self, M + i * (bw + G), y, bw, 64, p[0], C["panel2"],
                                          lambda i=i: self.pick(i), "secondary", 17))
        y += 64 + G
        pw = (W - 2 * M - 3 * G) // 4
        self.count_btn = button(self, M, y, pw, 64, "", C["panel"], lambda: self.cycle("count"), "secondary", 16)
        self.rate_btn = button(self, M + pw + G, y, pw, 64, "", C["panel"], lambda: self.cycle("rate"), "secondary", 16)
        self.size_btn = button(self, M + 2 * (pw + G), y, pw, 64, "", C["panel"], lambda: self.cycle("size"),
                               "secondary", 16)
        self.to_btn = button(self, M + 3 * (pw + G), y, pw, 64, "", C["panel"], self.show_target, "secondary", 16)
        y += 64 + G
        self.counts = tk.Canvas(self, width=W - 2 * M, height=BOTTOM - y, bg=C["panel"], highlightthickness=0,
                                cursor="none")
        self.counts.place(x=M, y=y)
        self.port = "snd0"
        self.bottom([("send", "SEND", C["go"], self.start, 200)])
        self.set_verdict("IDLE", "choose a packet type and tap SEND")
        self.refresh()

    def other(self, port=None):
        port = port or self.port
        return PORTS[1] if port == PORTS[0] else PORTS[0]

    def select_port(self, name):
        if self.state:
            return
        super().select_port(name)
        self.refresh()

    def shown(self):
        self.refresh()

    # --- parameters -------------------------------------------------------

    def pick(self, i):
        if not self.state:
            self.proto = i
            self.refresh()

    def cycle(self, what):
        if self.state:
            return
        if what == "size" and PROTOS[self.proto][1] not in SIZED:
            return
        n = {"count": COUNTS, "rate": RATES, "size": SIZES}[what]
        setattr(self, what, (getattr(self, what) + 1) % len(n))
        self.refresh()

    def target(self):
        """Address and MAC of the other test port, from the port status file."""
        st = self.app.port_state().get("ports", {})
        dst = st.get(self.other(), {})
        version = PROTOS[self.proto][3]
        if version is None:
            return "ff02::2", None, dst
        if version == 4:
            addr = next((a.split("/")[0] for a in dst.get("addr4", [])), None)
        else:
            addr = next((a.split("/")[0] for a in dst.get("addr6", []) if a.startswith("fe80")), None)
        return addr, dst.get("mac"), dst

    def show_target(self):
        addr, mac, _ = self.target()
        if not self.state:
            self.set_verdict("INFO", "target %s on %s, %s" % (short(addr or "none"), self.other(), mac or "no MAC"))

    def refresh(self):
        for i, b in enumerate(self.proto_btns):
            b.config(bg=C["sel"] if i == self.proto else C["panel2"],
                     activebackground=C["sel"] if i == self.proto else C["panel2"])
        sized = PROTOS[self.proto][1] in SIZED
        self.count_btn.config(text="COUNT\n" + COUNTS[self.count][1])
        self.rate_btn.config(text="RATE\n" + RATES[self.rate][1])
        self.size_btn.config(text="SIZE\n" + (SIZES[self.size][1] if sized else "fixed"),
                             fg="white" if sized else C["dim"])
        self.to_btn.config(text="TO\n%s auto" % self.other())
        if not self.state:
            self.draw_counts(None, None, "")

    def draw_counts(self, sent, received, note):
        c = self.counts
        c.delete("all")
        h = int(c.cget("height"))
        half = (W - 2 * M) // 2
        rows = (("SENT on " + self.port, sent), ("RECEIVED on " + self.other(), received))
        for i, (label, value) in enumerate(rows):
            x = 14 + i * half
            c.create_text(x, 8, text=label, font=font(14, True), fill=C["muted"], anchor="nw")
            c.create_text(x, 28, text="{:,}".format(value).replace(",", " ") if value is not None else "--",
                          font=font(30, True), fill=C["text"], anchor="nw")
        c.create_text(14, 72, text=note, font=font(14), fill=C["muted"], anchor="nw")
        total = COUNTS[self.count][0]
        c.create_rectangle(14, h - 14, W - 2 * M - 14, h - 8, fill=C["line"], width=0)
        if sent and total:
            c.create_rectangle(14, h - 14, 14 + (W - 2 * M - 28) * min(1, sent / total), h - 8,
                               fill=C["good"], width=0)

    # --- run --------------------------------------------------------------

    def start(self):
        src, dst_port = self.port, self.other()
        for port in (src, dst_port):
            busy = self.app.jobs.get(port)
            if busy:
                self.set_verdict("BUSY", "%s is running %s" % (port, busy["label"]))
                return
        label, proto, bpf, version = PROTOS[self.proto]
        addr, mac, dst_state = self.target()
        src_mac = self.app.port_state().get("ports", {}).get(src, {}).get("mac")
        if version is not None and (not addr or not mac):
            self.set_verdict("FAIL", "%s has no address to send to: is its adapter plugged in?" % dst_port)
            return
        if not src_mac:
            self.set_verdict("FAIL", "%s is not set up" % src)
            return
        count, rate = COUNTS[self.count][0], RATES[self.rate][0]
        gen = ["python3", "pkt_gen.py", src, "--proto", proto, "--count", str(count), "--rate", str(rate)]
        if version is not None:
            gen += ["--dst", addr, "--dst-mac", mac]
        if proto in SIZED and SIZES[self.size][0]:
            gen += ["--size", str(SIZES[self.size][0])]
        cfg = self.app.PORTS
        self.state = {"sent": 0, "received": 0 if dst_state.get("present") else None, "stopped": False,
                      "gen_done": None, "desc": "%s %s %s %s" % (label, src, ARR, dst_port)}
        self.running("send", self.stop)
        self.set_verdict("RUNNING", "starting the counter on %s" % dst_port)
        self.update_counts()
        if dst_state.get("present"):
            rx = ["sudo", "ip", "netns", "exec", cfg[dst_port]["ns"], "python3", "sniff_stats.py", dst_port,
                  "--bpf", "ether src %s and (%s)" % (src_mac, bpf), "--interval", "0.5", "--feed", "0"]
            self.app.run(dst_port, rx, "counting %s" % label, _Quiet(), on_line=self.rx_line,
                         on_done=self.rx_done, keep=20)
        self.gen_cmd = ["sudo", "ip", "netns", "exec", cfg[src]["ns"]] + gen
        self.after(1200, self.start_gen)

    def start_gen(self):
        if self.state is None or self.state["stopped"]:
            return
        self.app.run(self.port, self.gen_cmd, "sending " + self.state["desc"], self, on_line=self.gen_line,
                     on_done=self.gen_done, keep=20)

    def stop(self):
        if self.state:
            self.state["stopped"] = True
            if self.app.jobs.get(self.port):
                self.app.stop(self.port)
            elif self.app.jobs.get(self.other()):
                self.app.stop(self.other())

    def gen_line(self, text):
        if text.startswith("Sending") and self.state:
            self.state["sending"] = True
            self.update_counts()
        m = re.match(r"PROGRESS (\d+)", text)
        if m and self.state:
            self.state["sent"] = int(m.group(1))
            self.update_counts()

    def rx_line(self, text):
        if text.startswith("STATS ") and self.state and self.state["received"] is not None:
            m = re.search(r'"packets":(\d+)', text)
            if m:
                self.state["received"] = int(m.group(1))
                self.update_counts()

    def update_counts(self):
        s = self.state
        # Scapy builds the frames before the first one leaves: seconds, more for "until STOP"
        note = s["desc"] if s.get("sending") else s["desc"] + ": preparing packets" + chr(0x2026)
        self.draw_counts(s["sent"], s["received"], note)

    def gen_done(self, rc, out, stopped):
        m = re.search(r"^RESULT pkt_gen (.*)$", out, re.M)
        res = {}
        if m:
            try:
                res = json.loads(m.group(1))
            except ValueError:
                pass
        s = self.state
        s["gen_done"] = res
        if res.get("sent") is not None:
            s["sent"] = res["sent"]
        self.update_counts()
        # Frames still in flight: give the counter a moment before stopping it
        if self.app.jobs.get(self.other()):
            self.after(1500, lambda: self.app.stop(self.other()))
        else:
            self.finish()

    def rx_done(self, rc, out, stopped):
        m = re.search(r"^RESULT sniff_stats (.*)$", out, re.M)
        if m and self.state:
            try:
                self.state["received"] = json.loads(m.group(1))["packets"]
            except (ValueError, KeyError):
                pass
        if self.state and (self.state["gen_done"] is not None or not self.app.jobs.get(self.port)):
            self.finish()

    def finish(self):
        s, self.state = self.state, None
        self.idle("send")
        res = s["gen_done"] or {}
        sent, received = s["sent"], s["received"]
        self.draw_counts(sent, received, s["desc"])
        if res.get("error"):
            self.set_verdict("FAIL", "pkt_gen: %s" % res["error"])
            self.app.note("GENERATOR", "FAIL", "", " " + res["error"])
            return
        rate = " %s %d pkt/s" % (MID, res.get("rate_real", 0))
        if received is None:
            word, text = "INFO", "%d sent, %s is not plugged in" % (sent, self.other())
        elif s["stopped"] or res.get("aborted"):
            word, text = "STOPPED", "%d sent, %d received" % (sent, received)
        elif received == sent:
            word, text = "PASS", "%d sent from %s, %d received on %s, 0 lost" % (sent, self.port, received,
                                                                               self.other())
        else:
            word, text = "WARN", "%d sent, %d received, %d lost" % (sent, received, sent - received)
        self.set_verdict(word, text)
        self.draw_counts(sent, received, s["desc"] + rate)
        self.app.save_result("pkt_gen.py", self.port, {"verdict": word, "proto": PROTOS[self.proto][1], "sent": sent,
                                                       "received": received, "counted_on": self.other(),
                                                       "generator": res})
        self.app.note("GENERATOR", word, " %s/%d" % (received if received is not None else "-", sent),
                      " " + PROTOS[self.proto][0])
