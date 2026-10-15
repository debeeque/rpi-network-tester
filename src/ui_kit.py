import tkinter as tk

W, H = 800, 480
M = 15
G = 8
BAR_H = 32
BTN_H = 80
BTN_Y = H - M - BTN_H
TOP = BAR_H + G
BOTTOM = BTN_Y - G
BACK_W = 110
PORT_W = 92
SIDE_W = 92
VERDICT_H = 44

C = {
    "bg": "#0E2226", "bar": "#06151A", "panel": "#15323A", "panel2": "#1D434C",
    "line": "#2A5862", "text": "#ECF3F4", "muted": "#9DBCC2", "dim": "#63858B",
    "good": "#66BB6A", "warn": "#FFB300", "bad": "#EF5350", "accent": "#4FC3F7",
    "back": "#455A64", "sel": "#0277BD", "stop": "#C62828", "go": "#2E7D32",
    "action": "#00838F", "gray": "#37474F",
}
VERDICT = {"PASS": "good", "OK": "good", "WARN": "warn", "FAIL": "bad", "BUSY": "warn", "STOPPED": "warn",
           "RUNNING": "accent", "IDLE": "muted", "INFO": "text", "ON": "warn", "OFF": "muted"}
PROTO = {"TCP": "#42A5F5", "UDP": "#AB47BC", "ICMP": "#FF7043",
         "ICMPv6": "#FFCA28", "ARP": "#26A69A", "other": "#78909C"}
SANS, MONO = "Liberation Sans", "DejaVu Sans Mono"
DOT, MID, ARR, ELL = chr(0x25CF), chr(0x00B7), chr(0x2192), chr(0x2026)
UP, DOWN, LEFT, RIGHT = chr(0x25B2), chr(0x25BC), chr(0x25C0), chr(0x25B6)
PORTS = ("mon0", "snd0")


def font(size, bold=False, family=SANS):
    return (family, -size, "bold") if bold else (family, -size)


def button(parent, x, y, w, h, text, bg, command=None, role="main", size=17, fg="white"):
    b = tk.Button(parent, text=text, bg=bg, fg=fg, activebackground=bg, activeforeground=fg,
                  disabledforeground=C["dim"], font=font(size, True), bd=0, highlightthickness=0,
                  relief="flat", command=command, cursor="none")
    b.place(x=x, y=y, width=w, height=h)
    b.role = role
    return b


def short(addr):
    if "::" not in addr:
        return addr
    head, tail = addr.split("::", 1)
    groups = tail.split(":")
    if len(groups) <= 2:
        return addr
    return head + "::" + ELL + ":".join(groups[-2:])


class StatusBar(tk.Canvas):
    def __init__(self, parent, title):
        super().__init__(parent, width=W, height=BAR_H, bg=C["bar"], highlightthickness=0, cursor="none")
        self.place(x=0, y=0)
        self.title = title
        self.draw({})

    def draw(self, st):
        self.delete("all")
        y = BAR_H // 2 + 1
        self.create_text(M, y, text=self.title, font=font(17, True), fill=C["text"], anchor="w")
        x = 262
        for name in PORTS:
            p = st.get("ports", {}).get(name, {})
            if not p.get("present"):
                color, text = C["dim"], name + " --"
            elif p.get("carrier"):
                color, text = C["good"], "%s %s" % (name, p.get("speed") or "")
            else:
                color, text = C["bad"], name + " down"
            self.create_text(x, y, text=DOT, font=font(15), fill=color, anchor="w")
            self.create_text(x + 16, y, text=text, font=font(15), fill=C["text"], anchor="w")
            x += 102
        dhcp = st.get("dhcp")
        self.create_text(x, y, text="DHCP on" if dhcp else "DHCP off", font=font(15, bool(dhcp)),
                         fill=C["warn"] if dhcp else C["dim"], anchor="w")
        ssid = st.get("ssid")
        self.create_text(x + 80, y, text="Wi-Fi " + ssid[:11] if ssid else "Wi-Fi off", font=font(15),
                         fill=C["text"] if ssid else C["dim"], anchor="w")
        bx = W - M - 40
        self.create_text(bx - 36, y, text=st.get("time", ""), font=font(15, True), fill=C["text"], anchor="e")
        pct, color = st.get("battery", (None, C["dim"]))
        self.create_rectangle(bx - 26, y - 7, bx - 2, y + 7, outline=C["muted"], width=1)
        self.create_rectangle(bx - 2, y - 3, bx, y + 3, fill=C["muted"], width=0)
        if pct is not None:
            self.create_rectangle(bx - 24, y - 5, bx - 24 + int(20 * min(pct, 100) / 100), y + 5, fill=color, width=0)
        self.create_text(W - M, y, text="%d%%" % pct if pct is not None else "--", font=font(15),
                         fill=C["text"], anchor="e")


class Screen(tk.Frame):
    """Function screen: status bar, verdict line, content, bottom bar with BACK in a fixed place."""

    def __init__(self, app, title, ports=True):
        super().__init__(app.root, bg=C["bg"], width=W, height=H, cursor="none")
        self.app = app
        self.bar = StatusBar(self, title)
        self.port = "mon0"
        self.port_buttons = {}
        self.actions = {}
        self.has_ports = ports
        self.verdict_canvas = tk.Canvas(self, width=W - 2 * M, height=VERDICT_H, bg=C["panel"],
                                        highlightthickness=0, cursor="none")
        self.verdict_canvas.place(x=M, y=TOP)
        self.body = TOP + VERDICT_H + G
        self.logbox = None
        self.set_verdict("IDLE", "")

    def set_verdict(self, word, text):
        c = self.verdict_canvas
        c.delete("all")
        c.create_text(12, VERDICT_H // 2, text=word, font=font(22, True),
                      fill=C[VERDICT.get(word, "text")], anchor="w")
        c.create_text(150, VERDICT_H // 2, text=text, font=font(19), fill=C["text"], anchor="w")

    def make_log(self, y0):
        h = BOTTOM - y0
        w = W - 2 * M - SIDE_W - G
        self.logbox = tk.Text(self, bg=C["panel"], fg=C["text"], font=font(12, family=MONO), bd=0,
                              highlightthickness=0, wrap="none", padx=8, pady=6, cursor="none")
        self.logbox.place(x=M, y=y0, width=w, height=h)
        self.logbox.config(state="disabled")
        half = (h - G) // 2
        button(self, W - M - SIDE_W, y0, SIDE_W, half, UP, C["panel2"], lambda: self.scroll(-1), "secondary", 22)
        button(self, W - M - SIDE_W, y0 + half + G, SIDE_W, h - half - G, DOWN, C["panel2"],
               lambda: self.scroll(1), "secondary", 22)

    def scroll(self, direction):
        if self.logbox:
            self.logbox.yview_scroll(direction, "pages")

    def log(self, text):
        if not self.logbox:
            return
        at_end = self.logbox.yview()[1] >= 0.999
        self.logbox.config(state="normal")
        self.logbox.insert("end", text.rstrip("\n") + "\n")
        lines = int(self.logbox.index("end-1c").split(".")[0])
        if lines > 2000:
            self.logbox.delete("1.0", "%d.0" % (lines - 2000))
        self.logbox.config(state="disabled")
        if at_end:
            self.logbox.see("end")

    def bottom(self, items, back=None):
        """items: (key, text, color, command, base width); main buttons share the free width.
        BACK goes home unless a sub-page passes its parent."""
        x = M
        if self.has_ports:
            for name in PORTS:
                b = button(self, x, BTN_Y, PORT_W, BTN_H, "%s\n%s" % ("MON" if name == "mon0" else "SND", name),
                           C["panel2"], lambda n=name: self.select_port(n), "secondary", 17)
                self.port_buttons[name] = b
                x += PORT_W + G
        free = W - M - BACK_W - G - x - G * (len(items) - 1) - sum(it[4] for it in items)
        for key, text, color, command, width in items:
            width += free // max(1, len(items))
            b = button(self, x, BTN_Y, width, BTN_H, text, color, command, "main", 17)
            b.base = (text, color, command)
            self.actions[key] = b
            x += width + G
        button(self, W - M - BACK_W, BTN_Y, BACK_W, BTN_H, "BACK", C["back"], back or self.app.home, "secondary", 17)
        if self.has_ports:
            self.select_port(self.port)

    # The MAC tail printed on the adapter's sticker, read from the adapter itself
    def port_labels(self, ports):
        for name, b in self.port_buttons.items():
            p = ports.get(name, {})
            mac = p.get("mac") if p.get("present") else None
            text = "%s\n%s" % ("MON" if name == "mon0" else "SND", mac[-5:] if mac else "--")
            if b.cget("text") != text:
                b.config(text=text)

    def select_port(self, name):
        self.port = name
        for n, b in self.port_buttons.items():
            b.config(bg=C["sel"] if n == name else C["panel2"],
                     activebackground=C["sel"] if n == name else C["panel2"])

    def running(self, key, stop_command):
        b = self.actions[key]
        b.config(text="STOP", bg=C["stop"], activebackground=C["stop"], command=stop_command)

    def idle(self, key):
        b = self.actions[key]
        text, color, command = b.base
        b.config(text=text, bg=color, activebackground=color, command=command)

    def shown(self):
        pass
