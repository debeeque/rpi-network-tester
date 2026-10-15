import re
import subprocess
import threading
import tkinter as tk

from ui_kit import (BACK_W, BAR_H, BOTTOM, BTN_H, BTN_Y, C, DOT, DOWN, G, H, M, MID, SIDE_W, TOP, UP, VERDICT,
                    VERDICT_H, W, button, font)

BODY = TOP + VERDICT_H + G


def nmcli(*args, timeout=45):
    try:
        r = subprocess.run(["sudo", "nmcli", *args], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return 1, "timeout"
    return r.returncode, (r.stdout + r.stderr).strip()


# nmcli terse output separates fields with ':' and escapes ':' inside values
def split_terse(line):
    return [p.replace("\\:", ":").replace("\\\\", "\\") for p in re.split(r"(?<!\\):", line)]


def wifi_status():
    ssid = ip = None
    try:
        out = subprocess.run(["nmcli", "-t", "-f", "ACTIVE,SSID", "dev", "wifi", "list", "--rescan", "no"],
                             capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            f = split_terse(line)
            if len(f) >= 2 and f[0] == "yes":
                ssid = f[1]
        out = subprocess.run(["nmcli", "-g", "IP4.ADDRESS", "dev", "show", "wlan0"],
                             capture_output=True, text=True, timeout=5).stdout
        ip = out.split("/")[0].strip() or None
    except (OSError, subprocess.SubprocessError):
        pass
    return ssid, ip


def scan():
    code, out = nmcli("-t", "-f", "IN-USE,SSID,SIGNAL,SECURITY", "dev", "wifi", "list", "--rescan", "yes")
    if code != 0:
        return None, out
    nets = {}
    for line in out.splitlines():
        f = split_terse(line)
        if len(f) < 4 or not f[1]:
            continue
        net = {"ssid": f[1], "signal": int(f[2] or 0), "secure": f[3] not in ("", "--"), "inuse": f[0] == "*"}
        old = nets.get(net["ssid"])
        if old:
            net["inuse"] = net["inuse"] or old["inuse"]
            net["signal"] = max(net["signal"], old["signal"])
        nets[net["ssid"]] = net
    return sorted(nets.values(), key=lambda n: (not n["inuse"], -n["signal"])), ""


def saved_profiles():
    code, out = nmcli("-t", "-f", "NAME,TYPE", "con", "show")
    profiles = {}
    for line in out.splitlines() if code == 0 else []:
        f = split_terse(line)
        if len(f) >= 2 and f[1] == "802-11-wireless":
            c, ssid = nmcli("-g", "802-11-wireless.ssid", "con", "show", f[0])
            if c == 0 and ssid:
                profiles[split_terse(ssid)[0]] = f[0]
    return profiles


class OnScreenKeyboard:
    """Character keys in a rectangle; SHIFT, layout, space and delete are separate calls for a bottom bar."""
    LAYOUTS = {
        "abc": ["1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm"],
        "sym": ["1234567890", "!@#$%^&*()", "-_=+[]{}\\|~", ";:'\",.<>/?`"],
    }

    def __init__(self, parent, x, y, w, h, on_key):
        self.parent, self.box, self.on_key = parent, (x, y, w, h), on_key
        self.layout, self.caps, self.keys = "abc", False, []
        self.build()

    def build(self):
        for b in self.keys:
            b.destroy()
        self.keys = []
        x0, y0, w, h = self.box
        rows = self.LAYOUTS[self.layout]
        gap = G
        kh = (h - gap * (len(rows) - 1)) // len(rows)
        kw = (w - gap * 10) // 11
        for r, chars in enumerate(rows):
            x = x0 + (w - len(chars) * kw - (len(chars) - 1) * gap) // 2
            for ch in chars:
                ch = ch.upper() if self.caps else ch
                self.keys.append(button(self.parent, x, y0 + r * (kh + gap), kw, kh, ch, C["panel2"],
                                        lambda c=ch: self.on_key(c), "secondary", 22))
                x += kw + gap

    def toggle_caps(self):
        self.caps = not self.caps
        self.build()

    def toggle_layout(self):
        self.layout = "sym" if self.layout == "abc" else "abc"
        self.build()


class WifiDialog:
    PER_PAGE = 4

    def __init__(self, root, log=print, on_close=None):
        self.root, self.log, self.on_close = root, log, on_close
        self.nets, self.profiles = [], {}
        self.page_no, self.selected = 0, None
        self.password, self.show_pw, self.net = "", False, None
        self.widgets = []

        self.win = tk.Toplevel(root)
        self.win.title("Wi-Fi")
        self.win.geometry("%dx%d+0+0" % (W, H))
        self.win.attributes('-topmost', True)
        self.win.configure(bg=C["bg"], cursor="none")
        bar = tk.Canvas(self.win, width=W, height=BAR_H, bg=C["bar"], highlightthickness=0, cursor="none")
        bar.place(x=0, y=0)
        bar.create_text(M, BAR_H // 2 + 1, text="WI-FI", font=font(17, True), fill=C["text"], anchor="w")
        self.verdict = tk.Canvas(self.win, width=W - 2 * M, height=VERDICT_H, bg=C["panel"],
                                 highlightthickness=0, cursor="none")
        self.verdict.place(x=M, y=TOP)
        self.show_list()
        self.rescan()

    # Worker threads schedule through root: the dialog may be closed meanwhile
    def ui(self, fn, *args):
        self.root.after(0, lambda: fn(*args) if self.win.winfo_exists() else None)

    def set_status(self, word, text=""):
        c = self.verdict
        c.delete("all")
        c.create_text(12, VERDICT_H // 2, text=word, font=font(22, True), fill=C[VERDICT.get(word, "text")],
                      anchor="w")
        c.create_text(190, VERDICT_H // 2, text=text, font=font(19), fill=C["text"], anchor="w")

    def clear_page(self):
        for w in self.widgets:
            w.destroy()
        self.widgets = []

    def add(self, w):
        self.widgets.append(w)
        return w

    def bottom(self, items, back_text, back_cmd):
        x = M
        free = W - M - BACK_W - G - x - G * (len(items) - 1) - sum(it[3] for it in items)
        for text, color, cmd, width in items:
            width += free // len(items)
            self.add(button(self.win, x, BTN_Y, width, BTN_H, text, color, cmd, "main", 17))
            x += width + G
        self.add(button(self.win, W - M - BACK_W, BTN_Y, BACK_W, BTN_H, back_text, C["back"], back_cmd,
                        "secondary", 17))

    # --- network list -----------------------------------------------------

    def show_list(self):
        self.clear_page()
        self.net = None
        lw = W - 2 * M - SIDE_W - G
        self.list_box = self.add(tk.Frame(self.win, bg=C["bg"], cursor="none"))
        self.list_box.place(x=M, y=BODY, width=lw, height=BOTTOM - BODY)
        half = (BOTTOM - BODY - G) // 2
        self.add(button(self.win, W - M - SIDE_W, BODY, SIDE_W, half, UP, C["panel2"],
                        lambda: self.turn(-1), "secondary", 22))
        self.add(button(self.win, W - M - SIDE_W, BODY + half + G, SIDE_W, BOTTOM - BODY - half - G, DOWN,
                        C["panel2"], lambda: self.turn(1), "secondary", 22))
        self.bottom([("RESCAN", C["gray"], self.rescan, 150),
                     ("CONNECT", C["go"], self.connect_selected, 150),
                     ("DISCONNECT", "#BF360C", self.disconnect, 150)], "CLOSE", self.close)
        self.draw_list()

    def turn(self, step):
        pages = max(1, (len(self.nets) + self.PER_PAGE - 1) // self.PER_PAGE)
        self.page_no = min(pages - 1, max(0, self.page_no + step))
        self.draw_list()

    def draw_list(self):
        if not self.list_box.winfo_exists():
            return
        for w in self.list_box.winfo_children():
            w.destroy()
        lw = W - 2 * M - SIDE_W - G
        rh = (BOTTOM - BODY - G * (self.PER_PAGE - 1)) // self.PER_PAGE
        first = self.page_no * self.PER_PAGE
        for k, net in enumerate(self.nets[first:first + self.PER_PAGE]):
            self.make_row(first + k, net, 0, k * (rh + G), lw, rh)
        if not self.nets:
            tk.Label(self.list_box, text="no networks yet", font=font(17), fg=C["muted"], bg=C["bg"]).place(x=12, y=12)

    def make_row(self, i, net, x, y, w, h):
        bg = C["sel"] if i == self.selected else C["panel"]
        row = tk.Frame(self.list_box, bg=bg, cursor="none")
        row.place(x=x, y=y, width=w, height=h)
        name = tk.Label(row, text=net["ssid"], font=font(19, True), bg=bg, anchor="w",
                        fg=C["good"] if net["inuse"] and i != self.selected else C["text"])
        name.place(x=14, y=6)
        tags = (["connected"] if net["inuse"] else []) + (["saved"] if net["ssid"] in self.profiles else []) + \
               ["secured" if net["secure"] else "open"]
        info = tk.Label(row, text=("  %s  " % MID).join(tags), font=font(14), fg=C["muted"], bg=bg, anchor="w")
        info.place(x=14, y=h - 26)
        bars = tk.Canvas(row, width=36, height=30, bg=bg, highlightthickness=0, cursor="none")
        level = min(4, (net["signal"] + 24) // 25)
        for b in range(4):
            bh = 8 + b * 7
            bars.create_rectangle(b * 9, 30 - bh, b * 9 + 6, 30, width=0,
                                  fill=C["accent"] if b < level else C["line"])
        bars.place(x=w - 50, y=(h - 30) // 2)
        pct = tk.Label(row, text="%d%%" % net["signal"], font=font(16), fg=C["muted"], bg=bg, anchor="e")
        pct.place(x=w - 110, y=(h - 22) // 2, width=52)
        row.role = "secondary"
        for wdg in (row, name, info, bars, pct):
            wdg.bind("<Button-1>", lambda e, k=i: self.select(k))

    def select(self, i):
        self.selected = i
        self.draw_list()

    def rescan(self):
        self.set_status("SCANNING", "looking for networks" + chr(0x2026))

        def task():
            profiles = saved_profiles()
            nets, err = scan()
            self.ui(self.scan_done, profiles, nets, err)

        threading.Thread(target=task, daemon=True).start()

    def scan_done(self, profiles, nets, err):
        if nets is None:
            self.set_status("FAIL", "scan failed: %s" % err[:50])
            return
        self.profiles, self.nets, self.selected, self.page_no = profiles, nets, None, 0
        if self.net is None:
            self.draw_list()
            self.show_current()

    def show_current(self):
        ssid, ip = wifi_status()
        if ssid:
            self.set_status("OK", "connected to %s, %s" % (ssid, ip or "no IP"))
        else:
            self.set_status("OFF", "not connected")

    def connect_selected(self):
        if self.selected is None:
            self.set_status("INFO", "tap a network first")
            return
        net = self.nets[self.selected]
        if net["ssid"] in self.profiles:
            self.run_connect(["con", "up", "id", self.profiles[net["ssid"]]], net, ask_on_fail=True)
        elif not net["secure"]:
            self.run_connect(["dev", "wifi", "connect", net["ssid"], "ifname", "wlan0"], net)
        else:
            self.show_password(net)

    # --- password ---------------------------------------------------------

    def show_password(self, net):
        self.clear_page()
        self.net, self.password, self.show_pw = net, "", False
        self.kbd = OnScreenKeyboard(self.win, M, BODY, W - 2 * M, BOTTOM - BODY, self.key)
        self.widgets.extend([_KeysHolder(self.kbd)])
        self.bottom([("SHIFT", C["panel2"], self.kbd.toggle_caps, 80),
                     ("?123", C["panel2"], self.kbd.toggle_layout, 80),
                     ("SPACE", C["panel2"], lambda: self.key(" "), 120),
                     ("DEL", C["back"], self.backspace, 80),
                     ("SHOW", C["gray"], self.toggle_show, 80),
                     ("CONNECT", C["go"], self.connect_password, 100)], "BACK", self.back_to_list)
        self.show_typed()

    def key(self, ch):
        if len(self.password) < 63:
            self.password += ch
        self.show_typed()

    def backspace(self):
        self.password = self.password[:-1]
        self.show_typed()

    def toggle_show(self):
        self.show_pw = not self.show_pw
        self.show_typed()

    def show_typed(self):
        shown = self.password if self.show_pw else DOT * len(self.password)
        self.set_status("PASSWORD", "%s: %s_" % (self.net["ssid"][:14], shown[-24:]))

    def connect_password(self):
        self.run_connect(["dev", "wifi", "connect", self.net["ssid"], "password", self.password,
                          "ifname", "wlan0"], self.net)

    def back_to_list(self):
        self.show_list()
        self.show_current()

    # --- actions ----------------------------------------------------------

    def run_connect(self, args, net, ask_on_fail=False):
        self.set_status("RUNNING", "connecting to %s" % net["ssid"])

        def task():
            code, out = nmcli("-w", "30", *args)
            self.ui(self.connect_done, code, out, net, ask_on_fail)

        threading.Thread(target=task, daemon=True).start()

    def connect_done(self, code, out, net, ask_on_fail):
        if code == 0:
            self.log("[OK] Wi-Fi connected to %s" % net["ssid"])
            self.show_list()
            self.rescan()
        elif ask_on_fail and net["secure"]:
            self.log("[FAIL] Wi-Fi %s: saved profile failed, asking for password" % net["ssid"])
            self.show_password(net)
            self.set_status("FAIL", "saved password failed, type it again")
        else:
            self.log("[FAIL] Wi-Fi %s: %s" % (net["ssid"], out))
            self.set_status("FAIL", out[-50:])

    def disconnect(self):
        self.set_status("RUNNING", "disconnecting")

        def task():
            code, out = nmcli("dev", "disconnect", "wlan0")
            self.log("[%s] Wi-Fi disconnect: %s" % ("OK" if code == 0 else "FAIL", out))
            self.ui(self.rescan)

        threading.Thread(target=task, daemon=True).start()

    def close(self):
        self.win.destroy()
        if self.on_close:
            self.on_close()


class _KeysHolder:
    """Lets clear_page() remove the keyboard keys together with the other page widgets."""

    def __init__(self, kbd):
        self.kbd = kbd

    def destroy(self):
        for b in self.kbd.keys:
            b.destroy()
        self.kbd.keys = []
