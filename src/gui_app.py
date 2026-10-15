import tkinter as tk
import collections
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time

import results
from wifi_dialog import WifiDialog, wifi_status
from ui_kit import C, G, H, M, PORTS, TOP, W, StatusBar, button, font
from screens import (DhcpScreen, FunctionScreen, Ipv6Screen, KeypadScreen, PathScreen, ScanScreen, SystemScreen,
                     TargetScreen)
from speed import SpeedScreen, SweepScreen
from generator import GeneratorScreen
from port import PortScreen
from autotest_screen import AutotestLogScreen, AutotestScreen
from traffic import FilterScreen, HostScreen, PacketScreen, PausedScreen, TrafficScreen

BASE_DIR = "/home/muk0015/diploma_project"
UPS_STATUS = "/run/ups/status"
PORT_STATUS = "/run/analyzer/ports.json"
WELCOME_BG = os.path.join(BASE_DIR, "assets", "welcome_bg.png")
AUTO_LOCK_S = 600
SCREEN_OFF_S = 30
# Exit code that tells ~/.xinitrc to start the desktop instead of restarting the GUI
SERVICE_EXIT = 3
if os.path.exists(BASE_DIR):
    os.chdir(BASE_DIR)

TILES = [
    ("AUTOTEST", "link, DHCP, IPv6, gateway, DNS, targets", "#1E88E5", AutotestScreen),
    ("TRAFFIC", "live capture, protocols, top talkers, PCAP", "#00ACC1", TrafficScreen),
    ("GENERATOR", "ICMP, ICMPv6, UDP, TCP SYN, ARP, RS", "#00ACC1", GeneratorScreen),
    ("SPEED", "iperf3 TCP and UDP, sweep, server", "#1E88E5", SpeedScreen),
    ("PORT", "speed, duplex, partner modes, LLDP, VLAN", "#43A047", PortScreen),
    ("SCAN", "ARP, IPv6 neighbours, Nmap", "#43A047", ScanScreen),
    ("IPv6", "Router Advertisement audit", "#43A047", Ipv6Screen),
    ("PATH", "ping IPv4 and IPv6", "#1E88E5", PathScreen),
    ("WATCH", "periodic ping or TCP, history graph", "#1E88E5", None),
    ("RESULTS", "saved tests, export to USB", "#78909C", None),
    ("DHCP / RA", "serve addresses on the test ports", "#FB8C00", DhcpScreen),
    ("SYSTEM", "Wi-Fi, lock, desktop, power off", "#78909C", SystemScreen),
]
PAGES = {"TARGET": TargetScreen, "KEYPAD": KeypadScreen, "PAUSED": PausedScreen, "PACKET": PacketScreen,
         "FILTER": FilterScreen, "HOSTS": HostScreen, "SWEEP": SweepScreen,
         "AUTOTEST_LOG": AutotestLogScreen}


class AnalyzerApp:
    PORTS = {
        "mon0": {"ns": "analyzer_monitor", "iface": "mon0", "net4": "10.0.1.0/24",
                 "v4": "10.0.1.20", "v6": "fd00:1::20"},
        "snd0": {"ns": "analyzer_sender", "iface": "snd0", "net4": "10.0.2.0/24",
                 "v4": "10.0.2.20", "v6": "fd00:2::20"},
    }

    def __init__(self, root):
        self.root = root
        self.root.title("Portable Network Analyzer")
        self.root.geometry("%dx%d" % (W, H))
        # Kiosk mode: no title bar to hit on a resistive touchscreen
        self.root.attributes('-fullscreen', True)
        self.root.config(cursor="none", bg=C["bg"])

        self.found = {}
        self.scan_target = ""
        self.jobs = {}
        self.notes = {}
        self.screens = {}
        self.current = None
        self.status = {}
        self.ssid = self.wifi_ip = None
        self.welcome = self.catcher = self.wifi = None
        self.welcome_gen = 0
        self.locked = self.screen_off = False
        self.last_touch = time.monotonic()

        self.build_home()
        self.home()
        self.show_welcome()
        self.root.bind_all("<ButtonPress>", self.touched, add="+")
        try:
            # DPMS on with zero timeouts: the screen goes off only when locked
            subprocess.run(["xset", "+dpms", "dpms", "0", "0", "0"], timeout=5)
        except (OSError, subprocess.SubprocessError):
            pass
        self.root.after(5000, self.idle_check)
        self.tick()
        self.wifi_tick()

    # Tk widgets must only be touched from the main thread
    def ui(self, fn, *args, **kwargs):
        self.root.after(0, lambda: fn(*args, **kwargs))

    # --- navigation -------------------------------------------------------

    def build_home(self):
        f = tk.Frame(self.root, bg=C["bg"], width=W, height=H, cursor="none")
        f.bar = StatusBar(f, "NETWORK ANALYZER")
        cols, rows = 4, 3
        tw = (W - 2 * M - G * (cols - 1)) // cols
        th = (H - M - TOP - G * (rows - 1)) // rows
        f.tiles = {}
        for i, (name, sub, accent, cls) in enumerate(TILES):
            x = M + (i % cols) * (tw + G)
            y = TOP + (i // cols) * (th + G)
            f.tiles[name] = self.make_tile(f, x, y, tw, th, name, sub, accent, cls is not None)
        self.screens["HOME"] = f

    def make_tile(self, parent, x, y, w, h, name, sub, accent, ready):
        bg = C["panel"]
        t = tk.Frame(parent, bg=bg, cursor="none")
        t.place(x=x, y=y, width=w, height=h)
        tk.Frame(t, bg=accent if ready else C["dim"]).place(x=0, y=0, width=6, relheight=1)
        title = tk.Label(t, text=name, font=font(19, True), fg=C["text"] if ready else C["dim"], bg=bg, anchor="w")
        title.place(x=16, y=10)
        tk.Label(t, text=sub, font=font(14), fg=C["muted"] if ready else C["dim"], bg=bg, anchor="nw",
                 justify="left", wraplength=w - 28).place(x=16, y=41)
        line = tk.Frame(t, bg=bg)
        line.place(x=16, y=h - 32)
        t.word = tk.Label(line, font=font(16, True), bg=bg, fg=C["muted"])
        t.word.pack(side="left")
        t.rest = tk.Label(line, font=font(15), bg=bg, fg=C["muted"])
        t.rest.pack(side="left")
        t.role = "main"
        if ready:
            for wdg in (t, title, line, t.word, t.rest) + tuple(t.winfo_children()):
                wdg.bind("<Button-1>", lambda e, n=name: self.open(n))
            t.word.config(text="ready")
        else:
            t.word.config(text="not yet", fg=C["dim"])
        return t

    def open(self, name):
        if name not in self.screens:
            cls = PAGES.get(name) or next(c for n, s, a, c in TILES if n == name)
            s = cls(self)
            self.screens[name] = s
        self.show(name)

    def home(self):
        self.show("HOME")

    def show(self, name):
        s = self.screens[name]
        s.place(x=0, y=0, width=W, height=H)
        s.tkraise()
        if self.welcome is not None:
            self.welcome.tkraise()
        for other, o in self.screens.items():
            if other != name:
                o.place_forget()
        self.current = name
        if name == "HOME":
            self.refresh_tiles()
        elif hasattr(s, "shown"):
            s.shown()
        s.bar.draw(self.status)
        if hasattr(s, "port_labels"):
            s.port_labels(self.port_state().get("ports", {}))

    def note(self, tile, word, text, rest):
        self.notes[tile] = (word, text, rest)

    # Verdicts, logs and tile notes; discovered targets stay, a screen with a running test is kept
    def clear_results(self):
        self.notes.clear()
        busy = [job["screen"] for job in self.jobs.values()]
        for s in self.screens.values():
            if not isinstance(s, FunctionScreen) or s in busy:
                continue
            if s.logbox:
                s.logbox.config(state="normal")
                s.logbox.delete("1.0", "end")
                s.logbox.config(state="disabled")
            s.set_verdict("IDLE", "")
        return len(busy)

    def refresh_tiles(self):
        colors = {"PASS": "good", "OK": "good", "WARN": "warn", "FAIL": "bad", "INFO": "text", "ON": "warn",
                  "OFF": "muted"}
        st = self.port_state()
        for name, sub, accent, cls in TILES:
            if cls is not None and name not in self.notes:
                self.screens["HOME"].tiles[name].word.config(text="ready", fg=C["muted"])
                self.screens["HOME"].tiles[name].rest.config(text="")
        self.notes["DHCP / RA"] = ("ON", "", " serving") if st.get("dhcp") else ("OFF", "", " ports silent")
        self.notes["SYSTEM"] = ("Wi-Fi", "", " " + self.ssid[:12]) if self.ssid else ("Wi-Fi", " off", "")
        for name, (word, text, rest) in self.notes.items():
            t = self.screens["HOME"].tiles.get(name)
            if t is not None:
                t.word.config(text=word + text, fg=C[colors.get(word, "text")])
                # The tile is ~190 px wide: drop the tail rather than cut it in half
                t.rest.config(text=rest if len(word + text + rest) <= 20 else "")

    # --- running scripts, one job per port --------------------------------

    # keep: how many output lines to hold for on_done; a live capture must not grow without bound
    def run(self, port, cmd, label, screen, on_line=None, on_done=None, keep=None):
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                    bufsize=1, start_new_session=True)
        except OSError as e:
            screen.set_verdict("FAIL", str(e)[:60])
            if on_done:
                on_done(-1, "", False)
            return
        job = {"proc": proc, "label": label, "start": time.monotonic(), "screen": screen}
        self.jobs[port] = job
        self.progress(port, job)

        def reader():
            lines = collections.deque(maxlen=keep)
            for line in proc.stdout:
                lines.append(line)
                if on_line:
                    self.ui(on_line, line)
            rc = proc.wait()
            self.ui(finish, rc, "".join(lines))

        def finish(rc, out):
            job = self.jobs.pop(port, None)
            if on_done:
                on_done(rc, out, bool(job and job.get("stopped")))

        threading.Thread(target=reader, daemon=True).start()

    def progress(self, port, job):
        if self.jobs.get(port) is not job:
            return
        secs = int(time.monotonic() - job["start"])
        job["screen"].set_verdict("RUNNING", "%s, %d s" % (job["label"], secs))
        self.root.after(1000, self.progress, port, job)

    # sudo relays SIGINT to the command, which prints its summary and exits
    def stop(self, port):
        job = self.jobs.get(port)
        if job:
            job["stopped"] = True
            try:
                job["proc"].send_signal(signal.SIGINT)
            except OSError:
                pass

    # --- data for screens -------------------------------------------------

    def save_result(self, script, port, result):
        try:
            path = results.save(script, port, result)
        except OSError as e:
            print("save failed:", e, flush=True)
            return None
        return path

    # Written by analyzer-status.service on every link or address change
    def port_state(self):
        try:
            if time.time() - os.path.getmtime(PORT_STATUS) < 30:
                with open(PORT_STATUS) as f:
                    return json.load(f)
        except (OSError, ValueError):
            pass
        return {}

    def device_macs(self):
        ports = self.port_state().get("ports", {})
        return ",".join(p["mac"] for p in ports.values() if p.get("mac"))

    def wifi_gateway(self):
        try:
            out = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=3).stdout
        except (OSError, subprocess.SubprocessError):
            return None
        m = re.search(r"via (\S+)", out)
        return m.group(1) if m else None

    # Written every 10 s by the ups-monitor service; stale means the service is down
    def ups(self):
        try:
            if time.time() - os.path.getmtime(UPS_STATUS) < 30:
                with open(UPS_STATUS) as f:
                    return dict(re.findall(r"(\w+)=(\S+)", f.read()))
        except OSError:
            pass
        return {}

    def battery_text(self):
        fields = self.ups()
        try:
            pct = int(fields["PCT"])
            src = fields.get("SRC", "BAT")
            if src != "BAT":
                return f"{pct}% {'charging' if src == 'CHG' else 'AC'}", "darkgreen"
            mins = fields.get("MIN", "-")
            left = f" ~{int(mins) // 60}h{int(mins) % 60:02d}" if mins.isdigit() else ""
            low = pct < 10 or fields.get("LOW", "0") != "0"
            return f"{pct}%{left}", "red" if low else "orange" if pct < 25 else "green"
        except (KeyError, ValueError):
            return "--", "gray"

    def battery_level(self):
        fields = self.ups()
        try:
            pct = int(fields["PCT"])
        except (KeyError, ValueError):
            return None, C["dim"]
        if fields.get("SRC") != "BAT":
            return pct, C["good"]
        return pct, C["bad"] if pct < 10 else C["warn"] if pct < 25 else C["good"]

    def system_info(self):
        ups = self.ups()
        rows = [("Wi-Fi", "%s, %s" % (self.ssid, self.wifi_ip or "no IP") if self.ssid else "not connected")]
        if ups:
            rows.append(("Battery", "%s %%, %s V, %s A, %s" % (ups.get("PCT"), ups.get("V"), ups.get("I", "").lstrip("-"),
                                                              {"CHG": "charging", "AC": "on charger"}.get(ups.get("SRC"), "on battery"))))
        try:
            temp = subprocess.run(["vcgencmd", "measure_temp"], capture_output=True, text=True, timeout=3).stdout
            thr = subprocess.run(["vcgencmd", "get_throttled"], capture_output=True, text=True, timeout=3).stdout
            rows.append(("SoC", "%s, %s" % (temp.strip().replace("temp=", ""), thr.strip())))
        except (OSError, subprocess.SubprocessError):
            pass
        with open("/proc/uptime") as f:
            up = int(float(f.read().split()[0]))
        rows.append(("Uptime", "%d h %02d min" % (up // 3600, up % 3600 // 60)))
        rows.append(("Clock", time.strftime("%d.%m.%Y %H:%M %Z")))
        st = self.port_state()
        for port in PORTS:
            p = st.get("ports", {}).get(port, {})
            if p.get("present"):
                rows.append((port, "%s, %s" % (p.get("mac"), ", ".join(p.get("addr4", [])) or "no IPv4")))
            else:
                rows.append((port, "adapter not plugged in"))
        spare = st.get("spare", [])
        if spare:
            rows.append(("Spare", "%s, not used" % ", ".join(a["mac"] for a in spare)))
        return rows

    def tick(self):
        st = self.port_state()
        self.status = {"ports": st.get("ports", {}), "dhcp": st.get("dhcp", False),
                       "ssid": self.ssid, "time": time.strftime("%H:%M"), "battery": self.battery_level()}
        if self.current in self.screens:
            self.screens[self.current].bar.draw(self.status)
            if hasattr(self.screens[self.current], "port_labels"):
                self.screens[self.current].port_labels(self.status["ports"])
        if self.current == "HOME":
            self.refresh_tiles()
        self.root.after(2000, self.tick)

    def wifi_tick(self):
        def task():
            ssid, ip = wifi_status()
            self.ssid, self.wifi_ip = ssid, ip
        threading.Thread(target=task, daemon=True).start()
        self.root.after(10000, self.wifi_tick)

    # --- welcome and lock screen ------------------------------------------

    # Welcome screen doubles as the lock screen; drawn on a canvas so text sits on the wallpaper
    def show_welcome(self, locked=False):
        if self.welcome is not None and self.welcome.winfo_exists():
            self.btn_start.config(text="UNLOCK" if locked else "START")
            return
        self.welcome_gen += 1
        c = tk.Canvas(self.root, width=800, height=480, bg="#0B2A30", highlightthickness=0, cursor="none")
        c.place(x=0, y=0, relwidth=1, relheight=1)
        self.welcome = c
        try:
            self.bg_image = tk.PhotoImage(file=WELCOME_BG)
            c.create_image(0, 0, image=self.bg_image, anchor="nw")
        except tk.TclError:
            pass

        x = 480
        c.create_text(x, 40, text="Portable Network", font=('Arial', 24, 'bold'), fill="white", anchor="nw")
        c.create_text(x, 72, text="Analyzer", font=('Arial', 24, 'bold'), fill="white", anchor="nw")
        c.create_text(x, 114, text="Testing and monitoring networks", font=('Arial', 11), fill="#9FC5C9", anchor="nw")
        self.welcome_info = {}
        for i, key in enumerate(("Battery", "Ports", "Wi-Fi")):
            y = 156 + i * 24
            c.create_text(x, y, text=key, font=('Arial', 11), fill="#7FA7AD", anchor="nw")
            self.welcome_info[key] = c.create_text(x + 68, y, text="...", font=('Arial', 11), fill="white", anchor="nw")

        self.btn_start = tk.Button(c, text="UNLOCK" if locked else "START", bg="#43A047", fg="white", bd=0,
                                   activebackground="#2E7D32", activeforeground="white", font=('Arial', 18, 'bold'), command=self.unlock)
        c.create_window(x, 232, window=self.btn_start, anchor="nw", width=300, height=70)
        wifi = tk.Button(c, text="WI-FI", bg="#0277BD", fg="white", bd=0, activebackground="#0277BD", activeforeground="white", font=('Arial', 12, 'bold'), command=self.open_wifi)
        c.create_window(x, 312, window=wifi, anchor="nw", width=145, height=60)
        self.btn_off = tk.Button(c, text="POWER OFF", bg="#E53935", fg="white", bd=0, font=('Arial', 12, 'bold'),
                                 activebackground="#E53935", activeforeground="white", command=self.welcome_power_off)
        c.create_window(x + 155, 312, window=self.btn_off, anchor="nw", width=145, height=60)
        self.off_armed = False
        c.create_text(12, 468, text="Mikhail Mukanov  |  2027", font=('Arial', 9), fill="#5E8A90", anchor="w")
        self.update_welcome(self.welcome_gen)

    def update_welcome(self, gen):
        if gen != self.welcome_gen or self.welcome is None:
            return
        state = self.port_state()
        ports = []
        for port in PORTS:
            p = state.get("ports", {}).get(port, {})
            text = "absent" if not p.get("present") else f"{p['speed']}" if p.get("carrier") and p.get("speed") else "no link"
            ports.append(f"{port} {text}")
        values = {"Battery": self.battery_text()[0],
                  "Ports": f"{', '.join(ports)}, DHCP {'on' if state.get('dhcp') else 'off'}",
                  "Wi-Fi": f"{self.ssid} ({self.wifi_ip or 'no IP'})" if self.ssid else "not connected"}
        for key, text in values.items():
            self.welcome.itemconfig(self.welcome_info[key], text=text)
        self.root.after(3000, self.update_welcome, gen)

    def welcome_power_off(self):
        if self.off_armed:
            self.power_off()
            return
        self.off_armed = True
        self.btn_off.config(text="TAP AGAIN\nTO CONFIRM", bg=C["stop"], activebackground=C["stop"])
        self.root.after(4000, self.welcome_disarm)

    def welcome_disarm(self):
        if self.off_armed and self.welcome is not None:
            self.btn_off.config(text="POWER OFF", bg="#E53935", activebackground="#E53935")
        self.off_armed = False

    def unlock(self):
        self.locked = False
        if self.welcome is not None:
            self.welcome.destroy()
            self.welcome = None

    # Screen off is DPMS through X: saves 0.35 W of 4.5 W (measured 26.09.2026);
    # the backlight has only a mechanical switch and stays lit
    def touched(self, event=None):
        self.last_touch = time.monotonic()

    def idle_check(self):
        idle = time.monotonic() - self.last_touch
        if not self.locked and idle > AUTO_LOCK_S:
            self.lock()
        elif self.locked and not self.screen_off and idle > SCREEN_OFF_S:
            self.display(False)
        self.root.after(5000, self.idle_check)

    def lock(self):
        if self.wifi and self.wifi.win.winfo_exists():
            self.wifi.win.destroy()
        self.locked = True
        self.show_welcome(locked=True)
        self.display(False)

    def display(self, on):
        self.screen_off = not on
        if on:
            if self.catcher is not None:
                self.catcher.destroy()
                self.catcher = None
        elif self.catcher is None:
            # Swallows the waking tap so it cannot press a button on the lock screen
            self.catcher = tk.Frame(self.root, bg="black", cursor="none")
            self.catcher.place(x=0, y=0, relwidth=1, relheight=1)
            self.catcher.bind("<ButtonPress>", lambda e: self.display(True))
        try:
            subprocess.run(["xset", "dpms", "force", "on" if on else "off"], timeout=5)
        except (OSError, subprocess.SubprocessError):
            pass

    # --- system -----------------------------------------------------------

    def open_wifi(self):
        self.wifi = WifiDialog(self.root, print)

    def stop_all(self):
        for port in list(self.jobs):
            self.stop(port)

    def power_off(self):
        self.stop_all()
        subprocess.Popen(["sudo", "shutdown", "-h", "now"])

    def service_mode(self):
        self.close_app(SERVICE_EXIT)

    def close_app(self, code=0):
        self.stop_all()
        self.root.destroy()
        sys.exit(code)


if __name__ == "__main__":
    root = tk.Tk()
    app = AnalyzerApp(root)
    root.mainloop()
