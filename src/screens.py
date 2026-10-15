import re
import time
import tkinter as tk

import results

from ui_kit import BOTTOM, C, G, M, PORTS, W, Screen, button, font, short


class FunctionScreen(Screen):
    """Screen whose actions run one script at a time on the selected port."""

    def launch(self, key, cmd, label, on_done, port=None, script=None):
        """script: its RESULT line is saved to ~/results and handed to on_done(rc, out, result)."""
        port = port or self.port
        busy = self.app.jobs.get(port)
        if busy:
            self.set_verdict("BUSY", "%s is running %s" % (port, busy["label"]))
            return False
        self.log("-" * 60)
        self.log("%s  %s" % (time.strftime("%H:%M:%S"), label))
        self.running(key, lambda: self.app.stop(port))
        start = time.monotonic()

        # A stopped test has no valid result: the partial output would mislead the verdict
        def done(rc, out, stopped):
            self.idle(key)
            res = results.parse_result(out, script[:-3]) if script else None
            if res is not None:
                path = self.app.save_result(script, port, res)
                if path:
                    self.log("Saved %s" % path.replace("/home/muk0015/", "~/"))
            if stopped:
                secs = int(time.monotonic() - start)
                self.log("Stopped by user after %d s" % secs)
                self.set_verdict("STOPPED", "by user after %d s on %s" % (secs, port))
                return
            if script:
                on_done(rc, out, res)
            else:
                on_done(rc, out)

        self.app.run(port, cmd, label, self, on_line=self.show_line, on_done=done)
        return True

    def show_line(self, line):
        if not line.startswith("RESULT "):
            self.log(line)

    # Scripts without a RESULT line: the screen's own summary plus the raw output
    def save(self, script, data, out, port=None):
        data = dict(data, output=out.splitlines()[-400:])
        path = self.app.save_result(script, port or self.port, data)
        if path:
            self.log("Saved %s" % path.replace("/home/muk0015/", "~/"))

    def netns(self, cmd):
        cfg = self.app.PORTS[self.port]
        return ["sudo", "ip", "netns", "exec", cfg["ns"]] + cmd


class PathScreen(FunctionScreen):
    def __init__(self, app):
        super().__init__(app, "PATH")
        self.make_log(self.body)
        self.bottom([("v4", "PING v4", "#E64A19", lambda: self.start("v4"), 130),
                     ("v6", "PING v6", "#BF360C", lambda: self.start("v6"), 130)])

    def start(self, family):
        target = self.app.found.get(self.port, {}).get(family)
        cfg = self.app.PORTS[self.port]
        cmd = self.netns(["python3", "path_test.py", cfg["iface"], target or "auto", "-" + family[1]])
        self.launch(family, cmd, "ping %s %s" % (family, target + " (found by SCAN)" if target else "auto"),
                    lambda rc, out, res: self.done(family, res), script="path_test.py")

    def done(self, family, res):
        if not res:
            self.set_verdict("FAIL", "no result, see the log")
            self.app.note("PATH", "FAIL", "", " " + family)
            return
        word = res.get("verdict", "FAIL")
        if res.get("received"):
            text = "%d/%d replies, avg %.1f ms" % (res["received"], res["sent"], res.get("rtt_avg", 0))
            self.app.note("PATH", word, " %d/%d, %.1f ms" % (res["received"], res["sent"], res.get("rtt_avg", 0)),
                          " " + family)
        else:
            text = res.get("short") or "no reply"
            self.app.note("PATH", word, "", " " + family)
        self.set_verdict(word, "%s  %s, %s" % (text, family, self.port))


class ScanScreen(FunctionScreen):
    def __init__(self, app):
        super().__init__(app, "SCAN")
        y = self.body
        self.target_btn = button(self, M, y, 440, 60, "", C["panel2"], lambda: app.open("TARGET"), "secondary", 17)
        self.mode = "LAN"
        button(self, M + 440 + G, y, 160, 60, "GATEWAY", C["panel2"], self.gateway, "secondary", 17)
        self.mode_btn = button(self, M + 608 + G, y, W - 2 * M - 616, 60, "", C["panel2"], self.toggle_mode,
                               "secondary", 17)
        self.make_log(y + 60 + G)
        self.bottom([("arp", "ARP", "#1E88E5", self.arp, 100),
                     ("neigh", "NEIGHBORS", "#0277BD", self.neighbours, 130),
                     ("nmap", "NMAP", "#37474F", self.nmap, 100)])
        self.show_target()

    def shown(self):
        self.show_target()

    def show_target(self):
        self.target_btn.config(text="Nmap target: %s" % (self.app.scan_target or "choose"))
        self.mode_btn.config(text="via " + ("test port" if self.mode == "LAN" else "Wi-Fi"))

    def toggle_mode(self):
        self.mode = "WIFI" if self.mode == "LAN" else "LAN"
        self.show_target()

    def gateway(self):
        gw = self.app.wifi_gateway()
        if gw:
            self.app.scan_target = gw
            self.mode = "WIFI"
            self.log("Gateway of the Wi-Fi network: %s, scanning via Wi-Fi" % gw)
        else:
            self.log("No default gateway: Wi-Fi is not connected")
        self.show_target()

    def arp(self):
        cfg = self.app.PORTS[self.port]
        cmd = self.netns(["python3", "arp_scan.py", cfg["iface"], cfg["net4"]])
        self.launch("arp", cmd, "ARP sweep of %s on %s" % (cfg["net4"], self.port), self.arp_done)

    def arp_done(self, rc, out):
        found = re.findall(r"^IP: (\S+)", out, re.M)
        self.remember(out)
        word = "PASS" if found else "INFO"
        self.set_verdict(word, "%d hosts answered ARP on %s" % (len(found), self.port))
        self.app.note("SCAN", word if found else "INFO", " %d hosts" % len(found), "")
        self.save("arp_scan.py", {"verdict": word, "hosts": found, "net4": self.app.PORTS[self.port]["net4"]}, out)

    def neighbours(self):
        cfg = self.app.PORTS[self.port]
        own = self.app.device_macs()
        script = "python3 neigh_scan.py %s%s; python3 arp_scan.py %s %s" % (
            cfg["iface"], " --own " + own if own else "", cfg["iface"], cfg["net4"])
        self.launch("neigh", self.netns(["sh", "-c", script]), "IPv6 neighbours and ARP on %s" % self.port,
                    self.neighbours_done)

    def neighbours_done(self, rc, out):
        store = self.remember(out)
        n = re.search(r"^Neighbours\s+:\s+(\d+)", out, re.M)
        text = "%s IPv6 neighbours; targets v4 %s, v6 %s" % (
            n.group(1) if n else "?", store.get("v4", "none"), short(store.get("v6", "none")))
        self.set_verdict("PASS" if store else "INFO", text)
        self.app.note("SCAN", "PASS" if store else "INFO", " %s neighbours" % (n.group(1) if n else "?"), "")
        self.save("neigh_scan.py", {"verdict": "PASS" if store else "INFO", "neighbours": int(n.group(1)) if n else None,
                                    "target4": store.get("v4"), "target6": store.get("v6")}, out)

    def remember(self, out):
        store = self.app.found.setdefault(self.port, {})
        m6 = re.search(r"^TARGET6\s+:\s+(\S+)", out, re.M)
        if m6 and m6.group(1) != "none":
            store["v6"] = m6.group(1)
        m4 = re.search(r"^TARGET4:\s+(\S+)", out, re.M)
        if m4 and m4.group(1) != "none":
            store["v4"] = m4.group(1)
            self.app.scan_target = store["v4"]
        self.show_target()
        return store

    def nmap(self):
        target = self.app.scan_target
        if not target:
            self.set_verdict("FAIL", "choose a target first")
            return
        # Nmap refuses an IPv6 literal without -6 and scans nothing
        base = ["nmap"] + (["-6"] if ":" in target else []) + \
               ["-F", "-sV", "-T4", "--max-retries", "1", "--host-timeout", "30s", target]
        if self.mode == "LAN":
            self.launch("nmap", self.netns(base), "Nmap %s on %s" % (target, self.port), self.nmap_done)
        else:
            self.launch("nmap", ["sudo"] + base, "Nmap %s via Wi-Fi" % target, self.nmap_done, port="wifi")

    def nmap_done(self, rc, out):
        ports = re.findall(r"^(\d+/\w+)\s+open\s+(\S+)", out, re.M)
        if "Nmap done: 0 IP addresses" in out:
            word, text = "FAIL", "nothing scanned: %s is not a valid target" % self.app.scan_target
        elif "Host seems down" in out or "0 hosts up" in out:
            word, text = "WARN", "host %s seems down" % self.app.scan_target
        elif "due to host timeout" in out:
            word, text = "WARN", "scan not finished: %s timed out after 30 s" % self.app.scan_target
        elif ports:
            word, text = "INFO", "%d open: %s" % (len(ports), ", ".join(p for p, _ in ports[:4]))
        else:
            word, text = "INFO", "no open ports among the 100 most common"
        self.set_verdict(word, text)
        self.save("nmap", {"verdict": word, "target": self.app.scan_target, "via": self.mode,
                           "open": ["%s %s" % p for p in ports]}, out,
                  port=self.port if self.mode == "LAN" else "wifi")


class TargetScreen(Screen):
    def __init__(self, app):
        super().__init__(app, "SCAN " + chr(0x00B7) + " TARGET", ports=False)
        self.set_verdict("INFO", "tap a target, or type one on the keypad")
        self.bottom([("keypad", "KEYPAD", "#00838F", lambda: app.open("KEYPAD"), 200)])
        self.items = []

    def shown(self):
        for b in self.items:
            b.destroy()
        self.items = []
        cand = []
        for port in PORTS:
            for fam in ("v4", "v6"):
                t = self.app.found.get(port, {}).get(fam)
                if t:
                    cand.append((t, "found on %s" % port))
        gw = self.app.wifi_gateway()
        if gw:
            cand.append((gw, "Wi-Fi gateway"))
        for port in PORTS:
            cand.append((self.app.PORTS[port]["v4"], "stand default, %s" % port))
        seen = set()
        cand = [c for c in cand if not (c[0] in seen or seen.add(c[0]))][:6]
        bw = (W - 2 * M - G) // 2
        bh = (BOTTOM - self.body - 2 * G) // 3
        for i, (addr, why) in enumerate(cand):
            x = M + (i % 2) * (bw + G)
            y = self.body + (i // 2) * (bh + G)
            b = button(self, x, y, bw, bh, "%s\n%s" % (short(addr), why), C["panel"],
                       lambda a=addr: self.pick(a), "main", 17)
            self.items.append(b)

    def pick(self, addr):
        self.app.scan_target = addr
        self.app.open("SCAN")


class KeypadScreen(Screen):
    KEYS = ["1", "2", "3", "a", "b", "4", "5", "6", "c", "d", "7", "8", "9", "e", "f", ".", "0", ":", "DEL", "CLR"]

    def __init__(self, app):
        super().__init__(app, "SCAN " + chr(0x00B7) + " KEYPAD", ports=False)
        self.value = ""
        self.verdict_canvas.config(bg=C["panel2"])
        cols = 5
        kw = (W - 2 * M - G * (cols - 1)) // cols
        kh = (BOTTOM - self.body - 3 * G) // 4
        for i, k in enumerate(self.KEYS):
            x = M + (i % cols) * (kw + G)
            y = self.body + (i // cols) * (kh + G)
            color = C["back"] if k in ("DEL", "CLR") else C["panel"]
            button(self, x, y, kw, kh, k, color, lambda k=k: self.press(k), "secondary", 24)
        self.bottom([("ok", "OK", C["go"], self.ok, 200)])

    def shown(self):
        self.value = self.app.scan_target or ""
        self.show()

    def show(self):
        self.set_verdict("TARGET", self.value + "_")

    def press(self, k):
        if k == "DEL":
            self.value = self.value[:-1]
        elif k == "CLR":
            self.value = ""
        elif len(self.value) < 39:
            self.value += k
        self.show()

    def ok(self):
        if self.value:
            self.app.scan_target = self.value
        self.app.open("SCAN")


class Ipv6Screen(FunctionScreen):
    def __init__(self, app):
        super().__init__(app, "IPv6")
        self.make_log(self.body)
        self.bottom([("ra", "RA SCAN", "#00695C", self.ra, 160)])

    def ra(self):
        cfg = self.app.PORTS[self.port]
        cmd = ["python3", "ra_audit.py", cfg["iface"], "-t", "5"]
        own = self.app.device_macs()
        if own:
            cmd += ["--own", own]
        self.launch("ra", self.netns(cmd), "Router Advertisement audit on %s" % self.port, self.ra_done)

    def ra_done(self, rc, out):
        m = re.search(r"^Routers\s+:\s+(\d+)", out, re.M)
        total = int(m.group(1)) if m else 0
        foreign = out.count("[FOREIGN]")
        alerts = len(re.findall(r"\[ALERT\]", out))
        if foreign:
            word, text = "WARN", "%d routers, %d foreign" % (total, foreign)
        elif total:
            word, text = "PASS", "%d router%s, this device" % (total, "s" if total > 1 else "")
        else:
            word, text = "INFO", "no Router Advertisement"
        if alerts:
            text += ", %d alerts" % alerts
        self.set_verdict(word, "%s on %s" % (text, self.port))
        self.app.note("IPv6", word, " %d router%s" % (total, "" if total == 1 else "s"),
                      ", %d foreign" % foreign if foreign else "")
        self.save("ra_audit.py", {"verdict": word, "routers": total, "foreign": foreign, "alerts": alerts}, out)


class DhcpScreen(FunctionScreen):
    def __init__(self, app):
        super().__init__(app, "DHCP / RA", ports=False)
        self.info = tk.Canvas(self, width=W - 2 * M, height=BOTTOM - self.body, bg=C["panel"],
                              highlightthickness=0, cursor="none")
        self.info.place(x=M, y=self.body)
        self.bottom([("toggle", "", C["go"], self.toggle, 200)])

    def shown(self):
        st = self.app.port_state()
        on = st.get("dhcp", False)
        b = self.actions["toggle"]
        text, color = ("TURN OFF", C["back"]) if on else ("TURN ON", "#FB8C00")
        b.config(text=text, bg=color, activebackground=color)
        b.base = (text, color, self.toggle)
        self.set_verdict("ON" if on else "OFF", "serving addresses and RA" if on else "ports are silent")
        c = self.info
        c.delete("all")
        lines = [("The device answers DHCP and sends Router Advertisements on both test ports.", "text"),
                 ("Turn it on only on the test bench or in your own network:", "text"),
                 ("in a foreign network the device becomes a second DHCP server and router.", "warn"),
                 ("", "text")]
        for port in PORTS:
            p = st.get("ports", {}).get(port, {})
            cfg = self.app.PORTS[port]
            state = "serving" if p.get("dhcp") else "silent"
            lines.append(("%s   %s   %s, pool %s" % (port, state, cfg["net4"], cfg["v4"]),
                          "good" if p.get("dhcp") else "muted"))
        for i, (t, color) in enumerate(lines):
            c.create_text(14, 18 + i * 30, text=t, font=font(17), fill=C[color], anchor="w")

    def toggle(self):
        on = self.app.port_state().get("dhcp", False)
        mode = "nodhcp" if on else "dhcp"
        self.launch("toggle", ["sudo", "./setup_network.sh", mode], "setup_network.sh " + mode,
                    lambda rc, out: self.after(1500, self.shown), port="dhcp")


class SystemScreen(Screen):
    def __init__(self, app):
        super().__init__(app, "SYSTEM", ports=False)
        self.info = tk.Canvas(self, width=W - 2 * M, height=BOTTOM - self.body, bg=C["panel"],
                              highlightthickness=0, cursor="none")
        self.info.place(x=M, y=self.body)
        self.bottom([("wifi", "WI-FI", "#0277BD", app.open_wifi, 110),
                     ("lock", "LOCK", C["gray"], app.lock, 100),
                     ("service", "DESKTOP", "#546E7A", app.service_mode, 110),
                     ("clear", "CLEAR\nRESULTS", C["action"], self.clear_results, 110),
                     ("off", "POWER\nOFF", "#E53935", self.power_off, 110)])
        self.armed = False

    def shown(self):
        self.armed = False
        self.idle("off")
        self.set_verdict("INFO", "device status")
        rows = self.app.system_info()
        c = self.info
        c.delete("all")
        for i, (k, v) in enumerate(rows):
            c.create_text(14, 20 + i * 32, text=k, font=font(17), fill=C["muted"], anchor="w")
            c.create_text(190, 20 + i * 32, text=v, font=font(17), fill=C["text"], anchor="w")

    def clear_results(self):
        kept = self.app.clear_results()
        self.set_verdict("OK", "results cleared" + (", %d running test kept" % kept if kept else ""))

    def power_off(self):
        if self.armed:
            self.app.power_off()
            return
        self.armed = True
        b = self.actions["off"]
        b.config(text="TAP AGAIN\nTO CONFIRM", bg=C["stop"], activebackground=C["stop"])
        self.set_verdict("WARN", "tap POWER OFF again within 4 s to shut down")
        self.after(4000, self.disarm)

    def disarm(self):
        if self.armed:
            self.armed = False
            self.idle("off")
            self.set_verdict("INFO", "device status")
