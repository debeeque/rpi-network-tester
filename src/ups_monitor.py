import argparse
import os
import signal
import subprocess
import sys
import time
from datetime import datetime

from smbus import SMBus

REG_SHUNT = 0x01
REG_BUS = 0x02
SHUNT_OHM = 0.010

# Pack path resistance, from voltage steps between charger and battery operation
R_PACK = 0.25
# Energy delivered down to 9.6 V in the discharge test of 25-26.09.2026
E_FULL_WH = 28.2
# Load-compensated voltage (V + |I| * R_PACK) versus remaining energy, same test
CURVE = [
    (9.707, 0), (10.024, 5), (10.340, 10), (10.538, 15), (10.683, 20),
    (10.821, 25), (10.947, 30), (11.079, 35), (11.215, 40), (11.341, 45),
    (11.454, 50), (11.556, 55), (11.652, 60), (11.757, 65), (11.879, 70),
    (12.015, 75), (12.136, 80), (12.202, 85), (12.234, 90), (12.274, 95),
    (12.409, 100),
]
I_CHARGING = 0.02
I_EXTERNAL = -0.20
V_EMPTY = 9.6


def swap(word):
    return ((word & 0xFF) << 8) | (word >> 8)


def read_once(bus, addr):
    raw = swap(bus.read_word_data(addr, REG_SHUNT))
    if raw & 0x8000:
        raw -= 0x10000
    v_bus = (swap(bus.read_word_data(addr, REG_BUS)) >> 3) * 0.004
    return v_bus, raw * 10e-6 / SHUNT_OHM


def sample(bus, addr, n):
    vs, cs = [], []
    for _ in range(n):
        try:
            v, i = read_once(bus, addr)
        except OSError:
            continue
        vs.append(v)
        cs.append(i)
        time.sleep(0.02)
    if not vs:
        return None
    return sum(vs) / len(vs), sum(cs) / len(cs)


def percent(v, i):
    vr = v - i * R_PACK
    if vr <= CURVE[0][0]:
        return 0.0
    for (v0, p0), (v1, p1) in zip(CURVE, CURVE[1:]):
        if vr <= v1:
            return p0 + (p1 - p0) * (vr - v0) / (v1 - v0)
    return 100.0


def source(i):
    if i > I_CHARGING:
        return "CHG"
    if i > I_EXTERNAL:
        return "AC"
    return "BAT"


def status(v, i, p_avg):
    pct, src = percent(v, i), source(i)
    mins = None
    if src == "BAT" and p_avg < 0:
        mins = pct / 100 * E_FULL_WH / -p_avg * 60
    line = (f"BATTERY V={v:.2f} I={i:.2f} P={v * i:.1f} PCT={pct:.0f} "
            f"SRC={src} MIN={'-' if mins is None else f'{mins:.0f}'}")
    return line, pct, src, mins


def one_shot(bus, args):
    s = sample(bus, args.addr, args.samples)
    if s is None:
        print("BATTERY ERROR")
        return 1
    v, i = s
    line, pct, src, mins = status(v, i, v * i)
    print(f"Bus voltage: {v:.3f} V")
    print(f"Current:     {i:+.3f} A")
    print(f"Power:       {v * i:+.2f} W")
    print(f"Charge:      {pct:.0f} % ({src})")
    if mins is not None:
        print(f"Time left:   {int(mins) // 60} h {int(mins) % 60:02d} min")
    print(line)
    return 0


def write(f, line):
    f.write(line + "\n")
    f.flush()
    os.fsync(f.fileno())


def write_status(path, line):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(line + "\n")
    os.replace(tmp, path)


def monitor(bus, args):
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    log = ev = None
    if args.log:
        new = not os.path.exists(args.log) or os.path.getsize(args.log) == 0
        log = open(args.log, "a")
        if new:
            write(log, "t_mono_s,v_bus,i,p")
    if args.events:
        ev = open(args.events, "a")

    def event(text):
        t = time.monotonic()
        stamp = datetime.now().astimezone().isoformat(timespec="seconds")
        print(f"{stamp} {text}", flush=True)
        if log:
            write(log, f"# {t:.1f} {stamp} {text}")
        if ev:
            write(ev, f"{stamp} mono={t:.1f} {text}")

    event(f"start interval={args.interval} threshold={args.threshold} count={args.count}")
    low = 0
    p_avg = None
    next_t = time.monotonic()
    try:
        while True:
            s = sample(bus, args.addr, args.samples)
            t = time.monotonic()
            if s is None:
                print("read error", flush=True)
                if log:
                    write(log, f"# {t:.1f} read error")
            else:
                v, i = s
                p = v * i
                if p_avg is None or (p < 0) != (p_avg < 0):
                    p_avg = p
                else:
                    p_avg += 0.1 * (p - p_avg)
                if log:
                    write(log, f"{t:.1f},{v:.3f},{i:.3f},{p:.2f}")
                low = low + 1 if v < args.threshold else 0
                if args.status:
                    write_status(args.status, f"{status(v, i, p_avg)[0]} LOW={low}")
                if low >= args.count:
                    event(f"shutdown: v_bus < {args.threshold} V in {low} consecutive readings")
                    if args.dry_run:
                        low = 0
                    else:
                        subprocess.run(["sudo", "shutdown", "-h", "now"])
                        return 0
            next_t += args.interval
            time.sleep(max(0.0, next_t - time.monotonic()))
    finally:
        event("stop")
        for f in (log, ev):
            if f:
                f.close()


def main():
    parser = argparse.ArgumentParser(description="UPS Module 3S telemetry via INA219")
    parser.add_argument("--bus", type=int, default=3)
    parser.add_argument("--addr", type=lambda x: int(x, 0), default=0x41)
    parser.add_argument("--samples", type=int, default=20)
    parser.add_argument("--log")
    parser.add_argument("--status")
    parser.add_argument("--events")
    parser.add_argument("--interval", type=float, default=10)
    parser.add_argument("--threshold", type=float, default=V_EMPTY)
    parser.add_argument("--count", type=int, default=3)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    bus = SMBus(args.bus)
    if args.log or args.status or args.events:
        return monitor(bus, args)
    return one_shot(bus, args)


if __name__ == "__main__":
    sys.exit(main())
