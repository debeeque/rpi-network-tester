import sys

from scapy.all import *

# Interface and target network configuration
iface = sys.argv[1] if len(sys.argv) > 1 else "eth2"
ip_range = sys.argv[2] if len(sys.argv) > 2 else "10.0.2.0/24"

print(f"Scanning {ip_range} on {iface}...")

try:
    own = get_if_hwaddr(iface).lower()

    # Send ARP requests and capture responses
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_range),
                     iface=iface, timeout=2, verbose=False)

    target = None
    hosts = [r for s, r in ans if r.hwsrc.lower() != own]

    print(f"Found {len(hosts)} devices:")
    for received in hosts:
        print(f"IP: {received.psrc}  MAC: {received.hwsrc}")
        if target is None:
            target = received.psrc

    print(f"TARGET4: {target or 'none'}")

except Exception as e:
    print(f"Error: {e}")
