# 🔐 Network Security Attacks - PNETLab

**Autor:** [Tu Nombre]  
**Matrícula:** [Tu Matrícula]  
**Fecha:** 2026  
**Laboratorio:** Seguridad en Redes - PNETLab  

---

## 📋 Descripción

Repositorio de scripts de ataques de red implementados con **Scapy (Python)** en un entorno de laboratorio controlado con PNETLab.  
Cada ataque incluye su documentación técnica y contra-medida.

> ⚠️ **ADVERTENCIA LEGAL:** Estos scripts son únicamente para fines educativos en entornos controlados de laboratorio. El uso no autorizado en redes de producción es ilegal.

---

## 🗺️ Topología de Red

```
                        Internet (Net)
                             |
                           R1 (Router)
                     e0/1 → DHCP (Internet)
                     e0/0.10 → 192.168.10.1/24 (VLAN 10)
                     e0/0.20 → 192.168.20.1/24 (VLAN 20)
                             |
                        R3 (Switch IOSvL2)
                    e0/2 → Trunk hacia R1
                    e0/0 → VLAN 10 (VPC)
                    e0/1 → VLAN 10 (Kali-Atacante)
                   /                    \
              VPC                    Kali-Atacante
         192.168.10.2/24            192.168.10.4/24
```

---

## 📡 Direccionamiento IP

| Dispositivo     | Interfaz     | IP               | VLAN |
|----------------|--------------|------------------|------|
| R1             | e0/0.10      | 192.168.10.1/24  | 10   |
| R1             | e0/0.20      | 192.168.20.1/24  | 20   |
| R1             | e0/1         | DHCP (Internet)  | -    |
| R3 (Switch)    | e0/2         | Trunk            | -    |
| R3 (Switch)    | e0/0         | Access VLAN 10   | 10   |
| R3 (Switch)    | e0/1         | Access VLAN 10   | 10   |
| VPC            | eth0         | 192.168.10.2/24  | 10   |
| Kali-Atacante  | eth0         | 192.168.10.4/24  | 10   |

---

## 🚀 Ataques Implementados

| # | Ataque | Script | Protocolo | Contra-medida |
|---|--------|--------|-----------|---------------|
| 1 | DoS mediante CDP | [01_CDP_DoS](./01_CDP_DoS/) | CDP | `no cdp enable` |
| 2 | MitM mediante ARP | [02_ARP_MitM](./02_ARP_MitM/) | ARP | DAI + DHCP Snooping |
| 3 | DHCP Spoofing | [03_DHCP_Spoofing](./03_DHCP_Spoofing/) | DHCP | DHCP Snooping |
| 4 | DHCP Starvation | [04_DHCP_Starvation](./04_DHCP_Starvation/) | DHCP | Rate Limiting + Port Security |
| 5 | MAC Flooding | [05_MAC_Flooding](./05_MAC_Flooding/) | Ethernet | Port Security |
| 6 | STP Claim Root | [06_STP_Root_Attack](./06_STP_Root_Attack/) | STP | BPDU Guard + Root Guard |

---

## ⚙️ Requisitos

```bash
# Python 3.x
sudo apt install python3

# Scapy
pip install scapy

# Ejecutar siempre como root
sudo python3 script.py
```

---

## 📁 Estructura del Repositorio

```
network-attacks/
├── README.md
├── 01_CDP_DoS/
│   ├── README.md
│   └── cdp_dos_attack.py
├── 02_ARP_MitM/
│   ├── README.md
│   └── arp_mitm_attack.py
├── 03_DHCP_Spoofing/
│   ├── README.md
│   └── dhcp_spoofing.py
├── 04_DHCP_Starvation/
│   ├── README.md
│   └── dhcp_starvation.py
├── 05_MAC_Flooding/
│   ├── README.md
│   └── mac_flooding.py
└── 06_STP_Root_Attack/
    ├── README.md
    └── stp_root_attack.py
```
