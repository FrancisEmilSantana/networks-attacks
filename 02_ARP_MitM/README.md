# 02 - Ataque MitM mediante ARP Poisoning

## Objetivo del Laboratorio
Demostrar cómo un atacante puede interceptar el tráfico entre la víctima y el gateway mediante envenenamiento de tablas ARP.

## Objetivo del Script
Enviar ARP Reply falsos a víctima y gateway para que ambos crean que la MAC del atacante corresponde al otro dispositivo.

## Parámetros
| Parámetro | Descripción | Default |
|-----------|-------------|---------|
| `-i` | Interfaz de red | Requerido |
| `-t` | IP de la víctima | Requerido |
| `-g` | IP del gateway | Requerido |
| `-d` | Intervalo entre envíos | 2s |

## Requisitos
```bash
pip install scapy
sudo python3 arp_mitm_attack.py -i eth0 -t 192.168.10.2 -g 192.168.10.1
```

## Funcionamiento del Script
1. Obtiene MACs reales de víctima y gateway via ARP
2. Habilita IP Forwarding para no cortar la conexión
3. Envía ARP Reply falso a víctima: "el gateway soy yo"
4. Envía ARP Reply falso al gateway: "la víctima soy yo"
5. Todo el tráfico pasa por Kali (MitM activo)
6. Al terminar restaura las tablas ARP originales

## Documentación de Red
- **Atacante:** Kali 192.168.10.4
- **Víctima:** VPC 192.168.10.2
- **Gateway:** R1 192.168.10.1

## Contra-medida
```
R3(config)# ip dhcp snooping
R3(config)# ip dhcp snooping vlan 10
R3(config)# ip arp inspection vlan 10
R3(config)# interface ethernet 0/2
R3(config-if)# ip dhcp snooping trust
R3(config-if)# ip arp inspection trust
```

## Verificación
```bash
VPC> show arp
sudo tcpdump -i eth0 -n not arp
```
