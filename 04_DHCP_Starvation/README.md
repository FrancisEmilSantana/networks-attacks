# 04 - Ataque DHCP Starvation

## Objetivo del Laboratorio
Demostrar cómo un atacante puede agotar el pool de IPs del servidor DHCP, impidiendo que clientes legítimos obtengan configuración de red.

## Objetivo del Script
Completar handshake DHCP completo (DISCOVER→OFFER→REQUEST→ACK) con MACs falsas aleatorias para reservar todas las IPs del pool de R1.

## Parámetros
Sin parámetros - configuración hardcodeada para el laboratorio.

## Requisitos
```bash
pip install scapy
sudo python3 dhcp_starvation.py
```

## Funcionamiento del Script
1. Genera MAC aleatoria
2. Envía DHCP DISCOVER con esa MAC
3. Sniff captura el OFFER de R1
4. Envía DHCP REQUEST solicitando la IP ofrecida
5. R1 confirma con ACK → IP reservada del pool
6. Repite hasta agotar el pool

## Documentación de Red
- **Atacante:** Kali 192.168.10.4
- **Víctima:** R1 servidor DHCP 192.168.10.1
- **Pool objetivo:** 192.168.10.0/24

## Contra-medida
```
R3(config)# ip dhcp snooping
R3(config)# ip dhcp snooping vlan 10
R3(config)# interface ethernet 0/1
R3(config-if)# ip dhcp snooping limit rate 10
R3(config-if)# switchport port-security
R3(config-if)# switchport port-security maximum 2
R3(config-if)# switchport port-security violation shutdown
R3(config-if)# switchport port-security mac-address sticky
```

## Verificación
```
R1# show ip dhcp binding
R1# show ip dhcp pool
VPC> ip dhcp
```
