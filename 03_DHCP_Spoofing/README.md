# 03 - Ataque DHCP Spoofing

## Objetivo del Laboratorio
Demostrar cómo un atacante puede suplantar al servidor DHCP legítimo para asignar configuraciones de red falsas a los clientes.

## Objetivo del Script
Responder a los DHCP Discover antes que el servidor legítimo, asignando gateway falso 192.168.10.254 en lugar del real 192.168.10.1.

## Parámetros
Configuración hardcodeada:
- Servidor falso: 192.168.10.4 (Kali)
- Gateway falso: 192.168.10.254
- Pool asignado: 192.168.10.150+

## Requisitos
```bash
pip install scapy
sudo python3 dhcp_spoofing.py
```

## Funcionamiento del Script
1. Escucha paquetes DHCP en la red
2. Al detectar DISCOVER envía 5 OFFERs con gateway falso directamente a la MAC del cliente
3. Al detectar REQUEST envía 5 ACKs confirmando la IP falsa
4. El cliente obtiene gateway 192.168.10.254 (Kali)

## Documentación de Red
- **Atacante:** Kali 192.168.10.4
- **Víctima:** VPC 192.168.10.2
- **Gateway real:** R1 192.168.10.1
- **Gateway falso:** 192.168.10.254

## Contra-medida
```
R3(config)# ip dhcp snooping
R3(config)# ip dhcp snooping vlan 10
R3(config)# no ip dhcp snooping information option
R3(config)# interface ethernet 0/2
R3(config-if)# ip dhcp snooping trust
```

## Verificación
```bash
VPC> ip dhcp
VPC> show ip
```
