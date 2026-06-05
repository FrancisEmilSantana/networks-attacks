# 06 - Ataque STP Claim Root

## Objetivo del Laboratorio
Demostrar cómo un atacante puede reclamar el rol de Root Bridge enviando BPDUs con prioridad 0, alterando el flujo de tráfico de toda la red.

## Objetivo del Script
Enviar BPDUs con prioridad 0 forzando al switch R3 a ceder el rol de Root Bridge a Kali.

## Parámetros
Sin parámetros - configuración hardcodeada para el laboratorio.

## Requisitos
```bash
pip install scapy
sudo python3 stp_root_attack.py
```

## Funcionamiento del Script
1. Obtiene la MAC de eth0
2. Construye BPDUs con prioridad 0 (mejor que 32778 de R3)
3. Los envía al multicast STP 01:80:c2:00:00:00 cada 2 segundos
4. R3 recibe BPDUs con mejor prioridad y cede el rol
5. Kali se convierte en Root Bridge

## Documentación de Red
- **Atacante:** Kali 192.168.10.4
- **Root Bridge actual:** R3 prioridad 32778
- **Root Bridge falso:** Kali prioridad 0

## Contra-medida
```
R3(config)# interface ethernet 0/1
R3(config-if)# spanning-tree bpduguard enable
R3(config-if)# spanning-tree guard root
```

## Verificación
```
R3# show spanning-tree vlan 10
R3# show spanning-tree inconsistentports
```
