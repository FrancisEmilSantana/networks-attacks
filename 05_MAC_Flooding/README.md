# 05 - Ataque MAC Flooding

## Objetivo del Laboratorio
Demostrar cómo un atacante puede saturar la tabla CAM del switch con MACs falsas, haciendo que actúe como hub y reenvíe tráfico a todos los puertos.

## Objetivo del Script
Inundar la tabla CAM de R3 con tramas Ethernet de MACs origen aleatorias hasta saturarla completamente.

## Parámetros
Sin parámetros - configuración hardcodeada para el laboratorio.

## Requisitos
```bash
pip install scapy
sudo python3 mac_flooding.py
```

## Funcionamiento del Script
1. Genera MACs origen y destino aleatorias
2. Envía tramas Ethernet a máxima velocidad
3. El switch aprende cada MAC falsa en la tabla CAM
4. La tabla CAM se satura (~8000 entradas máximo)
5. El switch pasa a modo failopen → broadcast de todo el tráfico

## Documentación de Red
- **Atacante:** Kali 192.168.10.4
- **Víctima:** R3 tabla CAM
- **Efecto:** Switch actúa como HUB

## Contra-medida
```
R3(config)# interface ethernet 0/1
R3(config-if)# switchport port-security
R3(config-if)# switchport port-security maximum 2
R3(config-if)# switchport port-security violation shutdown
R3(config-if)# switchport port-security mac-address sticky
```

## Verificación
```
R3# show mac address-table count
sudo tcpdump -i eth0 -n
```
