# 01 - Ataque DoS mediante CDP

## Objetivo del Laboratorio
Demostrar cómo un atacante puede explotar el protocolo CDP para generar DoS en dispositivos Cisco, agotando su tabla de vecinos CDP y consumiendo memoria/CPU.

## Objetivo del Script
Generar inundación masiva de paquetes CDP falsos con Device-IDs y MACs aleatorias, saturando la tabla CDP del switch R3.

## Parámetros
| Parámetro | Descripción | Default |
|-----------|-------------|---------|
| `-i` | Interfaz de red | Requerido |
| `-c` | Número de paquetes (0=infinito) | 0 |
| `-d` | Delay entre paquetes | 0 |
| `-v` | Modo verbose | False |

## Requisitos
```bash
pip install scapy
sudo python3 cdp_dos_attack.py -i eth0
```

## Funcionamiento del Script
1. Genera MACs e IPs de origen aleatorias
2. Construye paquetes CDP con TLVs (DeviceID, PortID, Platform)
3. Los envía al multicast CDP 01:00:0c:cc:cc:cc
4. R3 crea una nueva entrada en su tabla CDP por cada paquete
5. La tabla se satura generando DoS

## Documentación de Red
- **Atacante:** Kali 192.168.10.4 (eth0) → R3 (e0/1)
- **Víctima:** R3 switch tabla CDP
- **Protocolo:** CDP Capa 2

## Contra-medida
```
R3(config)# interface ethernet 0/1
R3(config-if)# no cdp enable
R3(config)# no cdp run
```

## Verificación
```
R3# show cdp neighbors
R3# show processes cpu
```
