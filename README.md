# Repositorio 3 - DNS Spoofing / DNS Poisoning (itla.edu.do)

**Estudiante:** Francis Emil Santana
**Matricula:** 2024-1365

## Objetivo del laboratorio
Demostrar un ataque de **DNS Spoofing/Poisoning** en el que se falsifica
la respuesta a las consultas DNS del dominio `itla.edu.do`, de forma que
una victima sea redirigida a un servicio web local controlado por el
atacante, y documentar la contramedida correspondiente.

## Objetivo del script (dns_spoof.py)
Esnifar consultas DNS en la red local y responder de forma falsificada
a toda consulta dirigida a `itla.edu.do`, apuntando el registro A hacia
la IP del servidor web del atacante. Opcionalmente, realizar **ARP
poisoning** para posicionarse en medio (MITM) entre la victima y su
gateway.

### Parametros usados
| Parametro | Descripcion |
|-----------|-------------|
| `-i / --iface` | Interfaz de Kali |
| `-t / --target` | IP de la victima (VPC) |
| `-g / --gateway` | IP del gateway/router (R1) |
| `-d / --domain` | Dominio a falsificar (`itla.edu.do`) |
| `-l / --local-ip` | IP del servicio web local de destino |
| `--arp-spoof` | Activa ARP poisoning (MITM victima<->gateway) |

### Requisitos para utilizar la herramienta
- Kali Linux con Scapy instalado.
- Privilegios de root.
- Servicio web escuchando en `--local-ip` (ej: `python3 -m http.server 80`).
- Para MITM completo: habilitar reenvio de IP en Kali:
  `echo 1 > /proc/sys/net/ipv4/ip_forward`

## Documentacion del funcionamiento del script
1. (Opcional, `--arp-spoof`) Lanza un hilo que envia periodicamente
   respuestas ARP falsificadas a la victima y al gateway, haciendo que
   ambos envien su trafico a traves de Kali (MITM).
2. Inicia un sniffer con filtro BPF `udp port 53`.
3. Por cada paquete DNS de tipo consulta (`DNS qr=0`) cuyo `qname`
   coincide con `itla.edu.do` (o subdominios), construye una respuesta
   DNS (`DNS qr=1`) con un registro `DNSRR` cuyo `rdata` es la IP del
   servidor web local indicada en `-l`.
4. Envia la respuesta falsificada directamente al solicitante.
5. Al finalizar (Ctrl+C), si se activo `--arp-spoof`, restaura las
   tablas ARP originales de la victima y el gateway.

## Documentacion de la red

### Topologia
```
[Net] --e0/2-- [R1] --e0/0-- e0/0--[SW-VTP-Server]--e0/1 -- e0/0--[SW-1]
                                                                     |--e0/1-- [VPC]      (victima)
                                                                     |--e0/2-- [Kali / Linux]  (atacante)
```

### Direccionamiento IP
| Dispositivo | Interfaz | IP / Mascara | Rol |
|-------------|----------|--------------|-----|
| R1 | E0/2 | 10.0.137.23 /24 | Salida hacia Net (WAN) |
| R1 | E0/1.10 | 192.168.10.1 /24 | Gateway VLAN 10 |
| VPC | eth0 | 192.168.10.x /24 | Victima |
| Kali | eth0 | 192.168.10.x /24 | Atacante / servidor web falso |

### VLAN
| VLAN | Nombre | Notas |
|------|--------|-------|
| 10 | Usuarios | VPC y Kali en la misma VLAN/segmento (requisito para esnifar/spoofear) |

### Capturas de pantalla
> (Agregar aqui: resolucion DNS normal de `itla.edu.do` desde el VPC,
> ejecucion de `dns_spoof.py`, resolucion DNS falsificada apuntando a
> Kali, y acceso al servicio web falso desde el VPC)

## Documentar contramedidas
- **DNSSEC**: firma digital de las respuestas DNS para validar su
  autenticidad e integridad.
- **Dynamic ARP Inspection (DAI)** y **DHCP Snooping** en los switches:
  bloquean las respuestas ARP falsificadas necesarias para el MITM.
- Forzar el uso de resolutores DNS confiables y, de ser posible,
  **DNS sobre TLS/HTTPS (DoT/DoH)**.
- Monitoreo con IDS/IPS para detectar respuestas DNS duplicadas o que
  provienen de un origen inesperado.
