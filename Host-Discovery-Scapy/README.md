================================================================                
PROYECTO: HOST DISCOVERY CON SCAPY
================================================================

----------------------------------------------------------------
ARCHIVO 1: README.md
----------------------------------------------------------------
# Network Host Discovery Service (Scapy-based)

Herramienta técnica para la enumeración de hosts activos en capa 3 y 4 utilizando la librería Scapy. El proyecto implementa una metodología de descubrimiento multi-protocolo (ICMP, TCP, UDP) con lógica de filtrado para evitar falsos positivos generados por dispositivos intermedios.

## Arquitectura del Proyecto

- host_discovery.py: Módulo encargado de la forja de paquetes (packet crafting).
- main.py: Orquestador del escaneo. Gestiona el ciclo de envío/recepción (sr1) y el análisis de flags.
- requirements.txt: Dependencias del entorno (scapy).

## Especificaciones de la API Principal

### craft_discovery_pkts(protocols, ip_range, pkt_counts=None, port=80)
Genera una lista de objetos scapy.layers.inet.IP configurados para el descubrimiento.

Estrategia de Probing:
- ICMP: Implementa Echo Request (Type 8) para máxima compatibilidad.
- TCP: Utiliza flag SYN (0x02). Se considera host activo si recibe SYN-ACK (0x12) o RST-ACK (0x14).
- UDP: Envío de datagramas planos. Detección basada en respuestas directas o errores ICMP Port Unreachable.

## Instalación y Ejecución

1. Instalación: pip install scapy
2. Ejecución: sudo python main.py

----------------------------------------------------------------
ARCHIVO 2: host_discovery.py
----------------------------------------------------------------
from scapy.all import ICMP, IP, TCP, UDP

def craft_discovery_pkts(protocols, ip_range, pkt_counts=None, port=80):
    if isinstance(protocols, str):
        protocols = [protocols]
    
    pkt_counts = pkt_counts or {}
    packets = []
    
    for proto in protocols:
        proto_lower = proto.lower().strip()
        count = pkt_counts.get(proto_lower, 1)
        
        for i in range(count):
            if proto_lower == "udp":
                pkt = IP(dst=ip_range) / UDP(dport=port)
            elif proto_lower == "tcp":
                # Usamos SYN (S) para detectar el stack TCP/IP del host
                pkt = IP(dst=ip_range) / TCP(dport=port, flags="S")
            elif proto_lower == "icmp":
                # Echo Request (Type 8) es el estándar del ping
                pkt = IP(dst=ip_range) / ICMP(type=8)
            else:
                continue 
                
            packets.append(pkt)
            
    return packets

----------------------------------------------------------------
ARCHIVO 3: main.py
----------------------------------------------------------------
from scapy.all import IP, ICMP, TCP, UDP, IPerror, sr1
from host_discovery import craft_discovery_pkts
import logging

# Silenciar avisos de Scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def host_discovery(target_ip, protocols, timeout=2):
    packets = craft_discovery_pkts(protocols, target_ip)
    results = {}

    for pkt in packets:
        if ICMP in pkt:
            proto = "icmp"
        elif TCP in pkt:
            proto = "tcp"
        else:
            proto = "udp"

        # Enviamos y esperamos una respuesta (sr1)
        answered = sr1(pkt, timeout=timeout, verbose=0)
        responded = False

        if answered and IP in answered:
            src_ip = answered[IP].src
            
            # FILTRO CRÍTICO: La respuesta debe venir del target, no de un router
            if src_ip == target_ip:
                if proto == "icmp":
                    if answered.haslayer(ICMP) and answered[ICMP].type == 0:
                        responded = True

                elif proto == "tcp":
                    if answered.haslayer(TCP):
                        flags = answered[TCP].flags
                        # SYN-ACK (0x12) o RST (0x04/0x14) confirman host vivo
                        if flags & 0x02 or flags & 0x04:
                            responded = True

                elif proto == "udp":
                    if answered.haslayer(UDP):
                        responded = True
            
            # FILTRO ICMP ERROR: Si el host responde "Port Unreachable", está vivo
            elif answered.haslayer(ICMP) and answered[ICMP].type == 3:
                if answered.haslayer(IPerror) and answered[IPerror].dst == target_ip:
                    # Si el error viene de la IP destino, el host existe
                    if src_ip == target_ip:
                        responded = True

        results[proto] = responded
        status = "SI" if responded else "NO"
        print(f"IP: {target_ip:<15} | Protocolo: {proto.upper():<4} | Responde: {status}")

    return results

def main():
    print("\n== Host Discovery con Scapy (Versión Final) ==")
    ips_input = input("Introduce IPs separadas por coma: ")
    targets = [ip.strip() for ip in ips_input.split(",") if ip.strip()]
    
    prot_input = input("Protocolos (icmp,tcp,udp) [Enter = todos]: ").strip().lower()
    protocols = [p.strip() for p in prot_input.split(",")] if prot_input else ["icmp", "tcp", "udp"]

    active_hosts = []
    for ip in targets:
        print(f"\n--- Analizando: {ip} ---")
        res = host_discovery(ip, protocols)
        if any(res.values()):
            active_hosts.append(ip)

    print("\n== Resultado final ==")
    if active_hosts:
        print(f"Hosts activos detectados: {', '.join(active_hosts)}")
    else:
        print("No se detectó actividad de ningún host.")

if __name__ == "__main__":
    main()

----------------------------------------------------------------
ARCHIVO 4: requirements.txt
----------------------------------------------------------------
scapy>=2.5.0

