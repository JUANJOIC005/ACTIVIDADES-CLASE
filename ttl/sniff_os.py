#!/usr/bin/env python3
from scapy.all import sniff, IP, TCP, ICMP
import argparse

COMMON_INITIAL_TTLS = [32, 64, 128, 255]

def estimate_initial_ttl(observed_ttl):
    for ttl in COMMON_INITIAL_TTLS:
        if observed_ttl <= ttl:
            return ttl
    return observed_ttl

def guess_os(pkt):
    if IP not in pkt:
        return "Desconocido"

    ip = pkt[IP]
    observed_ttl = ip.ttl
    initial_ttl = estimate_initial_ttl(observed_ttl)

    if TCP in pkt:
        tcp = pkt[TCP]
        window = tcp.window
        options = [opt[0] for opt in tcp.options if isinstance(opt, tuple)]


        if initial_ttl == 64:
            if "Timestamp" in options or "WScale" in options or "SAckOK" in options:
                return "Linux/Unix"

        if initial_ttl == 128:
            return "Windows"

     
        if initial_ttl == 255:
            return "Dispositivo de red/BSD/Unix"

        return "SO no identificado con claridad"

    elif ICMP in pkt:
        if initial_ttl == 64:
            return "Linux/Unix"
        elif initial_ttl == 128:
            return "Windows"
        elif initial_ttl == 255:
            return "Dispositivo de red/BSD/Unix"
        else:
            return "SO no identificado con claridad"

    return "Desconocido"

def process_packet(pkt):
    if IP not in pkt:
        return

    ip = pkt[IP]
    print("=" * 60)
    print(f"Paquete capturado: {ip.src} -> {ip.dst}")
    print(f"TTL observado: {ip.ttl}")

    if TCP in pkt:
        tcp = pkt[TCP]
        flags = tcp.sprintf("%TCP.flags%")
        print("Protocolo: TCP")
        print(f"Puerto origen: {tcp.sport}")
        print(f"Puerto destino: {tcp.dport}")
        print(f"Flags: {flags}")
        print(f"Ventana TCP: {tcp.window}")
        print(f"Opciones TCP: {tcp.options}")

    elif ICMP in pkt:
        icmp = pkt[ICMP]
        print("Protocolo: ICMP")
        print(f"Tipo ICMP: {icmp.type}")
        print(f"Código ICMP: {icmp.code}")

    so = guess_os(pkt)
    print(f"Sistema operativo inferido: {so}")

def main():
    parser = argparse.ArgumentParser(
        description="Sniffer con Scapy para inferir el SO del contenedor emisor"
    )
    parser.add_argument("-i", "--iface", required=True, help="Interfaz a escuchar")
    parser.add_argument("-s", "--src", required=True, help="IP origen a vigilar")
    parser.add_argument("-d", "--dst", required=True, help="IP destino a vigilar")
    args = parser.parse_args()

    bpf_filter = (
        f"src host {args.src} and dst host {args.dst} and "
        f"(icmp or (tcp and (port 80 or port 22)))"
    )

    print(f"Escuchando en la interfaz: {args.iface}")
    print(f"Filtro BPF: {bpf_filter}")

    sniff(iface=args.iface, filter=bpf_filter, prn=process_packet, store=False)

if __name__ == "__main__":
    main()
