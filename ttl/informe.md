# Trabajo TTl

## Objetivos

El objetivo de esta práctica es identificar el sistema operativo probable de un contenedor que genera tráfico hacia una IP situada en otra red, utilizando packet sniffing con Scapy. Para ello se ha empleado una topología Docker con varios contenedores y routers, de forma que el tráfico atraviesa varios saltos antes de llegar al destino. La detección del sistema operativo se realiza analizando características de la pila TCP/IP, especialmente el valor TTL y, en el caso de TCP, las opciones del protocolo.

## Esenario de red

El escenario está compuesto por varios contenedores Docker. El contenedor app2 actúa como cliente y tiene la IP 10.0.2.10. El contenedor app1 actúa como servidor web y tiene la IP 10.0.1.10. Entre ambas redes existen tres routers (router-3, router-2 y router-1), por lo que el tráfico pasa por varios saltos. Este comportamiento multi-hop es importante porque cada router decrementa el TTL en una unidad. La topología está definida en el fichero YAML proporcionado.

## Código sniff-os.py

```python 

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
            

```



## Explicación de código 


El script utiliza la función `sniff()` de Scapy para capturar paquetes en una interfaz indicada por el usuario. Se aplica un filtro BPF para capturar únicamente tráfico de interés entre `10.0.2.10` y `10.0.1.10`, limitándolo a ICMP y TCP en puertos relevantes.

La función `estimate_initial_ttl()` estima el TTL inicial probable del sistema emisor usando valores habituales como `64`, `128` o `255`.

La función `guess_os()` aplica una heurística simple: si el TTL inicial estimado es 64 y además aparecen opciones TCP como `SAckOK`, `Timestamp` y `WScale`, se considera que el sistema operativo probable es Linux/Unix.

Finalmente, `process_packet()` muestra por pantalla la información relevante de cada paquete capturado y la conclusión sobre el sistema operativo inferido.


## Resultados

En los resultados `resultados-http.txt` y `resultados-icmp.txt`
Se pueden ver los resultados de las dos salidas al realizar las pruebas.


