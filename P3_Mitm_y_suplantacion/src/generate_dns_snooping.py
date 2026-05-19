from __future__ import annotations

import argparse
import random
import string
import time

from scapy.all import DNS, DNSQR, IP, UDP, sr1


def random_label(length: int = 10) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Genera consultas DNS a subdominios falsos dentro del laboratorio Docker."
    )
    parser.add_argument("--resolver", default="10.10.30.53", help="IP del DNS resolver local.")
    parser.add_argument("--zone", default="lab.local", help="Zona DNS local.")
    parser.add_argument("--count", type=int, default=20, help="Numero de consultas a generar.")
    parser.add_argument("--delay", type=float, default=0.2, help="Pausa entre consultas.")
    args = parser.parse_args()

    print(
        f"Generando {args.count} consultas falsas contra {args.resolver} "
        f"dentro de {args.zone}",
        flush=True,
    )

    for index in range(1, args.count + 1):
        qname = f"{random_label()}.{args.zone}"
        pkt = IP(dst=args.resolver) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=qname))
        response = sr1(pkt, timeout=1, verbose=False)
        status = "sin respuesta"
        if response and response.haslayer(DNS):
            status = f"rcode={response[DNS].rcode}"
        print(f"{index:02d}. {qname} -> {status}", flush=True)
        time.sleep(args.delay)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
