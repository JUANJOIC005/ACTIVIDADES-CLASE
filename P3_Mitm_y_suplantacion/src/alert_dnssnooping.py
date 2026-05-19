from __future__ import annotations

import argparse
import sys
import time
from collections import defaultdict, deque

from scapy.all import DNS, DNSQR, IP, UDP, sniff


KNOWN_HOSTS = {
    "www.lab.local.",
    "dns.lab.local.",
}


def is_suspicious_query(qname: str, zone: str) -> bool:
    if not qname.endswith(zone):
        return False
    if qname in KNOWN_HOSTS:
        return False
    leftmost = qname[: -len(zone)].strip(".").split(".")[0]
    return len(leftmost) >= 6


def purge_old(events: deque[float], now: float, window: int) -> None:
    while events and now - events[0] > window:
        events.popleft()


def alert_dnssnooping(packet, state: dict) -> None:
    if not (packet.haslayer(IP) and packet.haslayer(UDP) and packet.haslayer(DNS)):
        return

    dns = packet[DNS]
    if dns.qr != 0 or dns.qdcount < 1 or not packet.haslayer(DNSQR):
        return

    qname = packet[DNSQR].qname.decode(errors="ignore").lower()
    if not is_suspicious_query(qname, state["zone"]):
        return

    src = packet[IP].src
    if state["client"] and src != state["client"]:
        return

    now = time.time()
    events = state["events"][src]
    events.append(now)
    purge_old(events, now, state["window"])

    stamp = time.strftime("%H:%M:%S")
    print(
        f"[{stamp}] DNS sospechoso desde {src}: {qname} "
        f"({len(events)}/{state['threshold']} en {state['window']}s)",
        flush=True,
    )

    if len(events) >= state["threshold"]:
        if now - state["last_alert"][src] >= state["cooldown"]:
            print(
                f"[{stamp}] ALERTA DNS SNOOPING: {src} supera el umbral "
                f"con subdominios inexistentes en {state['zone']}",
                flush=True,
            )
            state["last_alert"][src] = now


def main() -> int:
    parser = argparse.ArgumentParser(
        description="IDS simple para detectar rafagas de consultas DNS a subdominios falsos."
    )
    parser.add_argument("--iface", default="eth0", help="Interfaz a monitorizar.")
    parser.add_argument("--zone", default="lab.local.", help="Zona DNS del laboratorio.")
    parser.add_argument("--threshold", type=int, default=8, help="Consultas necesarias para alertar.")
    parser.add_argument("--window", type=int, default=10, help="Ventana temporal en segundos.")
    parser.add_argument("--cooldown", type=int, default=10, help="Segundos entre alertas repetidas.")
    parser.add_argument("--client", help="IP de cliente a vigilar. Si se omite, vigila todos.")
    args = parser.parse_args()

    zone = args.zone.lower()
    if not zone.endswith("."):
        zone += "."

    state = {
        "zone": zone,
        "threshold": args.threshold,
        "window": args.window,
        "cooldown": args.cooldown,
        "client": args.client,
        "events": defaultdict(deque),
        "last_alert": defaultdict(float),
    }

    print(
        f"Monitorizando DNS en {args.iface}: umbral {args.threshold} "
        f"consultas/{args.window}s para *.{zone}",
        flush=True,
    )

    try:
        sniff(
            iface=args.iface,
            filter="udp port 53",
            store=False,
            prn=lambda pkt: alert_dnssnooping(pkt, state),
        )
    except PermissionError:
        print("Error: ejecuta el script con permisos NET_RAW/root.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nMonitorizacion DNS finalizada.", flush=True)
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
