from __future__ import annotations

import argparse
import sys
import time

from scapy.all import ARP, sniff


def normalise_mac(mac: str) -> str:
    return mac.strip().lower()


def alert_arpspoof(packet, state: dict) -> None:
    if not packet.haslayer(ARP):
        return

    arp = packet[ARP]
    if arp.op != 2:
        return

    ip = str(arp.psrc)
    mac = normalise_mac(str(arp.hwsrc))
    watched_ips = state["watched_ips"]

    if watched_ips and ip not in watched_ips:
        return

    now = time.strftime("%H:%M:%S")
    expected = state["expected_macs"].get(ip)
    previous = state["seen_macs"].get(ip)

    if expected and mac != expected:
        print(
            f"[{now}] ALERTA ARP SPOOFING: {ip} deberia usar {expected}, "
            f"pero anuncia {mac} hacia {arp.pdst}",
            flush=True,
        )
    elif previous and previous != mac:
        print(
            f"[{now}] ALERTA ARP SPOOFING: {ip} ha cambiado de MAC "
            f"{previous} -> {mac} hacia {arp.pdst}",
            flush=True,
        )
    else:
        print(f"[{now}] ARP OK: {ip} esta asociado a {mac}", flush=True)

    state["seen_macs"][ip] = mac


def parse_expected(values: list[str]) -> dict[str, str]:
    result = {}
    for value in values:
        if "=" not in value:
            raise argparse.ArgumentTypeError("Usa formato IP=MAC")
        ip, mac = value.split("=", 1)
        result[ip.strip()] = normalise_mac(mac)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="IDS simple para detectar cambios sospechosos en respuestas ARP."
    )
    parser.add_argument("--iface", default="eth0", help="Interfaz a monitorizar.")
    parser.add_argument(
        "--watch",
        action="append",
        default=[],
        help="IP a vigilar. Puede repetirse. Si no se indica, vigila todas.",
    )
    parser.add_argument(
        "--expected",
        action="append",
        default=[],
        help="Asociacion legitima IP=MAC. Ejemplo: 10.10.10.1=02:42:0a:0a:0a:01",
    )
    args = parser.parse_args()

    state = {
        "watched_ips": set(args.watch),
        "expected_macs": parse_expected(args.expected),
        "seen_macs": {},
    }

    print(f"Monitorizando ARP en {args.iface}. Pulsa Ctrl+C para terminar.", flush=True)
    if state["watched_ips"]:
        print(f"IPs vigiladas: {', '.join(sorted(state['watched_ips']))}", flush=True)
    if state["expected_macs"]:
        print(f"MAC legitimas: {state['expected_macs']}", flush=True)

    try:
        sniff(
            iface=args.iface,
            filter="arp",
            store=False,
            prn=lambda pkt: alert_arpspoof(pkt, state),
        )
    except PermissionError:
        print("Error: ejecuta el script con permisos NET_RAW/root.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nMonitorizacion ARP finalizada.", flush=True)
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
