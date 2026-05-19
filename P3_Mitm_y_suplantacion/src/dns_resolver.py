from __future__ import annotations

import socket


UPSTREAM = ("10.10.30.100", 53)
LISTEN = ("0.0.0.0", 53)


def main() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(LISTEN)
    print(f"DNS resolver local escuchando en {LISTEN[0]}:{LISTEN[1]}", flush=True)
    print(f"Reenviando consultas a {UPSTREAM[0]}:{UPSTREAM[1]}", flush=True)

    while True:
        data, client = sock.recvfrom(4096)
        upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        upstream.settimeout(2)
        try:
            upstream.sendto(data, UPSTREAM)
            response, _ = upstream.recvfrom(4096)
            sock.sendto(response, client)
        except socket.timeout:
            print(f"Timeout resolviendo consulta de {client[0]}", flush=True)
        finally:
            upstream.close()


if __name__ == "__main__":
    main()
