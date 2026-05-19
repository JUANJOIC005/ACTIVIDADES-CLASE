from scapy.all import IP, ICMP, TCP, UDP, sr1, conf, IPerror
from host_discovery import craft_discovery_pkts
import logging

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

        
        answered = sr1(pkt, timeout=timeout, verbose=0)

        responded = False

        if answered and IP in answered:
            src_ip = answered[IP].src
            
        
            if src_ip == target_ip:
                
                if proto == "icmp":
                    if answered.haslayer(ICMP):
                        if answered[ICMP].type in [0, 14]:
                            responded = True

                elif proto == "tcp":
                    if answered.haslayer(TCP):
                        flags = answered[TCP].flags
                        if flags & 0x02 or flags & 0x04:
                            responded = True

                elif proto == "udp":
                    
                    if answered.haslayer(UDP):
                        responded = True
            
           
            elif answered.haslayer(ICMP) and answered[ICMP].type == 3:
                
                if answered.haslayer(IPerror) and answered[IPerror].dst == target_ip:
                     
                     if src_ip == target_ip:
                         responded = True

        results[proto] = responded
        status = "SI" if responded else "NO"
        print(f"IP: {target_ip:<15} | Protocolo: {proto.upper():<4} | Responde: {status}")

    return results

def main():
    print("\n" + "="*30)
    print("  Host Discovery")
    print("="*30)

    ips_input = input("Introduce IPs separadas por coma: ")
    targets = [ip.strip() for ip in ips_input.split(",") if ip.strip()]

    prot_input = input("Protocolos (icmp,tcp,udp) [Enter = todos]: ").strip().lower()

    if prot_input == "":
        protocols = ["icmp", "tcp", "udp"]
    else:
        protocols = [p.strip() for p in prot_input.split(",") if p.strip()]

    active_hosts = []

    for ip in targets:
        print(f"\n--- Analizando: {ip} ---")
        res = host_discovery(ip, protocols)

        if any(res.values()):
            active_hosts.append(ip)

    print("\n" + "="*30)
    print("      RESULTADO FINAL")
    print("="*30)
    if active_hosts:
        print(f"Hosts activos confirmados: {', '.join(active_hosts)}")
    else:
        print("No se detectó actividad de ningún host.")

if __name__ == "__main__":
    main()
