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
        
                pkt = IP(dst=ip_range) / TCP(dport=port, flags="S")
            
            elif proto_lower == "icmp":
                pkt = IP(dst=ip_range) / ICMP(type=8)
            
            else:
                continue 
                
            packets.append(pkt)
            
    return packets
