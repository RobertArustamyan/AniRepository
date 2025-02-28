from scapy.all import ARP, sniff, sr

def get_mac(ip):
    ans, _ = sr(ARP(op=ARP.who_has, pdst=ip), timeout=2, verbose=False)
    return ans[0][1].hwsrc if ans else None

def process_packet(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        real_mac = get_mac(packet[ARP].psrc)
        response_mac = packet[ARP].hwsrc
        if real_mac and real_mac != response_mac:
            print(f"Potential MITM attack detected: {packet[ARP].psrc} is being spoofed.")

sniff(filter="arp", store=0, prn=process_packet)
