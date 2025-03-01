import scapy.all as scapy
import time
import requests

# Set thresholds for detecting different types of attacks
UDP_THRESHOLD = 1000  # Max UDP packets/sec
SYN_THRESHOLD = 500  # Max SYN packets/sec

# Dictionaries to track IPs associated with each attack type
udp_ips = {}
syn_ips = {}

# Timer to measure elapsed time
start_time = time.time()


def detect_ddos(packet):
    """Detects DDoS attacks based on packet type"""
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src

        # Track UDP Flood
        if packet.haslayer(scapy.UDP):
            udp_ips[src_ip] = udp_ips.get(src_ip, 0) + 1

        # Track SYN Flood
        elif packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags == "S":
            syn_ips[src_ip] = syn_ips.get(src_ip, 0) + 1

        # Print results after a certain time to avoid overwhelming output
        elapsed_time = time.time() - start_time
        if elapsed_time >= 5:  # Prints every 5 seconds
            identify_attack_and_protect()
            reset_tracking()


def identify_attack_and_protect():
    """Identifies the attack type and IP, and provides protection solutions"""
    attack_detected = False
    for ip, count in udp_ips.items():
        if count > UDP_THRESHOLD:
            print(f"IP: {ip} discovered DDoS attack (UDP Flood): Solution: Block with iptables")
            attack_detected = True
            # os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")  # Uncomment to block IP with iptables

    for ip, count in syn_ips.items():
        if count > SYN_THRESHOLD:
            print(f"IP: {ip} discovered DDoS attack (SYN Flood): Solution: Enable SYN Cookies")
            attack_detected = True
            # os.system("sudo sysctl -w net.ipv4.tcp_syncookies=1")  # Uncomment to enable SYN cookies

    if not attack_detected:
        print(f"No DDoS vulnerabilities detected for the target URL.")


def reset_tracking():
    """Resets the attack detection counts after printing results"""
    global udp_ips, syn_ips
    udp_ips = {}
    syn_ips = {}
    global start_time
    start_time = time.time()  # Reset the timer


def start_detection(target_url):
    """Starts the DDoS detection process"""
    print(f"Starting DDoS detection for {target_url}...")
    scapy.sniff(filter="ip", prn=detect_ddos, store=False, count=1000)


if __name__ == "__main__":
    # Take target URL as input from the user
    target_url = "https://xss-game.appspot.com/level1/frame"
    start_detection(target_url)
