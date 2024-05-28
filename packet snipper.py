from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

def packet_handler(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        print(f"Source IP: {ip_src}, Destination IP: {ip_dst}, Protocol: {protocol}", end='')

        if TCP in packet:
            print(f", TCP Payload: {bytes(packet[TCP].payload)}")
        elif UDP in packet:
            print(f", UDP Payload: {bytes(packet[UDP].payload)}")
        elif ICMP in packet:
            print(f", ICMP Payload: {bytes(packet[ICMP].payload)}")
        else:
            print()

def start_sniffing():
    print("Starting packet sniffer...")
    sniff(prn=packet_handler, store=False, count=10) 


if __name__ == "__main__":
    start_sniffing()
