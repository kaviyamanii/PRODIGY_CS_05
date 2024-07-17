#Task_05
#Network packet Analyzer

from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        payload = packet[IP].payload

        print(f"IP Source: {ip_src}")
        print(f"IP Destination: {ip_dst}")

        if protocol == 6:
            print("Protocol: TCP")
            if TCP in packet:
                print(f"Payload: {bytes(packet[TCP].payload)}")
        elif protocol == 17:
            print("Protocol: UDP")
            if UDP in packet:
                print(f"Payload: {bytes(packet[UDP].payload)}")
        else:
            print(f"Protocol: {protocol}")

        print("-" * 40)

def main():
    interface = input("Enter the interface to sniff on (e.g., eth0): ")
    print(f"Sniffing on {interface}... Press Ctrl+C to stop.")
    sniff(iface=interface, prn=packet_callback, store=0)

if __name__ == "__main__":
    main()