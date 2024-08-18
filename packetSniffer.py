from scapy.all import sniff, IP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")

        if UDP in packet:
            udp_layer = packet[UDP]
            print(f"Protocol: UDP")
            print(f"Source Port: {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")
            print(f"Payload: {udp_layer.payload}")

        print("\n" + "-"*50 + "\n")

print("\nPACKET SNIFFER AND DISPLAY\n")

print("Starting packet sniffing...")
print("\n" + "-"*50 + "\n")
sniff(prn=packet_callback, store=0)