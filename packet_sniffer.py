from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

# Function to process and display packet information
def packet_handler(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dest_ip = ip_layer.dst
        protocol = ip_layer.proto

        # Determine the transport protocol (e.g., TCP, UDP)
        if TCP in packet:
            transport_layer = "TCP"
            payload = packet[TCP].payload
        elif UDP in packet:
            transport_layer = "UDP"
            payload = packet[UDP].payload
        else:
            transport_layer = "Other"
            payload = None
        
        # Print packet details
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dest_ip}")
        print(f"Protocol: {transport_layer}")
        print(f"Protocol: {transport_layer} (Code: {protocol})")
        if payload:
            print(f"Payload: {payload}")
        print("-" * 30)

# Sniff packets and pass each packet to the handler
def start_sniffer(interface=None, packet_count=0):
    print("Starting packet capture...")
    # Sniff packets on a specific interface or all if none specified
    sniff(iface=interface, prn=packet_handler, count=packet_count)

# Start the sniffer
if __name__ == "__main__":
    interface = "Wi-Fi"  # Change to your network interface (e.g., "eth0" or "wlan0")
    packet_count = 10  # Number of packets to capture (0 for unlimited)
    start_sniffer(interface=interface, packet_count=packet_count)
