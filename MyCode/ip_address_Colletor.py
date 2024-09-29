import os
from scapy.all import *
from scapy.layers.dns import DNS
import sys

def extract_dns_packets(pcap_file, target_ip):
    """
    Extract DNS packets related to a specific IP address from the provided PCAP file.
    """
    dns_packets = []

    # Read packets from the input PCAP file
    packets = rdpcap(pcap_file)

    for packet in packets:
        # Check if the packet has DNS layer and either source or destination IP matches the target IP
        if packet.haslayer(DNS):
            ip_layer = packet.getlayer(IP)
            if ip_layer and (ip_layer.src == target_ip or ip_layer.dst == target_ip):
                dns_packets.append(packet)
    
    return dns_packets

def process_pcap_files(directory, target_ip):
    """
    Recursively find and process all PCAP files in the given directory and its subdirectories.
    Extract DNS packets related to the target IP from each PCAP file.
    """
    all_dns_packets = []

    # Walk through the directory and subdirectories to find .pcap files
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".pcap"):
                pcap_path = os.path.join(root, file)
                print(f"Processing file: {pcap_path}")
                dns_packets = extract_dns_packets(pcap_path, target_ip)
                all_dns_packets.extend(dns_packets)
    
    return all_dns_packets

def save_to_pcap(packets, output_pcap_file):
    """
    Save the extracted DNS packets to a new PCAP file.
    """
    if packets:
        wrpcap(output_pcap_file, packets)
        print(f"Extracted DNS records have been written to {output_pcap_file}")
    else:
        print("No DNS packets found for the specified IP address.")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python parse_pcap_dns.py <pcap_folder> <target_ip> <output.pcap>")
        sys.exit(1)

    pcap_folder = sys.argv[1]
    target_ip = sys.argv[2]
    output_pcap = sys.argv[3]

    # Recursively find and process all PCAP files in the given folder
    all_dns_packets = process_pcap_files(pcap_folder, target_ip)

    # Save all the extracted DNS packets into a single output PCAP file
    save_to_pcap(all_dns_packets, output_pcap)
