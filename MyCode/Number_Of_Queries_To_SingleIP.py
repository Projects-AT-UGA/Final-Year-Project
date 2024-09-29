import os
import argparse
from scapy.all import rdpcap, DNSQR, IP
from collections import defaultdict

# Function to parse a single PCAP file and count DNS queries by domain and IP address
def parse_pcap_file(pcap_file, ip_filter=None):
    # Dictionary to store count of requests per domain
    domain_requests = defaultdict(int)
    # Dictionary to store count of requests per IP address
    ip_requests = defaultdict(int)

    # Read the PCAP file
    packets = rdpcap(pcap_file)

    # Iterate through each packet
    for packet in packets:
        # Check if the packet has a DNS query layer
        if packet.haslayer(DNSQR):
            # If IP filter is provided, check if it matches the packet's source IP
            src_ip = packet[IP].src
            if ip_filter and src_ip != ip_filter:
                continue  # Skip if IP doesn't match the provided IP filter

            # Extract the queried domain name
            queried_domain = packet[DNSQR].qname.decode('utf-8').strip('.')
            domain_requests[queried_domain] += 1

            # Count the number of queries per source IP address
            ip_requests[src_ip] += 1

    return domain_requests, ip_requests

# Function to parse all PCAP files in a folder
def parse_pcap_folder(folder, ip_filter=None):
    # Dictionary to store cumulative count of requests per domain
    all_domain_requests = defaultdict(int)
    # Dictionary to store cumulative count of requests per IP address
    all_ip_requests = defaultdict(int)

    # Iterate over all files in the folder
    for filename in os.listdir(folder):
        # Ensure it's a PCAP file
        if filename.endswith(".pcap"):
            pcap_file_path = os.path.join(folder, filename)
            print(f"Processing {pcap_file_path}")
            # Parse the individual PCAP file
            file_domain_requests, file_ip_requests = parse_pcap_file(pcap_file_path, ip_filter)

            # Aggregate the domain results
            for domain, count in file_domain_requests.items():
                all_domain_requests[domain] += count

            # Aggregate the IP results
            for ip, count in file_ip_requests.items():
                all_ip_requests[ip] += count

    return all_domain_requests, all_ip_requests

# Command-line argument parser setup
def main():
    print("example query: python Number_Of_Queries_To_SingleIP.py ./India/20221201 --ip 192.168.2.42")
    parser = argparse.ArgumentParser(description="Parse a folder of PCAP files and count DNS queries by domain and IP.")
    parser.add_argument("folder", help="Path to the folder containing PCAP files")
    parser.add_argument("--ip", help="Filter queries for a specific source IP address", required=False)
    args = parser.parse_args()

    # Parse the folder and optionally filter by IP
    domain_requests, ip_requests = parse_pcap_folder(args.folder, ip_filter=args.ip)

    # Display results for domain queries
    print("\nDNS Query Count by Domain:")
    for domain, count in domain_requests.items():
        print(f"{domain}: {count} queries")

    # Display results for IP queries
    print("\nDNS Query Count by IP Address:")
    for ip, count in ip_requests.items():
        print(f"{ip}: {count} queries")

if __name__ == "__main__":
    main()
