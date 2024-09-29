import os
import argparse
from scapy.all import rdpcap, DNSQR, IP
from collections import defaultdict

# Function to parse a single PCAP file and count DNS queries, domains, and destination IPs per source IP
def parse_pcap_file(pcap_file, ip_filter=None):
    # Dictionary to store count of DNS queries, domain names, and destination IPs per source IP
    ip_requests = defaultdict(lambda: {'count': 0, 'domains': defaultdict(int), 'dest_ips': defaultdict(int)})

    # Read the PCAP file
    packets = rdpcap(pcap_file)

    # Iterate through each packet
    for packet in packets:
        # Check if the packet has a DNS query layer and IP layer
        if packet.haslayer(DNSQR) and packet.haslayer(IP):
            # Extract the source IP address
            src_ip = packet[IP].src
            # Extract the destination IP address
            dest_ip = packet[IP].dst

            # If IP filter is provided, count only queries from the specified IP
            if ip_filter and src_ip != ip_filter:
                continue  # Skip if IP doesn't match the filter

            # Increment the DNS query count for this source IP
            ip_requests[src_ip]['count'] += 1

            # Increment the count for the destination IP
            ip_requests[src_ip]['dest_ips'][dest_ip] += 1

            # Extract the domain name being queried
            domain_name = packet[DNSQR].qname.decode('utf-8')
            # Increment the count for the domain queried by this source IP
            ip_requests[src_ip]['domains'][domain_name] += 1

    return ip_requests

# Function to parse all PCAP files in a folder and aggregate the results for all IPs
def parse_pcap_folder(folder, ip_filter=None):
    # Dictionary to store cumulative count of requests per IP address and their domains
    all_ip_requests = defaultdict(lambda: {'count': 0, 'domains': defaultdict(int), 'dest_ips': defaultdict(int)})

    # Iterate over all files in the folder
    for filename in os.listdir(folder):
        # Ensure it's a PCAP file
        if filename.endswith(".pcap"):
            pcap_file_path = os.path.join(folder, filename)
            print(f"Processing {pcap_file_path}")
            # Parse the individual PCAP file
            file_ip_requests = parse_pcap_file(pcap_file_path, ip_filter)

            # Aggregate the IP and domain results
            for ip, data in file_ip_requests.items():
                all_ip_requests[ip]['count'] += data['count']
                for domain, count in data['domains'].items():
                    all_ip_requests[ip]['domains'][domain] += count
                for dest_ip, count in data['dest_ips'].items():
                    all_ip_requests[ip]['dest_ips'][dest_ip] += count

    return all_ip_requests

# Command-line argument parser setup
def main():
    parser = argparse.ArgumentParser(description="Parse a folder of PCAP files and count DNS queries by IP address, domain names, and destination IPs.")
    parser.add_argument("folder", help="Path to the folder containing PCAP files")
    parser.add_argument("--ip", help="Filter queries for a specific source IP address", required=False)
    args = parser.parse_args()

    # Parse the folder and optionally filter by IP
    ip_requests = parse_pcap_folder(args.folder, ip_filter=args.ip)

    # Display results
    for ip, data in ip_requests.items():
        if args.ip and ip != args.ip:
            continue  # Skip if filtering by specific IP and it doesn't match
        print("================================================================")
        print(f"\nSource IP: {ip}")
        print(f"Total DNS Queries: {data['count']}")
        print("Queried Domain Names:")
        for domain, count in data['domains'].items():
            print(f"  {domain}: {count} queries")
        print()
        print("Destination IP Addresses:")
        for dest_ip, count in data['dest_ips'].items():
            print(f"  {dest_ip}: {count} queries")

if __name__ == "__main__":
    main()
