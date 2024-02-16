

import dpkt

def print_mdns_packets(pcap_file):
    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for timestamp, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if isinstance(eth.data, dpkt.ip.IP) and isinstance(eth.data.data, dpkt.udp.UDP):
                ip = eth.data
                udp = ip.data
                if udp.sport == 5353 or udp.dport == 5353:
                    mdns = dpkt.dns.DNS(udp.data)
                    if mdns.qr == dpkt.dns.DNS_R:
                        print(f"Timestamp: {timestamp}, mDNS Packet: {mdns}")
                        # Additional processing or printing of mDNS packet details can be done here

def main():
    pcap_file = 'AUSTRALIA_20221001_00_04_16_UTC.pcap'
    print_mdns_packets(pcap_file)

if __name__ == "__main__":
    main()
