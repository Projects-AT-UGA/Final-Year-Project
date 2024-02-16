import sys
import os
import glob
import json

from scapy.all import *
from collections import defaultdict
from datetime import datetime


def get_subdirectories(directory):
    subdirectories = []
    for item in os.listdir(directory):
        item_path = os.path.join(directory, item)
        if os.path.isdir(item_path):
            subdirectories.append(item)
    return subdirectories
def get_pcap_files(directory):
    pcap_files = []
    
    for file in os.listdir(directory):

        if file.endswith(".pcap"):
            pcap_files.append(os.path.join(directory, file))
    return pcap_files


def extract_mdns_data(pcap_file):
    qtype_mapping = {
    1: "A", 2: "NS", 3: "MD", 4: "MF", 5: "CNAME",
    6: "SOA", 7: "MB", 8: "MG", 9: "MR", 10: "NULL",
    11: "WKS", 12: "PTR", 13: "HINFO", 14: "MINFO",
    15: "MX", 16: "TXT", 17: "RP", 18: "AFSDB", 19: "X25",
    20: "ISDN", 21: "RT", 22: "NSAP", 23: "NSAP_PTR",
    24: "SIG", 25: "KEY", 26: "PX", 27: "GPOS", 28: "AAAA",
    29: "LOC", 30: "NXT", 31: "EID", 32: "NIMLOC", 33: "SRV",
    34: "ATMA", 35: "NAPTR", 36: "KX", 37: "CERT", 38: "A6",
    39: "DNAME", 40: "SINK", 41: "OPT", 42: "APL", 43: "DS",
    44: "SSHFP", 45: "IPSECKEY", 46: "RRSIG", 47: "NSEC",
    48: "DNSKEY", 49: "DHCID", 50: "NSEC3", 51: "NSEC3PARAM",
    52: "TLSA", 53: "SMIMEA", 54: "HIP", 55: "NINFO", 56: "RKEY",
    57: "TALINK", 58: "CDS", 59: "CDNSKEY", 60: "OPENPGPKEY",
    61: "CSYNC", 62: "ZONEMD", 63: "SVCB", 64: "HTTPS", 65: "SPF",
    99: "UINFO", 100: "UID", 101: "GID", 102: "UNSPEC", 103: "NID",
    104: "L32", 105: "L64", 106: "LP", 107: "EUI48", 108: "EUI64",
    109: "TKEY", 249: "TKEY", 250: "TSIG", 251: "IXFR", 252: "AXFR",
    253: "MAILB", 254: "MAILA", 255: "ANY",
    **{i: "RESERVED" for i in range(32770, 65536)}  # Handling reserved qtypes
    }


    qclass_mapping = {
    1: "IN",  # Internet
    2: "CS",  # CSNET (Obsolete)
    3: "CH",  # CHAOS
    4: "HS",  # Hesiod
    **{i: "RESERVED" for i in range(32768, 65536)}  # Handling reserved qclasses
    }


    opcode_mapping = {
    0: "Query",
    1: "Inverse Query",
    2: "Status",
    **{i: "RESERVED" for i in range(3, 16)}  # Handling reserved opcodes
    }

    mdns_data = defaultdict(list)

    pkts = rdpcap(pcap_file)
    for pkt in pkts:
        if DNS in pkt and pkt.haslayer(IP) and UDP in pkt:
            # Ensure the packet is an mDNS packet by checking the destination port (5353)
            if pkt[UDP].dport == 5353:
                # Check if the DNS question section exists
                if pkt.haslayer(DNSQR):
                    domain = pkt[DNS].qd.qname.decode('utf-8')
                    dest_ip = pkt[IP].dst
                    timestamp = float(pkt.time)
                    date = datetime.fromtimestamp(timestamp)
                    id = pkt[DNS].id
                    qtype = pkt[DNS].qd.qtype
                    qclass = pkt[DNS].qd.qclass
                    rd = pkt[DNS].rd
                    tc = pkt[DNS].tc
                    aa = pkt[DNS].aa
                    opcode = pkt[DNS].opcode


                    # Map numeric values to human-readable strings
                    qtype_str = qtype_mapping.get(qtype, "Unknown")
                    qclass_str = qclass_mapping.get(qclass, "Unknown")
                    opcode_str = opcode_mapping.get(opcode, "Unknown")

                    # Store the mDNS data
                    mdns_data[domain].append({
                        "destination_ip": dest_ip,
                        "date": date,
                        "id": id,
                        "qtype": qtype,
                        "qclass": qclass,
                        "qtype_human_readable": qtype_str,
                        "qclass_human_readable": qclass_str,
                        "rd": rd,
                        "tc": tc,
                        "aa": aa,
                        "opcode": opcode,
                        "opcode_human_readable": opcode_str
                    })

    return mdns_data



# Function to extract DNS data from pcap files
# Function to extract DNS data from pcap files
def extract_dns_data(pcap_file):
    # Define a dictionary to store DNS data
    dns_data = defaultdict(list)

    # Mapping dictionaries for qtype, qclass, and opcode
    qtype_mapping = {
        1: "A",
        2: "NS",
        5: "CNAME",
        15: "MX",
        28: "AAAA",
        # Add more mappings as needed
    }

    qclass_mapping = {
        1: "IN",
        # Add more mappings as needed
    }

    opcode_mapping = {
        0: "Query",
        1: "Inverse Query",
        2: "Status",
        # Add more mappings as needed
    }

    pkts = rdpcap(pcap_file)
    for pkt in pkts:
        if pkt.haslayer(DNS) and pkt.haslayer(IP):
            if pkt[DNS].qr == 0:
                # Extract DNS data from DNS query packets
                domain = pkt[DNS].qd.qname.decode('utf-8')
                dest_ip = pkt[IP].dst
                timestamp = float(pkt.time)
                date = datetime.fromtimestamp(timestamp)
                id = pkt[DNS].id
                qtype = pkt[DNS].qd.qtype
                qtype_str = qtype_mapping.get(qtype, "Unknown")  # Get the string representation from the mapping
                qclass = pkt[DNS].qd.qclass
                qclass_str = qclass_mapping.get(qclass, "Unknown")  # Get the string representation from the mapping
                rd = pkt[DNS].rd
                tc = pkt[DNS].tc
                aa = pkt[DNS].aa
                opcode = pkt[DNS].opcode
                opcode_str = opcode_mapping.get(opcode, "Unknown")  # Get the string representation from the mapping
                dns_data[domain].append({
                    "destination_ip": dest_ip,
                    "date": date,
                    "id": id,
                    "qtype": qtype,
                    "qclass": qclass,
                    "qtype_human_readable": qtype_str,
                    "qclass_human_readable": qclass_str,
                    "rd": rd,
                    "tc": tc,
                    "aa": aa,
                    "opcode": opcode,
                    "opcode_human_readable": opcode_str  # New variable to store human-readable opcode
                })

    return dns_data

def print_Dns(dns_data):
    for domain, entries in dns_data.items():
            print(f"Domain: {domain}")
            for entry in entries:
                print(entry)



def write_dns_data_to_json(dns_data,directory,subdirectory,filename):
    if not os.path.exists(directory):
        os.makedirs(directory)
    subdirectory = os.path.join(directory, subdirectory)

    if not os.path.exists(subdirectory):
        os.makedirs(subdirectory)

    # Define the file path for the JSON file
    file_path = os.path.join(subdirectory, filename)
   
    # Write the dns_data dictionary to the JSON file
    with open(file_path, 'w+') as json_file:
        json.dump(dns_data, json_file, default=str, indent=4)






def main():
    

    #directory from where all the subdirectories should contain pcap files 
    
    directory = "./AUSTRALIA_PCAPS"
    subdirectories = get_subdirectories(directory)
   

    eachdirectories_pcapfiles={} #initalize a directory to storeall pcap files
    for singlesubdirectory in subdirectories: #extract names of all pcap files from directories
        current_dir = os.getcwd()
        currdirectory=os.path.join(current_dir,directory, singlesubdirectory)
        pcap_files = get_pcap_files(currdirectory)
        eachdirectories_pcapfiles[singlesubdirectory]=pcap_files 
        
    
    
    files_with_no_mdns_data=[]
    for eachdirectory in eachdirectories_pcapfiles:#for each pcap file do the parsing
        count=0
        for eachfile in eachdirectories_pcapfiles[eachdirectory]:
            dns_data = extract_mdns_data(eachfile)

            if bool(dns_data):
                write_dns_data_to_json(dns_data, directory+"_DATA", eachdirectory,os.path.splitext(os.path.basename(eachfile))[0]+".json")
            else:
                files_with_no_mdns_data.append(eachfile)
            count+=1
       
    print(files_with_no_mdns_data)
     
    

if __name__ == "__main__":
    main()





