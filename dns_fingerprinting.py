# Author: Darpan Shrivastava

import json, os, argparse, time
from scapy.all import *
#from Levenshtein import distance as lev
from dateutil.relativedelta import relativedelta
from datetime import datetime, timedelta

device_dictionary = {"192.168.1.2": "PixStar_FotoConnect", "192.168.1.3": "Google_NestProtect", 
                     "192.168.1.4": "Samsung_WisenetSmartCam_A1", "192.168.1.5": "TP-Link_TapoHomesecurityCamera", 
                     "192.168.1.6": "Dlink_Omna180CamHD", "192.168.1.8": "Sengled_SmartBulbStarterKit", 
                     "192.168.1.9": "Amazon_EchoDot3rdGeneration", "192.168.1.10": "Amazon_EchoDot", 
                     "192.168.1.11": "Amazon_Echo", "192.168.1.12": "Withings_Body+SmartScale",
                     "192.168.1.15": "Wansview_WirelessCloudcamera", "192.168.1.16": "SmartAtoms_LaMetricTime",
                     "192.168.1.17": "Netatmo_SmartHomeWeatherStation", "192.168.1.18": "HP_OfficeJetPro6978",
                     "192.168.1.19": "TP-Link_TapoMiniSmartWifiSocket1", "192.168.1.20": "TP-Link_TapoMiniSmartWifiSocket2",
                     "192.168.1.21": "TP-Link_KasaSmartWifiPlugMini1", "192.168.1.22": "TP-Link_KasaSmartWifiPlugMini2",
                     "192.168.1.23": "Lifx_SmarterLights", "192.168.1.24": "TP-Link_KasaSmartWiFiLightBulbMulticolor",
                     "192.168.1.25": "Philips_HueBridge", "192.168.1.26": "D-Link_FullHDPan&TiltProHDWifiCamera",
                     "192.168.1.30": "Meross_SmartWiFiGarageDoorOpener", "192.168.1.31": "Yi_1080pHomeCameraAIPlus",
                     "192.168.1.32": "iRobot_RoombaRobotVaccum", "192.168.1.33": "Reolink_RLC520Camera1",
                     "192.168.1.34": "Reolink_RLC520Camera2", "192.168.1.35": "Amcrest_SecurityTurretCamera",
                     "192.168.1.37": "Wemo_WiFiSmartLightSwitch", "192.168.1.38": "Ecobee_Switch+",
                     "192.168.1.43": "Insignia_FireTV", "192.168.1.44": "Xiaomi_360HomeSecurityCamera2k",
                     "192.168.1.47": "TP-Link_KasaSmartLightStrip", "192.168.1.48": "Ring_Doorbell4",
                     "192.168.1.49": "Ecobee_3liteSmartThermostat", "192.168.1.50": "Google_NestThermostat"}

vendor_level = {"amazon_vendor": ["192.168.1.9", "192.168.1.10", "192.168.1.11"], "dlink_vendor":["192.168.1.6", "192.168.1.26"], 
                "tplink_vendor": ["192.168.1.5", "192.168.1.19", "192.168.1.20", "192.168.1.21", "192.168.1.22", "192.168.1.24", "192.168.1.47"], "reolink_vendor": ["192.168.1.33", "192.168.1.34"],
                "ecobee_vendor": ["192.168.1.38", "192.168.1.49"], "google_vendor": ["192.168.1.3", "192.168.1.50"]}

# This is used to sort the order in which the subdirectory is to be opened
def sort_pcapdir(path_to_file):

    subdir_needed = []
    if args.day:
        subdir_needed.append(args.date)
    elif args.week:
        count_days = 6
        subdir_needed.append(args.date)
        starting_date_object = datetime.strptime(subdir_needed[0], "%Y%m%d")
        for i in range(count_days):
            ending_date_intermediate = starting_date_object + timedelta(days=i+1)
            ending_date = datetime.strftime(ending_date_intermediate, "%Y%m%d")
            subdir_needed.append(ending_date)
    elif args.month:
        starting_date_object = datetime.strptime(args.date, "%Y%m%d")
        ending_date_object = starting_date_object + relativedelta(months=1) - timedelta(days=1)
        delta = ending_date_object - starting_date_object

        for i in range(delta.days + 1):
            days = starting_date_object + timedelta(days=i)
            subdir_needed.append(datetime.strftime(days,"%Y%m%d"))
    return subdir_needed

# Sort pcap files in increasing order by time
def sort_pcap(entries): 
    return sorted(entries)

# Main logic to parse pcap and get dns information
def iterate_parse_pcap(subdirs, ip_address, dns_data):
    for items in subdirs:
        print("Dealing with the following Subdirectory: ",path.split("/")[-2].split("_")[0] +"="+items)
        for filename in os.listdir(path+items):

            if filename.endswith(".pcap"):
                pcap_file = os.path.join(path,items, filename)
    

        # read PCAP file
                packets = rdpcap(pcap_file)

        # loop through packets
            for packet in packets:
                # check if packet is a DNS request from the selected IP address
                if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0 and (packet[IP].src == ip_address and packet[IP].dst != "224.0.0.251"):
                    # extract domain name, destination IP address, and timestamp
                    domain = packet.getlayer(DNS).qd.qname.decode()
                    dest_ip = packet[IP].dst
                    timestamp = packet.time
                    date = datetime.fromtimestamp(int(timestamp)).strftime("%Y-%m-%d %H:%M:%S")
                    # extract more information from the DNS packet
                    id = packet.getlayer(DNS).id
                    qtype = packet.getlayer(DNS).qd.qtype
                    qclass = packet.getlayer(DNS).qd.qclass
                    rd = packet.getlayer(DNS).rd
                    tc = packet.getlayer(DNS).tc
                    aa = packet.getlayer(DNS).aa
                    opcode = packet.getlayer(DNS).opcode

                    # add data to dictionary
                    
                    if domain not in dns_data:
                        dns_data[domain] = []
                    dns_data[domain].append({
                        "destination_ip": dest_ip,
                        "date": date,
                        "id": id,
                        "qtype": qtype,
                        "qclass": qclass,
                        "rd": rd,
                        "tc": tc,
                        "aa": aa,
                        "opcode": opcode
                    })
                    # print(dns_data)

# This function is to change the ip_address. Specifically, change the subnet to india.                 
def change_ip(ip_str):
    ip_list = (ip_str).split(".")
    ip_list[2] = "2"
    return ".".join(ip_list)

# This function formats the JSON dictionary to only get the requested fields. 
def compare_values(data):
   result = {}
   for key in data:
       values = data[key]
       domain_result = {}
       for value in values:
           ip = value.get("destination_ip")
           if ip in domain_result:   
                domain_result[ip].append(value)
           else:
               domain_result[ip] = [value]
       result[key] = domain_result
   return result

# This function splits the domain names by a delimeter and tries to find common substrings.
def match_domains(dict1, dict2):
    for key1 in dict1.keys():
        parts1 = key1.split('.')
        for key2 in dict2.keys():
            parts2 = key2.split('.')
            if key1 == key2:
                print("Complete Match: ", key1 ,"and", key2)
            else:

                if parts1[-1] == parts2[-1] and parts1[-2] == parts2[-2]:
                    common_parts = []
                    for i, part1 in enumerate(parts1):
                        for j, part2 in enumerate(parts2):
                            if part1 == part2:
                                common_parts.append(part1)
                            else:
                            # Check for common substring
                                new_list = []
                                for k in range(2, min(len(part1), len(part2))+1):
                                    if part1[:k] == part2[:k]:
                                        new_list.append(part1[:k])
                                if new_list:
                                    common_parts.append(new_list[-1])
                # Filter out empty strings from the list of common parts
                    common_parts = [part for part in common_parts if part]
                    if len(common_parts) > 0:
                        print("Matched parts: " + str(common_parts) + " in keys '" + key1+ "of AUS" + "' and '" + key2 + "of IND" +"'.")

# This function removes any duplicate domains.
def remove_dups(path):
    with open(path) as f:
        data = json.load(f)

    # Find and delete the dictionaries that have a matching key
    keys_to_delete = []
    for i, (key1, dict1) in enumerate(data.items()):
        for key2, dict2 in list(data.items())[i+1:]:
            for inner_key in dict1.keys():
                if inner_key in dict2:
                    print(f"Matching key '{inner_key}' found in dictionaries '{key1}' and '{key2}'")
                    keys_to_delete.append((key1, key2, inner_key))
    
    if len(keys_to_delete) == 0:
        print("No duplicates found. Nothing to delete")
        return
    
    # Remove the duplicate keys from the dictionaries
    for items in keys_to_delete:
        try:
            del data[items[0]][items[2]]
        except:
            pass
        try:
            del data[items[1]][items[2]]
        except:
            pass
    
    # Remove the duplicate dictionaries
    #for key in keys_to_delete:
    #    del data[key]
    
    # Write the remaining data to a new JSON file
    os.remove(path)
    with open(path, 'w') as f:
        json.dump(data, f, indent=4)

# This function is not being used for now. 
def levenshtein_distance(a,b):
    return lev(a,b)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='DNS fingerprinting')
    parser.add_argument('--ip', dest='ip',type=str ,help=' Specify IP Address. Format - 192.168.1.x. THIS IS AN OPTIONAL FIELD AND WILL NOT WORK WITH THE VENDOR FLAG.')
    parser.add_argument('--date', dest='date',type=str ,help='Input initial date. Format - YYYYMMDD.')
    parser.add_argument('--day', dest='day', action='store_true',help='Analysis for a day')
    parser.add_argument('--week', dest='week',action='store_true', help='Analysis for a week')
    parser.add_argument('--month', dest='month',action='store_true', help='Analysis for a month. PLease start from the start of the month.') # This feature has not been tested. 
    parser.add_argument('--vendor', dest='vendor',action='store_true', help='Vendor level analysis for pair of devices that have no unique fingerprints')
    #starttime = time.time()
    args = parser.parse_args()

    # Only Change the below paths accordingly.
    path_aus  = './AUSTRALIA_PCAPS/'
    path_ind = '/.../.../.../.../INDIA_PCAPS/'
    print(args.vendor)

    if args.vendor:
        if args.day:
            duration = "_day"
        elif args.week:
            duration = "_week"
        elif args.month:
            duration = "_month"
        else:
            print("Invalid duration specified")
        for key, items in vendor_level.items():
            aus_fingerprint = {} # This dictionary contains the  requestsed domain and the IP address.
            ind_fingerprint = {} # This dictionary contains the  requestsed domain and the IP address.
            result = {}
            result1 = {}
            print("Vendor:", key)
            for ip_address in items:
                dns_data_aus = {}
                dns_data_ind = {}

                print("Dealing with IP: " + ip_address)

                path  = path_aus

                subdirs = sort_pcapdir(path_aus)

                iterate_parse_pcap(subdirs, ip_address, dns_data_aus)

                aus = compare_values(dns_data_aus)

                # This dictionary contains the requested domain and the IP address.
                for item in aus.keys():
                    aus_fingerprint[item] = list(aus[item].keys())

                subdirs.clear()

                path = path_ind

                subdirs = sort_pcapdir(path_ind)
                ind_ip_address = change_ip(ip_address)

                # iterate_parse_pcap(subdirs, ind_ip_address, dns_data_ind)

                ind = compare_values(dns_data_ind)

                for item in ind.keys():
                    ind_fingerprint[item] = list(ind[item].keys())

                for domain in set(aus_fingerprint.keys()).union(ind_fingerprint.keys()):
                    if domain in aus_fingerprint and domain in ind_fingerprint:
                        if aus_fingerprint[domain] == ind_fingerprint[domain]:
                            result[domain] = aus_fingerprint[domain]
                        else:
                            result[domain] = {'AUS': aus_fingerprint[domain], 'IND': ind_fingerprint[domain]}
                    elif domain in aus_fingerprint:
                        result[domain] = {'AUS': aus_fingerprint[domain]}
                    elif domain in ind_fingerprint:
                        result[domain] = {'IND': ind_fingerprint[domain]}
                
                for domain in set(aus_fingerprint.keys()).intersection(ind_fingerprint.keys()):
                    if domain in aus_fingerprint and domain in ind_fingerprint:
                        if aus_fingerprint[domain] == ind_fingerprint[domain]:
                            result1[domain] = aus_fingerprint[domain]
                        else:
                            result1[domain] = {'AUS': aus_fingerprint[domain], 'IND': ind_fingerprint[domain]}
                    elif domain in aus_fingerprint:
                        result1[domain] = {'AUS': aus_fingerprint[domain]}
                    elif domain in ind_fingerprint:
                        result1[domain] = {'IND': ind_fingerprint[domain]}

            # This is for intersection for vendor level devices
            try:
                if os.path.isfile("vendor_intersection_" + args.date + duration + ".json"):
                    with open("vendor_intersection_" + args.date + duration + ".json", "r") as outfile: 
                        data = json.loads(outfile.read())
                        data[key] = result1

                    with open("vendor_intersection_" + args.date + duration + ".json", "w") as output_file:
                        json.dump(data, output_file, indent=4)
                else:
                    print("Output file does not exist. Creating it now...")
                    data = {}
                    data[key] = result1
                    with open("vendor_intersection_" + args.date + duration + ".json", "w") as output_file:
                        json.dump(data, output_file, indent=4)

            except json.decoder.JSONDecodeError:
                data = {}
                data[key] = result1
                with open("vendor_intersection_" + args.date + duration +".json", "w") as output_file:
                        json.dump(data, output_file, indent=4)
            

            # This is for union for vendor level devices
            try:
                if os.path.isfile("vendor_union_" + args.date + duration + ".json"):
                    with open("vendor_union_" + args.date + duration + ".json", "r") as outfile: 
                        data = json.loads(outfile.read())
                        data[key] = result

                    with open("vendor_union_" + args.date + duration + ".json", "w") as output_file:
                        json.dump(data, output_file, indent=4)
                else:
                    print("Output file does not exist. Creating it now...")
                    data = {}
                    data[key] = result
                    with open("vendor_union_" + args.date + duration + ".json", "w") as output_file:
                        json.dump(data, output_file, indent=4)

            except json.decoder.JSONDecodeError:
                data = {}
                data[key] = result
                with open("vendor_union_" + args.date + duration +".json", "w") as output_file:
                        json.dump(data, output_file, indent=4)

        remove_dups("vendor_intersection_"  +args.date + duration +".json")   
        remove_dups("vendor_union_"  +args.date + duration +".json")

    else:
        if args.day:
            duration = "_day"
        elif args.week:
            duration = "_week"
        elif args.month:
            duration = "_month"
        else:
            print("Invalid duration specified")
        if args.ip:
            test = [args.ip]
        else:
            test = device_dictionary.keys()
        for items in test:   #device_dictionary.keys()
            dns_data_aus = {}
            dns_data_ind = {}
            print("Dealing with IP: " + items)
            
            path  = path_aus

            subdirs = sort_pcapdir(path_aus)

            iterate_parse_pcap(subdirs, items, dns_data_aus)

            aus = compare_values(dns_data_aus)

            aus_fingerprint = {}  # This dictionary contains the  requestsed domain and the IP address.
    
            for item in aus.keys():
                aus_fingerprint[item] = list(aus[item].keys())

            subdirs.clear()

            path = path_ind

            subdirs = sort_pcapdir(path_ind)
            ind_ip_address = change_ip(items)

            #iterate_parse_pcap(subdirs, ind_ip_address, dns_data_ind)

            ind = compare_values(dns_data_ind)

            ind_fingerprint = {} # This dictionary contains the  requestsed domain and the IP address.

            for item in ind.keys():
                ind_fingerprint[item] = list(ind[item].keys())

            match_domains(aus_fingerprint, ind_fingerprint)

            # The below code just extract the keys and then uses intersection to find common keys. 
            result = {}
            for domain in set(aus_fingerprint.keys()).intersection(ind_fingerprint.keys()):
                if aus_fingerprint[domain] == ind_fingerprint[domain]:
                    result[domain] = aus_fingerprint[domain]
                else:
                    result[domain] = {'AUS': aus_fingerprint[domain], 'IND': ind_fingerprint[domain]}

            if device_dictionary[items] is not None:  #get(args.ip)
                device_name = device_dictionary[items]
            else:
                print("Device does not exist in the device_dictionary. Kindly check.")
            data={}
            try:
                with open("dns_invariants_" +args.date + duration +".json", "r") as outfile: 
                    data = json.loads(outfile.read())
                    data[device_name] = result
            except:
                pass
            with open("dns_invariants_"  +args.date + duration +".json", "w+") as output_file:
                json.dump(data, output_file, indent=4)
        
        remove_dups("dns_invariants_"  +args.date + duration +".json")