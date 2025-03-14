from scapy.all import *
import  os, json, argparse
matched_output = {} # This dictionary contains the invariants.
output = {} # This dictionary holds the JSON that will contain the mDNS invariants for now.
#occured_items = set()


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
                     "192.168.1.42": "Google_NestMini", "192.168.1.46": "Google_Chromecast",
                     "192.168.1.43": "Insignia_FireTV", "192.168.1.44": "Xiaomi_360HomeSecurityCamera2k",
                     "192.168.1.47": "TP-Link_KasaSmartLightStrip", "192.168.1.48": "Ring_Doorbell4",
                     "192.168.1.49": "Ecobee_3liteSmartThermostat", "192.168.1.50": "Google_NestThermostat"}

################################
#------Necessary Functions-----#
################################

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

# This function is to change the ip_address. Specifically, change the subnet to india.                 
def change_ip(ip_str):
    ip_list = (ip_str).split(".")
    ip_list[2] = "2"
    return ".".join(ip_list)

# This function is for parsing type A response. 
def a_response_type(item, response_type, source_ip): 
    #rdata = item.rdata
    rrname = item.rrname.decode() # Decode the rrname field.
    record = {
        "rrname": rrname,
    }

    device_name_delimeter = source_ip.split(".")
    if device_name_delimeter[2] =="2":
        device_name = device_dictionary.get(source_ip.replace(".2", ".1"))
    else:
        device_name = device_dictionary.get(source_ip)

    if response_type not in output[device_name]:
        output[device_name][response_type] = [record]
    else:
        for item in output[device_name][response_type]:
            previous_record_rrname = item["rrname"]
            if previous_record_rrname == record["rrname"]:
                break
        else:
            output[device_name][response_type].append(record)

# This function is for parsing type PTR response.
def ptr_response_type(item, response_type, source_ip):
    rrname = item.rrname.decode() # Decode the rrname field.  
    rdata = item.rdata.decode()
    record = {
        "rrname": rrname,
        "rdata": rdata
    }

    device_name_delimeter = source_ip.split(".")
    if device_name_delimeter[2] =="2":
        device_name = device_dictionary.get(source_ip.replace(".2", ".1"))
    else:
        device_name = device_dictionary.get(source_ip)

    if response_type not in output[device_name]:
        output[device_name][response_type] = [record]
    else:
        for item in output[device_name][response_type]:
            previous_record_rrname = item["rrname"]
            previous_record_rdata = item["rdata"]
            if (previous_record_rrname == record["rrname"]) or (previous_record_rdata == record["rdata"]):
                break
        else:
            output[device_name][response_type].append(record)

# This function is for parsing type TXT response. 
def txt_response_type(item, response_type, source_ip): 
    rrname = item.rrname.decode() # Decode the rrname field.
    rdata_list = []
    rdata = item.rdata
    #print(rdata)
    for items in rdata:
        rdata_list.append(items.decode())

    record = {
        "rrname": rrname,
        "rdata": rdata_list,
    }

    device_name_delimeter = source_ip.split(".")
    if device_name_delimeter[2] =="2":
        device_name = device_dictionary.get(source_ip.replace(".2", ".1"))
    else:
        device_name = device_dictionary.get(source_ip)

    if response_type not in output[device_name]:
        #print(item)
        output[device_name][response_type] = [record]
    else:
        for item in output[device_name][response_type]:
            previous_record_rrname = item["rrname"]
            previous_record_rdata = item["rdata"]
            #print(item)
            if (previous_record_rrname == record["rrname"]) or (previous_record_rdata == record["rdata"]):
                break
        else:
            output[device_name][response_type].append(record)

# This function is for parsing type SRV response. 
def srv_response_type(item, response_type, source_ip): 
    rrname = item.rrname.decode() # Decode the rrname field.
    srv_priority = item.priority
    srv_port = item.port
    srv_weight = item.weight
    srv_target = item.target.decode('utf-8')
    record = {
        "rrname": rrname,
        "target": srv_target,
        "weight": srv_weight,
        "port": srv_port,
        "priority": srv_priority
    }

    device_name_delimeter = source_ip.split(".")
    if device_name_delimeter[2] =="2":
        device_name = device_dictionary.get(source_ip.replace(".2", ".1"))
    else:
        device_name = device_dictionary.get(source_ip)

    if response_type not in output[device_name]:
        output[device_name][response_type] = [record]
    else:
        for item in output[device_name][response_type]:
            #print(item)
            previous_record_rrname = item["rrname"]
            previous_record_target = item["target"]
            previous_record_weight = item["weight"]
            previous_record_port = item["port"]
            previous_record_priority = item["priority"]
            #print(item)
            if (previous_record_rrname == record["rrname"]) or (previous_record_target == record["target"]) or (previous_record_weight == record["weight"]) or (previous_record_port == record["port"]) or (previous_record_priority == record["priority"]):
                break
        else:
            output[device_name][response_type].append(record)

# This function parses the packets and returns the JSON file. 
def iterate_parse_pcap(subdirs, path, output_file_name):
    for items in subdirs:
        print("Dealing with the following Subdirectory: ",path.split("/")[-2].split("_")[0] +"="+items)
        for filename in os.listdir(path+"/"+items):
            #print(filename)
            if filename.endswith(".pcap"):
                pcap_file = os.path.join(path,items, filename)
        packets = rdpcap(pcap_file)
        for packet in packets: # Looping through each packet. 
            if packet.haslayer(DNS) and (packet[IP].dst == "224.0.0.251"): # Filtering and only getting mDNS packets based on the destination IP address.
                if packet[DNS].qr == 0: # Checking if it is a request packet. If so, we do nothing. 
                    #print("This is a request. Doing nothing.")
                    pass
                elif packet[DNS].qr == 1: # Checking if it is a response packet
                    source_ip = packet[IP].src # Getting the source IP address.
                    #print(source_ip)

                    device_name_delimeter = source_ip.split(".")
                    if device_name_delimeter[2] =="2":
                        device_name = device_dictionary.get(source_ip.replace(".2", ".1"))
                    else:
                        device_name = device_dictionary.get(source_ip)

                    if device_name not in output: # Creating a dictionary inside output to hold source IP address as a key.
                            output[device_name] = {}

                    # print answer section
                    if packet[DNS].ancount > 0: # Counting the answer section as it can contain multiple records. 
                        ancount = packet[DNS].ancount
                        for items in range(ancount): # Looping through the answer section
                            answer = packet[DNS].an[items]
                            #rrname = answer.rrname.decode() # Decode the rrname field.
                            response_type = dnsqtypes.get(answer.type) # Getting the response type such as A, TXT, PTR etc.

                            if response_type == "A":  # A record
                                a_response_type(answer, response_type, source_ip)

                            elif response_type == "PTR":  # PTR record
                                ptr_response_type(answer, response_type, source_ip)

                            elif response_type == "TXT":  # TXT record
                                txt_response_type(answer, response_type, source_ip)
                        
                            elif response_type == "SRV":  # SRV record
                                srv_response_type(answer, response_type, source_ip)
            
                            else:
                                print("Unknown record type:", response_type)
                    
                    # print additional section
                    if packet[DNS].arcount > 0: # Counting the additional section as it can contain multiple records.
                        arcount = packet[DNS].arcount
    
                        for items in range(arcount): # Looping through the additional section
                            add = packet[DNS].ar[items]
                            response_type = dnsqtypes.get(add.type) # Getting the response type such as A, TXT, PTR etc.
                    
                            if add.type == 1:  # A record
                                a_response_type(add, response_type, source_ip)
                        
                            elif add.type == 12:  # PTR record
                                ptr_response_type(add, response_type, source_ip)
                        
                            elif add.type == 16:  # TXT record
                                txt_response_type(add, response_type, source_ip)
                        
                            elif add.type == 33:  # SRV record
                                srv_response_type(add, response_type, source_ip)
                        
                            else:
                                print("Unknown record type:", response_type)

                    try:  # The below code is responsible for creating a JSON file. TWe will change this so that it is more error prone.
                        if os.path.isfile(output_file_name):
                                with open(output_file_name, "r") as outfile: 
                                    data = json.loads(outfile.read())
                            

                                with open(output_file_name, "w") as output_file:
                                    json.dump(output, output_file, indent=4)
                        else:
                            print("Output file does not exist. Creating it now...") #
                # data = {}
                # data[key] = 
                            with open(output_file_name, "w") as output_file:
                                json.dump(output, output_file, indent=4)

                    except json.decoder.JSONDecodeError:
                        data = {}
                        data[key] = result
                        with open(output_file_name, "w") as output_file:
                            json.dump(data, output_file, indent=4)


# This function takes the two dictionaries and finds the common keys. Then tries to find common substrings from them. This creates a new json file. 
def compare_dict(dict_aus,dict_ind):
    common_devices = list(set(dict_aus.keys()) & set(dict_ind.keys()))
    uncommon_devices_aus = list(dict_aus.keys() - common_devices) # Not doing anything for now to the uncommon devices. 
    uncommon_devices_ind = list(dict_ind.keys() - common_devices) # Not doing anything for now to the uncommon devices. 
    
    for keys in common_devices:
        matched_output[keys] = {}
        #print(keys)
        aus_type = dict_aus[keys]
        ind_type = dict_ind[keys]
        #print(aus_type)
        for response_type in aus_type:
            
            if response_type == "SRV":
                rrname_list = []
                target_list = []
                for aus_items in aus_type[response_type]:
                    rrname_aus = aus_items["rrname"]
                    target_aus = aus_items["target"]
                    for ind_items in ind_type[response_type]:
                        rrname_ind = ind_items["rrname"]
                        target_ind = ind_items["target"]

                        rrname_list.append(find_common_strings(rrname_aus, rrname_ind,4))
                        combined_rrname_list = list(set(sum(rrname_list, [])))

                        target_list.append(find_common_strings(target_aus, target_ind,4))
                        combined_target_list = list(set(sum(target_list, [])))
                record = {
                    "rrname": combined_rrname_list,
                    "target": combined_target_list
                }
                if response_type not in matched_output[keys]:
                    matched_output[keys][response_type] = [record]


            elif response_type == "PTR":
                
                rrname_list = []
                rdata_list = []
                for aus_items in aus_type[response_type]:
                    rrname_aus = aus_items["rrname"]
                    rdata_aus = aus_items["rdata"]
                    for ind_items in ind_type[response_type]:
                        rrname_ind = ind_items["rrname"]
                        rdata_ind = ind_items["rdata"]

                        
                        rrname_list.append(find_common_strings(rrname_aus, rrname_ind,4))
                        combined_rrname_list = list(set(sum(rrname_list, [])))
                        #occured_items.update(combined_rrname_list)
                        #print(combined_rrname_list)

                        rdata_list.append(find_common_strings(rdata_aus, rdata_ind,4))
                        combined_rdata_list = list(set(sum(rdata_list, [])))
                        #occured_items.update(combined_rrname_list)

                
                record = {
                    "rrname": combined_rrname_list,
                    "rdata": combined_rdata_list
                }
                if response_type not in matched_output[keys]:
                    matched_output[keys][response_type] = [record]

            elif response_type == "A":
                
                rrname_list = []
                
                for aus_items in aus_type[response_type]:
                    rrname_aus = aus_items["rrname"]
                    
                    for ind_items in ind_type[response_type]:
                        rrname_ind = ind_items["rrname"]

                        
                        rrname_list.append(find_common_strings(rrname_aus, rrname_ind,4))
                        combined_rrname_list = list(set(sum(rrname_list, [])))
                        #print(combined_rrname_list)
                
                record = {
                    "rrname": combined_rrname_list
                }
                if response_type not in matched_output[keys]:
                    matched_output[keys][response_type] = [record]
            

        
    with open("testing_match.json", "w") as output_file:
        json.dump(matched_output, output_file, indent=4)
                #print(rdata_list)

                        #print(result)
                        #print("--------------------------------")
                        #quit()
                        #record = {
                        #    "rrname": rrname,
                        #    "rdata": rdata_list,
    #}
                        #matched_output[keys][response_type] = [result]

                        
                        #result.append(''.join(rrname_aus[len(result):]))
                        #print(rdata_list)

                        #print(rrname_aus)
                        #print(rdata_aus)
                        #print(rrname_ind)
                        #print(rdata_ind)
                        

                        
                    
        #quit()

# this function is not being used. Expermiental function to find common substrings. 
def find_common_substrings(s1, s2):
    m, n = len(s1), len(s2)
    common_substrings = set()
    
    for i in range(m):
        for j in range(n):
            k = 0
            # iterate over matching characters
            while (i+k < m and j+k < n and s1[i+k] == s2[j+k]):
                k += 1
                # add current common substring to set
                common_substrings.add(s1[i:i+k])
    
    # remove substrings of length 1
    common_substrings.discard('')
    #common_substrings.
    # sort by length and lexicographically
    return sorted(sorted(common_substrings), key=len)

# this function is not being used. Expermiental function to find common substrings. 
def LCS(str1, str2):
    m = len(str1)
    n = len(str2)
    new_list = []
    lcs = [["" for j in range(n + 1)] for i in range(m + 1)]
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if str1[i - 1] == str2[j - 1]:
                lcs[i][j] = lcs[i - 1][j - 1] + str1[i - 1]
            else:
                lcs[i][j] = max(lcs[i - 1][j], lcs[i][j - 1], key=len)
    new_list.append(lcs[i][j])
            

    return new_list#lcs[m][n]

# this function is not being used. Expermiental function to find common substrings. 
def LCS_new(str1, str2):
    m = len(str1)
    n = len(str2)
    lcs = [[0 for j in range(n + 1)] for i in range(m + 1)]
    max_len = 0
    end_index = 0
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if str1[i - 1] == str2[j - 1]:
                lcs[i][j] = lcs[i - 1][j - 1] + 1
                if lcs[i][j] > max_len:
                    max_len = lcs[i][j]
                    end_index = i - 1
            else:
                lcs[i][j] = 0
    return str1[end_index - max_len + 1: end_index + 1]

# this function is not being used. Expermiental function to find common substrings. 
def LCS_ultra(str1, str2):
    m = len(str1)
    n = len(str2)
    lcs = [["" for j in range(n + 1)] for i in range(m + 1)]
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if str1[i - 1] == str2[j - 1]:
                lcs[i][j] = lcs[i - 1][j - 1] + str1[i - 1]
            else:
                lcs[i][j] = max(lcs[i - 1][j], lcs[i][j - 1], key=len)

    # find the indices where the LCS string appears in both input strings
    lcs_str = lcs[m][n]
    i = str1.find(lcs_str)
    j = str2.find(lcs_str)

    # split the two input strings at the LCS indices to get the desired output format
    output = [str1[:i], str1[i:i+len(lcs_str)], str1[i+len(lcs_str):j], str2[j:j+len(lcs_str)], str2[j+len(lcs_str):]]

    return output

# The compare_dict function call this function. this function contains the main logic for comparing two strings. 
def find_common_strings(a, b, min_length):
    new_list = []
    # look for a_chars in b
    #print(f"a: {a}")
    #print(f"b: {b}")
    a_index = 0
    b_index = 0
    substring = ""
    while a_index < len(a):
        while a_index < len(a) and b_index < len(b) and a[a_index] == b[b_index]:
            substring += a[a_index]
            a_index += 1
            b_index += 1
        if len(substring) > 0:
            if len(substring) > min_length:
                #print(a_index, b_index)
                new_list.append(substring)
            substring = ""
        if b_index >= len(b):
            a_index += 1
            b_index = 0
        else:
            b_index += 1
    #print("==========================")
    return new_list

#This function removes duplicates form the main invariant json file. 
def remove_duplicates(input_file, output_file):
    with open(input_file, 'r') as f:
        data = json.load(f)
    
    # create a set to hold all unique values
    unique_values = set()
    
    # loop through each device in the input dictionary
    for device, records in data.items():
        # loop through each record type (A, PTR, SRV) for the device
        for record_type, records_list in records.items():
            # loop through each record in the records list
            for record in records_list:
                # loop through each key-value pair in the record
                for key, value in record.items():
                    # if the key is rrname, rdata, or target
                    if key in ['rrname', 'rdata', 'target']:
                        # create a new list to hold the updated values for this key
                        updated_values = []
                        # loop through each value in the original list for this key
                        for v in value:
                            # if the value is not already in the set of unique values
                            if v not in unique_values:
                                # add it to the set and the updated list
                                unique_values.add(v)
                                updated_values.append(v)
                        # replace the original list with the updated list
                        record[key] = updated_values
    
    # write the updated dictionary to the output file
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=4)
    
    
if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='mDNS fingerprinting')
    #parser.add_argument('--ip', dest='ip',type=str ,help=' Specify IP Address. Format - 192.168.1.x. THIS IS AN OPTIONAL FIELD AND WILL NOT WORK WITH THE VENDOR FLAG.')
    parser.add_argument('--date', dest='date',type=str ,help='Input initial date. Format - YYYYMMDD.')
    parser.add_argument('--day', dest='day', action='store_true',help='Analysis for a day')
    parser.add_argument('--week', dest='week',action='store_true', help='Analysis for a week')
    parser.add_argument('--month', dest='month',action='store_true', help='Analysis for a month. PLease start from the start of the month.') # This feature has not been tested. 
    #parser.add_argument('--vendor', dest='vendor',action='store_true', help='Vendor level analysis for pair of devices that have no unique fingerprints')
    #starttime = time.time()
    args = parser.parse_args()

    # Only Change the below paths accordingly.
    # path_aus  = '/Users/darpan/Desktop/IoTlab_Scripts(Local_machine)/AUSTRALIA_PCAPS'
    path_ind = '/Users/gong/Desktop/IoT_lab/INDIA_PCAPS/'

    '''
    subdirs_aus = sort_pcapdir(path_aus)
    iterate_parse_pcap(subdirs_aus, path_aus, "mdns_aus.json")
    a = output.copy()

    output.clear()
    '''
    subdirs_ind = sort_pcapdir(path_ind)
    iterate_parse_pcap(subdirs_ind, path_ind, "mdns_ind.json")
    b = output.copy()
    #compare_dict(a,b)

# Iterate over each IP address in the dictionaries
    # for ip in a.keys() | b.keys():
    #     result[ip] = {}

    # # Iterate over each record type (PTR, SRV, TXT, A)
    #     for record_type in ["PTR", "SRV", "TXT", "A"]:
    #         if record_type in a[ip] and record_type in b[ip.replace("1.", "2.")]:
    #         # If both dictionaries have this record type for this IP, compare the values
    #             a_values = a[ip][record_type]
    #             b_values = b[ip.replace("1.", "2.")][record_type]
    #             print(a_values)
    #             print(b_values)
    #             quit()
    #         else:
    #             pass

            # Check if the values are equal, otherwise extract the common substring
    #             if a_values == b_values:
    #                 result[ip][record_type] = a_values
    #             else:
    #                 result_values = []
    #                 for a_value, b_value in zip(a_values, b_values):
    #                     if a_value == b_value:
    #                         result_values.append(a_value)
    #                     else:
    #                     # Find the common substring between the two values
    #                         common_substring = os.path.commonprefix([a_value["rrname"], b_value["rrname"]])

    #                     # Split the values based on the common substring and put them in a list
    #                         a_substrings = [a_value["rrname"].split(common_substring), [a_value[key] for key in a_value.keys() if key != "rrname"]]
    #                         b_substrings = [b_value["rrname"].split(common_substring), [b_value[key] for key in b_value.keys() if key != "rrname"]]
    #                         result_substrings = [a_substrings[0] + b_substrings[0][1:], a_substrings[1] + b_substrings[1]]

    #                     # Join the substrings and put the resulting value in the result list
    #                         result_value = {}
    #                         result_value["rrname"] = common_substring + "".join(result_substrings[0])
    #                         for i, key in enumerate(["target", "weight", "port", "priority"]):
    #                             result_value[key] = result_substrings[1][i]
    #                         result_values.append(result_value)

    #                 result[ip][record_type] = result_values
    #         else:
    #         # If one of the dictionaries doesn't have this record type for this IP, just copy the value from the other dictionary
    #             if record_type in a[ip]:
    #                 result[ip][record_type] = a[ip][record_type]
    #             else:
    #                 result[ip][record_type] = b[ip][record_type]

    # print(result)
