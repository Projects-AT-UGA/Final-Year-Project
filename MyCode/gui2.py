import os
import pyshark
import tkinter as tk
from tkinter import ttk
from datetime import datetime

# Device dictionary mapping IPs to device names
device_dictionary = {
    "192.168.2.2": "PixStar_FotoConnect",
    "192.168.2.3": "Google_NestProtect",
    "192.168.2.4": "Samsung_WisenetSmartCam_A1",
    "192.168.2.5": "TP-Link_TapoHomesecurityCamera",
    "192.168.2.6": "Dlink_Omna180CamHD",
    "192.168.2.8": "Sengled_SmartBulbStarterKit",
    "192.168.2.9": "Amazon_EchoDot3rdGeneration",
    "192.168.2.10": "Amazon_EchoDot",
    "192.168.2.11": "Amazon_Echo",
    "192.168.2.12": "Withings_Body+SmartScale",
    "192.168.2.15": "Wansview_WirelessCloudcamera",
    "192.168.2.16": "SmartAtoms_LaMetricTime",
    "192.168.2.17": "Netatmo_SmartHomeWeatherStation",
    "192.168.2.18": "HP_OfficeJetPro6978",
    "192.168.2.19": "TP-Link_TapoMiniSmartWifiSocket1",
    "192.168.2.20": "TP-Link_TapoMiniSmartWifiSocket2",
    "192.168.2.21": "TP-Link_KasaSmartWifiPlugMini1",
    "192.168.2.22": "TP-Link_KasaSmartWifiPlugMini2",
    "192.168.2.23": "Lifx_SmarterLights",
    "192.168.2.24": "TP-Link_KasaSmartWiFiLightBulbMulticolor",
    "192.168.2.25": "Philips_HueBridge",
    "192.168.2.26": "D-Link_FullHDPan&TiltProHDWifiCamera",
    "192.168.2.30": "Meross_SmartWiFiGarageDoorOpener",
    "192.168.2.31": "Yi_1080pHomeCameraAIPlus",
    "192.168.2.32": "iRobot_RoombaRobotVaccum",
    "192.168.2.33": "Reolink_RLC520Camera1",
    "192.168.2.34": "Reolink_RLC520Camera2",
    "192.168.2.35": "Amcrest_SecurityTurretCamera",
    "192.168.2.37": "Wemo_WiFiSmartLightSwitch",
    "192.168.2.38": "Ecobee_Switch+",
    "192.168.2.40": "Blink Sync Module 2",
    "192.168.2.41": "Blink Mini indoor Plug-In HD smart security Camera",
    "192.168.2.42": "Google nest Mini",
    "192.168.2.43": "Insignia_FireTV",
    "192.168.2.44": "Xiaomi_360HomeSecurityCamera2k",
    "192.168.2.47": "TP-Link_KasaSmartLightStrip",
    "192.168.2.48": "Ring_Doorbell4",
    "192.168.2.49": "Ecobee_3liteSmartThermostat",
    "192.168.2.50": "Google_NestThermostat",
    "192.168.2.245": "August Wi-fi Smart Lock"
}


# Function to analyze pcap files
# Updated Function to Analyze PCAP Files
def analyze_pcap_files(folder_path):
    packet_count = {
        ip: {
            "input": 0,
            "output": 0,
            "last_time": None,
            "device_name": device_name,
            "tcp_input": 0,
            "tcp_output": 0,
            "udp_input": 0,
            "udp_output": 0,
            "icmp_input": 0,
            "icmp_output": 0,
            "external_traffic": {}  # Field to track traffic with external IPs
        } for ip, device_name in device_dictionary.items()
    }

    # Iterate through all pcap files in the folder
    for filename in os.listdir(folder_path):
        if filename.endswith(".pcap"):
            cap = pyshark.FileCapture(os.path.join(folder_path, filename))
            for packet in cap:
                try:
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst
                    timestamp = datetime.fromisoformat(packet.sniff_time.isoformat().replace('Z', ''))

                    # Determine protocol type
                    protocol = None
                    if hasattr(packet, 'tcp'):
                        protocol = 'tcp'
                    elif hasattr(packet, 'udp'):
                        protocol = 'udp'
                    elif hasattr(packet, 'icmp'):
                        protocol = 'icmp'

                    # Check if source is internal
                    if src_ip in device_dictionary:
                        packet_count[src_ip]['output'] += 1
                        if protocol == 'tcp':
                            packet_count[src_ip]['tcp_output'] += 1
                        elif protocol == 'udp':
                            packet_count[src_ip]['udp_output'] += 1
                        elif protocol == 'icmp':
                            packet_count[src_ip]['icmp_output'] += 1

                        # Update last time
                        if not packet_count[src_ip]['last_time'] or timestamp > packet_count[src_ip]['last_time']:
                            packet_count[src_ip]['last_time'] = timestamp

                        # External destination traffic
                        if dst_ip not in device_dictionary:
                            if dst_ip not in packet_count[src_ip]['external_traffic']:
                                packet_count[src_ip]['external_traffic'][dst_ip] = {"input": 0, "output": 0}
                            packet_count[src_ip]['external_traffic'][dst_ip]['output'] += 1

                    # Check if destination is internal
                    if dst_ip in device_dictionary:
                        packet_count[dst_ip]['input'] += 1
                        if protocol == 'tcp':
                            packet_count[dst_ip]['tcp_input'] += 1
                        elif protocol == 'udp':
                            packet_count[dst_ip]['udp_input'] += 1
                        elif protocol == 'icmp':
                            packet_count[dst_ip]['icmp_input'] += 1

                        # Update last time
                        if not packet_count[dst_ip]['last_time'] or timestamp > packet_count[dst_ip]['last_time']:
                            packet_count[dst_ip]['last_time'] = timestamp

                        # External source traffic
                        if src_ip not in device_dictionary:
                            if src_ip not in packet_count[dst_ip]['external_traffic']:
                                packet_count[dst_ip]['external_traffic'][src_ip] = {"input": 0, "output": 0}
                            packet_count[dst_ip]['external_traffic'][src_ip]['input'] += 1

                except AttributeError:
                    # Handle cases where packet does not have expected attributes
                    continue
                except ValueError:
                    # Handle invalid timestamp formats
                    print(f"Error parsing timestamp for packet: {packet}")
                    continue

    return packet_count

# Function to format the time difference into human-readable format
def format_time_since_last_packet(last_time):
    if last_time is None:
        return "N/A"

    delta = datetime.now() - last_time
    days, remainder = divmod(delta.total_seconds(), 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)

    parts = []
    if days > 0:
        parts.append(f"{int(days)} days")
    if hours > 0:
        parts.append(f"{int(hours)} hours")
    if minutes > 0:
        parts.append(f"{int(minutes)} minutes")
    if seconds > 0:
        parts.append(f"{int(seconds)} seconds")

    return ", ".join(parts) if parts else "Just now"

from tkinter import ttk
import tkinter as tk

def create_gui(packet_count):
    def update_treeview_with_filters(packet_count, include_tcp, include_udp, include_icmp):
        # Clear current data in the treeview
        for item in tree.get_children():
            tree.delete(item)

        # Recalculate and display the filtered data
        for ip, data in packet_count.items():
            input_packets = 0
            output_packets = 0

            # Add counts based on protocol inclusion
            if include_tcp:
                input_packets += data['tcp_input']
                output_packets += data['tcp_output']
            if include_udp:
                input_packets += data['udp_input']
                output_packets += data['udp_output']
            if include_icmp:
                input_packets += data['icmp_input']
                output_packets += data['icmp_output']

            last_time = data['last_time'].strftime('%Y-%m-%d %H:%M:%S') if data['last_time'] else "N/A"
            time_since_last_packet = format_time_since_last_packet(data['last_time'])
            tree.insert("", "end", values=(data['device_name'], ip,input_packets, output_packets, last_time, time_since_last_packet))

    def on_checkbox_change():
        # Get the state of each checkbox
        include_tcp = tcp_checkbox_var.get()
        include_udp = udp_checkbox_var.get()
        include_icmp = icmp_checkbox_var.get()

        # Update treeview with selected filters
        update_treeview_with_filters(packet_count, include_tcp, include_udp, include_icmp)

    def populate_external_traffic_tree(packet_count):
        # Clear current data in the external traffic treeview
        for item in external_traffic_tree.get_children():
            external_traffic_tree.delete(item)

        # Populate the treeview with all IPs and their packet counts
        for ip, data in packet_count.items():
            external_traffic_tree.insert("", "end", values=(data['device_name'],ip, data['input'], data['output']))

    root = tk.Tk()
    root.title("Packet Analysis")

    # Create a notebook to hold multiple tabs
    notebook = ttk.Notebook(root)
    notebook.pack(fill=tk.BOTH, expand=True)

    # Tab 1: Device traffic with filters
    tab1 = ttk.Frame(notebook)
    notebook.add(tab1, text="Device Traffic")

    checkbox_frame = tk.Frame(tab1)
    checkbox_frame.pack(fill=tk.X, padx=10, pady=5)

    tcp_checkbox_var = tk.BooleanVar(value=True)
    udp_checkbox_var = tk.BooleanVar(value=True)
    icmp_checkbox_var = tk.BooleanVar(value=True)

    tcp_checkbox = tk.Checkbutton(checkbox_frame, text="Include TCP", variable=tcp_checkbox_var, command=on_checkbox_change)
    udp_checkbox = tk.Checkbutton(checkbox_frame, text="Include UDP", variable=udp_checkbox_var, command=on_checkbox_change)
    icmp_checkbox = tk.Checkbutton(checkbox_frame, text="Include ICMP", variable=icmp_checkbox_var, command=on_checkbox_change)

    tcp_checkbox.pack(side=tk.LEFT, padx=5)
    udp_checkbox.pack(side=tk.LEFT, padx=5)
    icmp_checkbox.pack(side=tk.LEFT, padx=5)

    frame = tk.Frame(tab1)
    frame.pack(fill=tk.BOTH, expand=True)

    scrollbar = tk.Scrollbar(frame)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    tree = ttk.Treeview(frame, columns=("Device","IP Address", "Input Packets", "Output Packets", "Last Packet Time", "Time Since Last Packet"), show='headings', yscrollcommand=scrollbar.set)
    tree.pack(fill=tk.BOTH, expand=True)
    scrollbar.config(command=tree.yview)

    for col in ["Device", "IP Address","Input Packets", "Output Packets", "Last Packet Time", "Time Since Last Packet"]:
        tree.heading(col, text=col, command=lambda _col=col: sort_column(tree, _col))

    update_treeview_with_filters(packet_count, True, True, True)

    # Tab 2: External traffic overview
    tab2 = ttk.Frame(notebook)
    notebook.add(tab2, text="External Traffic")

    ext_frame = tk.Frame(tab2)
    ext_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    ext_scrollbar = tk.Scrollbar(ext_frame)
    ext_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    external_traffic_tree = ttk.Treeview(ext_frame, columns=("Device","IP Address", "Input Packets", "Output Packets"), show='headings', yscrollcommand=ext_scrollbar.set)
    external_traffic_tree.pack(fill=tk.BOTH, expand=True)
    ext_scrollbar.config(command=external_traffic_tree.yview)
    external_traffic_tree.heading("Device", text="Device")
    external_traffic_tree.heading("IP Address", text="IP Address")
    external_traffic_tree.heading("Input Packets", text="Input Packets")
    external_traffic_tree.heading("Output Packets", text="Output Packets")

    # Populate the external traffic treeview with all IP addresses
    populate_external_traffic_tree(packet_count)

    root.mainloop()


sort_order = {"Device": True, "Input Packets": True, "Output Packets": True, "Last Packet Time": True, "Time Since Last Packet": True}

def sort_column(tree, col):
    global sort_order
    data = [(tree.item(child)['values'], child) for child in tree.get_children()]
    idx = list(tree["columns"]).index(col)
    data.sort(key=lambda x: x[0][idx], reverse=not sort_order[col])
    sort_order[col] = not sort_order[col]

    for child in tree.get_children():
        tree.delete(child)
    for item in data:
        tree.insert("", "end", values=item[0])






# # Function to sort the treeview
# sort_order = {  # To keep track of sort order for each column
#     "Device": True,
#     "Input Packets": True,
#     "Output Packets": True,
#     "Last Packet Time": True,
#     "Time Since Last Packet": True
# }

# def sort_column(tree, col):
#     global sort_order
#     # Sort the data in the treeview
#     data = [(tree.item(child)['values'], child) for child in tree.get_children()]

#     # Determine the current sort order
#     sort_order[col] = not sort_order[col]
#     reverse = not sort_order[col]  # Reverse sort if it's now ascending

#     # Sort data
#     data.sort(key=lambda x: x[0][tree['columns'].index(col)], reverse=reverse)

#     # Clear the treeview and reinsert sorted data
#     for child in tree.get_children():
#         tree.delete(child)

#     for item in data:
#         tree.insert("", "end", values=item[0])

# Main execution
if __name__ == "__main__":
    folder_path = "INDIA"  # Replace with the path to your folder containing pcap files
    packet_count = analyze_pcap_files(folder_path)
    
    for x,y in packet_count.items():
        print(x,y)

    create_gui(packet_count)

#filter by ip address of device and tcp and icmp and udp specific ip address
#what is destinatio of out packets
#filter with check box show 
#external ip adddress only
#web interface
