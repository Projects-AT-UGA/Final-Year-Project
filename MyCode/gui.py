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
def analyze_pcap_files(folder_path):
    packet_count = {ip: {"input": 0, "output": 0, "last_time": None, "device_name": device_name} for ip, device_name in device_dictionary.items()}

    # Iterate through all pcap files in the folder
    for filename in os.listdir(folder_path):
        if filename.endswith(".pcap"):
            cap = pyshark.FileCapture(os.path.join(folder_path, filename))
            for packet in cap:
                try:
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst
                    timestamp = datetime.fromisoformat(packet.sniff_time.isoformat().replace('Z', ''))

                    # Check if the packet's source IP is in the device dictionary
                    if src_ip in device_dictionary:
                        packet_count[src_ip]['output'] += 1
                        if (packet_count[src_ip]['last_time'] is None) or (timestamp > packet_count[src_ip]['last_time']):
                            packet_count[src_ip]['last_time'] = timestamp

                    # Check if the packet's destination IP is in the device dictionary
                    if dst_ip in device_dictionary:
                        packet_count[dst_ip]['input'] += 1
                        if (packet_count[dst_ip]['last_time'] is None) or (timestamp > packet_count[dst_ip]['last_time']):
                            packet_count[dst_ip]['last_time'] = timestamp
                except AttributeError:
                    # Handle cases where the packet does not have the expected attributes
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

# Function to create the GUI
def create_gui(packet_count):
    root = tk.Tk()
    root.title("Packet Analysis")
    
    # Create a frame for the treeview
    frame = tk.Frame(root)
    frame.pack(fill=tk.BOTH, expand=True)

    # Create a scrollbar
    scrollbar = tk.Scrollbar(frame)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    # Create the treeview
    tree = ttk.Treeview(frame, columns=("Device", "Input Packets", "Output Packets", "Last Packet Time", "Time Since Last Packet"), show='headings', yscrollcommand=scrollbar.set)
    tree.pack(fill=tk.BOTH, expand=True)

    # Configure scrollbar
    scrollbar.config(command=tree.yview)

    # Define headings
    for col in ["Device", "Input Packets", "Output Packets", "Last Packet Time", "Time Since Last Packet"]:
        tree.heading(col, text=col, command=lambda _col=col: sort_column(tree, _col))

    # Insert data into the treeview
    for ip, data in packet_count.items():
        last_time = data['last_time'].strftime('%Y-%m-%d %H:%M:%S') if data['last_time'] else "N/A"
        time_since_last_packet = format_time_since_last_packet(data['last_time'])
        tree.insert("", "end", values=(data['device_name'], data['input'], data['output'], last_time, time_since_last_packet))

    # Resize handling
    def resize_tree(event):
        for col in tree["columns"]:
            tree.column(col, width=tk.WINFO_WIDTH)

    root.bind("<Configure>", resize_tree)

    root.mainloop()

# Function to sort the treeview
sort_order = {  # To keep track of sort order for each column
    "Device": True,
    "Input Packets": True,
    "Output Packets": True,
    "Last Packet Time": True,
    "Time Since Last Packet": True
}

def sort_column(tree, col):
    global sort_order
    # Sort the data in the treeview
    data = [(tree.item(child)['values'], child) for child in tree.get_children()]

    # Determine the current sort order
    sort_order[col] = not sort_order[col]
    reverse = not sort_order[col]  # Reverse sort if it's now ascending

    # Sort data
    data.sort(key=lambda x: x[0][tree['columns'].index(col)], reverse=reverse)

    # Clear the treeview and reinsert sorted data
    for child in tree.get_children():
        tree.delete(child)

    for item in data:
        tree.insert("", "end", values=item[0])

# Main execution
if __name__ == "__main__":
    folder_path = "INDIA"  # Replace with the path to your folder containing pcap files
    packet_count = analyze_pcap_files(folder_path)
    create_gui(packet_count)

#filter with check box show and tcp and icmp and udp specific ip address
#external ip adddress only
#what is destinatio of out packets
#filter by ip address of device 
#web interface
