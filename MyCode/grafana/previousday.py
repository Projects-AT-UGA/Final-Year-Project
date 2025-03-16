import os
import scapy.all as scapy
import mysql.connector
from datetime import datetime, timedelta

# Device dictionary (you can keep the same as before)
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
    "192.168.2.245": "August Wi-fi Smart Lock",
}




db_config = {
    'host': 'localhost',
    'port': 3307,
    'user': 'root',
    'password': 'Iotlab@2025',  # Replace with your MySQL password
    'database': 'main'  # Database name
}


# Function to connect to MySQL database
def connect_db():
    connection = mysql.connector.connect(**db_config)
    return connection

# Function to create the combined device_info table and device_status table if they don't exist
def create_tables_if_not_exists():
    connection = connect_db()
    cursor = connection.cursor()

    create_device_info_table = """
    CREATE TABLE IF NOT EXISTS device_info (
        id INT AUTO_INCREMENT PRIMARY KEY,
        ip_address VARCHAR(15),
        device_name VARCHAR(255),
        date DATE,
        udp_bytes_sent BIGINT,
        udp_bytes_received BIGINT,
        tcp_bytes_sent BIGINT,
        tcp_bytes_received BIGINT,
        icmp_bytes_sent BIGINT,
        icmp_bytes_received BIGINT,
        UNIQUE (ip_address, date)
    );
    """

    create_device_status_table = """
    CREATE TABLE IF NOT EXISTS device_status (
        id INT AUTO_INCREMENT PRIMARY KEY,
        ip_address VARCHAR(15),
        device_name VARCHAR(255),
        last_seen_time DATETIME,
        previous_seen_time VARCHAR(255)
    );
    """

    cursor.execute(create_device_info_table)
    cursor.execute(create_device_status_table)
    connection.commit()
    cursor.close()
    connection.close()

# Function to insert or update device info (ensuring ip_address and date combination is unique)
def insert_or_update_device_info(ip, device_name, date, udp_sent, udp_received, tcp_sent, tcp_received, icmp_sent, icmp_received):
    connection = connect_db()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO device_info (ip_address, device_name, date, udp_bytes_sent, udp_bytes_received, tcp_bytes_sent, tcp_bytes_received, icmp_bytes_sent, icmp_bytes_received)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
        udp_bytes_sent = udp_bytes_sent + VALUES(udp_bytes_sent),
        udp_bytes_received = udp_bytes_received + VALUES(udp_bytes_received),
        tcp_bytes_sent = tcp_bytes_sent + VALUES(tcp_bytes_sent),
        tcp_bytes_received = tcp_bytes_received + VALUES(tcp_bytes_received),
        icmp_bytes_sent = icmp_bytes_sent + VALUES(icmp_bytes_sent),
        icmp_bytes_received = icmp_bytes_received + VALUES(icmp_bytes_received)
    """, (ip, device_name, date, udp_sent, udp_received, tcp_sent, tcp_received, icmp_sent, icmp_received))

    connection.commit()
    cursor.close()
    connection.close()

# Function to calculate relative time difference
def get_relative_time(last_seen_time):
    current_time = datetime.now()
    diff = current_time - last_seen_time

    if diff < timedelta(minutes=1):
        return "Just now"
    elif diff < timedelta(hours=1):
        return f"{int(diff.total_seconds() // 60)} minutes ago"
    elif diff < timedelta(days=1):
        return f"{int(diff.total_seconds() // 3600)} hours ago"
    else:
        return f"{int(diff.total_seconds() // 86400)} days ago"

temp=set()
# Function to process pcap files and extract

def process_pcap_files(folder_path):
    traffic_data = {}
    active_devices = {}

    for root, _, files in os.walk(folder_path):
        for filename in files:
            if filename.endswith(".pcap"):
                file_path = os.path.join(root, filename)
                packets = scapy.rdpcap(file_path)

                temp_traffic_data = {} #local traffic data for each pcap
                temp_active_devices = {} #local active devices for each pcap

                for packet in packets:
                    if packet.haslayer(scapy.IP):
                        ip = packet[scapy.IP].src
                        dst_ip = packet[scapy.IP].dst

                        for ip_addr in [ip, dst_ip]:

                            if ip_addr in device_dictionary:
                                packet_time = datetime.fromtimestamp(float(packet.time))
                                bytes_len = len(packet)
                                if ip_addr not in temp_traffic_data:
                                    temp_traffic_data[ip_addr] = {}

                                date_key = packet_time.date()
                                if date_key not in temp_traffic_data[ip_addr]:
                                    temp_traffic_data[ip_addr][date_key] = {'udp_sent': 0, 'udp_received': 0, 'tcp_sent': 0, 'tcp_received': 0, 'icmp_sent': 0, 'icmp_received': 0}

                                if packet.haslayer(scapy.TCP):
                                    if ip_addr == packet[scapy.IP].src:
                                        temp_traffic_data[ip_addr][date_key]['tcp_sent'] += bytes_len
                                    elif ip_addr == packet[scapy.IP].dst:
                                        temp_traffic_data[ip_addr][date_key]['tcp_received'] += bytes_len
                                elif packet.haslayer(scapy.UDP):
                                    if ip_addr == packet[scapy.IP].src:
                                        temp_traffic_data[ip_addr][date_key]['udp_sent'] += bytes_len
                                    elif ip_addr == packet[scapy.IP].dst:
                                        temp_traffic_data[ip_addr][date_key]['udp_received'] += bytes_len
                                elif packet.haslayer(scapy.ICMP):
                                    if ip_addr == packet[scapy.IP].src:
                                        temp_traffic_data[ip_addr][date_key]['icmp_sent'] += bytes_len
                                    elif ip_addr == packet[scapy.IP].dst:
                                        temp_traffic_data[ip_addr][date_key]['icmp_received'] += bytes_len

                                if ip_addr not in temp_active_devices or packet_time > temp_active_devices[ip_addr]:
                                    temp_active_devices[ip_addr] = packet_time
                                temp.add(packet[scapy.IP].dst)

                #insert data after each pcap file.
                for ip, date_data in temp_traffic_data.items():
                    device_name = device_dictionary[ip]
                    for date, data in date_data.items():
                        insert_or_update_device_info(ip, device_name, date, data['udp_sent'], data['udp_received'], data['tcp_sent'], data['tcp_received'], data['icmp_sent'], data['icmp_received'])

                if temp_active_devices:
                    update_device_status_for_all_devices(temp_active_devices)
                else:
                    print(f"No devices found in {filename}.")
                print(f"Processed and inserted data from {filename}")

    return traffic_data, active_devices

# Function to update device status and store the relative time in previous_seen_time
def update_device_status(ip, device_name, current_time, last_seen_time):
    connection = connect_db()
    cursor = connection.cursor()

    # Check if the device already exists in the database
    cursor.execute("SELECT id, last_seen_time FROM device_status WHERE ip_address = %s", (ip,))
    existing_device = cursor.fetchone()

    if existing_device:
        device_id, previous_seen_time_db = existing_device
        # Calculate the relative time difference from the last seen time
        previous_seen_time = get_relative_time(last_seen_time)
        cursor.execute(
            "UPDATE device_status SET previous_seen_time = %s, last_seen_time = %s WHERE id = %s",
            (previous_seen_time, last_seen_time, device_id)
        )
    else:
        # If device doesn't exist, there is no previous seen time
        previous_seen_time = get_relative_time(last_seen_time)
        cursor.execute(
            "INSERT INTO device_status (ip_address, device_name, last_seen_time, previous_seen_time) VALUES (%s, %s, %s, %s)",
            (ip, device_name, last_seen_time, previous_seen_time)
        )

    connection.commit()
    cursor.close()
    connection.close()

# Function to update device status for all devices
def update_device_status_for_all_devices(active_devices):
    for ip, last_seen_time in active_devices.items():
        device_name = device_dictionary.get(ip, "Unknown Device")
        update_device_status(ip, device_name, last_seen_time, last_seen_time)

    print(f"Updated {len(active_devices)} device(s) status.")

# Main function
def main():
    create_tables_if_not_exists()
    folder_path = '/data/UGAIoTpcaps/INDIA_PCAPS'  # Adjust as needed
    traffic_data, active_devices = process_pcap_files(folder_path)

    print("Updated device traffic data with one-to-many relationship, including subfolders.")

if __name__ == "__main__":
    main()