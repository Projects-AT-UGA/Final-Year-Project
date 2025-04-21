import os
import scapy.all as scapy
import mysql.connector
from datetime import datetime, timedelta, date

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
    "192.168.1.24": "tplink kasa smart wifi light bulb",
    "192.168.1.8": "Philips hue bridge",
    "192.168.1.8": "singled element classic smart bulb starter kit",
    "192.168.1.2": "pixstar Foto connect xd wifi 10:n",
    "192.168.1.39": "Logitech harmony hub",
    "192.168.1.43": "insignia FireTv",
    "192.168.1.4": "Samsung klisenet smart cam A1",
    "192.168.1.33": "Reolink RLC-520",
    "192.168.1.5": "Tp-link Home security wifi camera",
    "192.168.1.34": "Reolink RLC-520 (second device)",
    "192.168.1.15": "Wansview wireless cloud ptz ip camera Q5 1080p",
    "192.168.1.35": "amcrest security turrent camera",
    "192.168.1.6": "D-link omna 180cam hd",
    "192.168.1.36": "microseven camera",
    "192.168.1.26": "D-link full hd pan & tilt pro hd wifi camera",
    "192.168.1.31": "yi 1080p home camera AI plus",
    "192.168.1.44": "Xiami 360 home security camera 2k",
    "192.168.1.42": "google nest mini",
    "192.168.1.11": "amazon echo",
    "192.168.1.9": "amazon echo dot 3rd gen",
    "192.168.1.10": "amazon echo dot",
    "192.168.1.16": "la metric time",
    "192.168.1.17": "Netatmo smart home weather station",
    "192.168.1.19": "tp-link tapo mini smart wifi socket (first device)",
    "192.168.1.20": "tp-link tapo mini smart wifi socket (second device)",
    "192.168.1.21": "kasa smart wifi plug mini (first device)",
    "192.168.1.22": "kasa smart wifi plug mini (second device)",
    "192.168.1.40": "august wifi smart lock",
    "192.168.1.27": "switchbot hub mini",
    "192.168.1.47": "tp-link kasa smart light strip",
    "192.168.1.30": "meross smart wifi garage door opener",
    "192.168.1.37": "Belkin wemo wifi smart dimmer",
    "192.168.1.38": "echobee switch+",
    "192.168.1.48": "ring doorbell 4",
    "192.168.1.49": "ecobee 3lite smart thermostat",
    "192.168.1.50": "google nest thermostat",
    "192.168.1.28": "Samsung smarthtings hub",
    "192.168.1.51": "Honeywell color smart thermostat",
    "192.168.1.18": "hp officer jet pro 6978",
    "192.168.1.12": "wifithings body + smart scale",
    "192.168.1.32": "iRobot romba robot vaccum"
}

db_config = {
    'host': 'localhost',
    'port': 3307,
    'user': 'root',
    'password': 'Iotlab@2025',
    'database': 'main'
}

def connect_db():
    return mysql.connector.connect(**db_config)

def create_tables_if_not_exists():
    connection = connect_db()
    cursor = connection.cursor()
    cursor.execute("""
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
            dns_queries BIGINT,
            distinct_dns_queries BIGINT,
            UNIQUE (ip_address, date)
        );
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS device_status (
            id INT AUTO_INCREMENT PRIMARY KEY,
            ip_address VARCHAR(15),
            device_name VARCHAR(255),
            last_seen_time DATETIME,
            previous_seen_time VARCHAR(255)
        );
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS dns_queries_info (
            id INT AUTO_INCREMENT PRIMARY KEY,
            ip_address VARCHAR(15),
            domain_name VARCHAR(255),
            query_count INT,
            query_date DATE,
            UNIQUE (ip_address, domain_name, query_date)
        );
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS destination_traffic (
            id INT AUTO_INCREMENT PRIMARY KEY,
            src_ip VARCHAR(15),
            dest_ip VARCHAR(15),
            date DATE,
            tcp_bytes_sent BIGINT,
            tcp_bytes_received BIGINT,
            udp_bytes_sent BIGINT,
            udp_bytes_received BIGINT,
            UNIQUE (src_ip, dest_ip, date)
        );
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS processed_pcaps (
            id INT AUTO_INCREMENT PRIMARY KEY,
            file_path VARCHAR(255) UNIQUE,
            processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    connection.commit()
    cursor.close()
    connection.close()

def is_pcap_processed(file_path):
    connection = connect_db()
    cursor = connection.cursor()
    cursor.execute("SELECT id FROM processed_pcaps WHERE file_path = %s", (file_path,))
    result = cursor.fetchone()
    cursor.close()
    connection.close()
    return result is not None

def mark_pcap_as_processed(file_path):
    connection = connect_db()
    cursor = connection.cursor()
    cursor.execute("INSERT INTO processed_pcaps (file_path) VALUES (%s)", (file_path,))
    connection.commit()
    cursor.close()
    connection.close()

def insert_or_update_device_info(ip, device_name, date, udp_sent, udp_received, tcp_sent, tcp_received, icmp_sent, icmp_received, dns_queries, distinct_dns_queries):
    connection = connect_db()
    cursor = connection.cursor()
    cursor.execute("""
        INSERT INTO device_info (ip_address, device_name, date, udp_bytes_sent, udp_bytes_received, tcp_bytes_sent, tcp_bytes_received, icmp_bytes_sent, icmp_bytes_received, dns_queries, distinct_dns_queries)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
        udp_bytes_sent = udp_bytes_sent + VALUES(udp_bytes_sent),
        udp_bytes_received = udp_bytes_received + VALUES(udp_bytes_received),
        tcp_bytes_sent = tcp_bytes_sent + VALUES(tcp_bytes_sent),
        tcp_bytes_received = tcp_bytes_received + VALUES(tcp_bytes_received),
        icmp_bytes_sent = icmp_bytes_sent + VALUES(icmp_bytes_sent),
        icmp_bytes_received = icmp_bytes_received + VALUES(icmp_bytes_received),
        dns_queries = dns_queries + VALUES(dns_queries),
        distinct_dns_queries = distinct_dns_queries + VALUES(distinct_dns_queries)
    """, (ip, device_name, date, udp_sent, udp_received, tcp_sent, tcp_received, icmp_sent, icmp_received, dns_queries, distinct_dns_queries))
    connection.commit()
    cursor.close()
    connection.close()

def insert_or_update_dns_query(ip_address, domain_name, timestamp):
    connection = connect_db()
    cursor = connection.cursor()
    query_date = timestamp.date()
    cursor.execute("""
        INSERT INTO dns_queries_info (ip_address, domain_name, query_count, query_date)
        VALUES (%s, %s, 1, %s)
        ON DUPLICATE KEY UPDATE
        query_count = query_count + 1
    """, (ip_address, domain_name, query_date))
    connection.commit()
    cursor.close()
    connection.close()

def insert_or_update_destination_traffic(src_ip, dest_ip, date, tcp_sent, tcp_received, udp_sent, udp_received):
    connection = connect_db()
    cursor = connection.cursor()
    cursor.execute("""
        INSERT INTO destination_traffic (src_ip, dest_ip, date, tcp_bytes_sent, tcp_bytes_received, udp_bytes_sent, udp_bytes_received)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
        tcp_bytes_sent = tcp_bytes_sent + VALUES(tcp_bytes_sent),
        tcp_bytes_received = tcp_bytes_received + VALUES(tcp_bytes_received),
        udp_bytes_sent = udp_bytes_sent + VALUES(udp_bytes_sent),
        udp_bytes_received = udp_bytes_received + VALUES(udp_bytes_received)
    """, (src_ip, dest_ip, date, tcp_sent, tcp_received, udp_sent, udp_received))
    connection.commit()
    cursor.close()
    connection.close()

def get_relative_time(last_seen_time):
    diff = datetime.now() - last_seen_time
    if diff < timedelta(minutes=1):
        return "Just now"
    elif diff < timedelta(hours=1):
        return f"{int(diff.total_seconds() // 60)} minutes ago"
    elif diff < timedelta(days=1):
        return f"{int(diff.total_seconds() // 3600)} hours ago"
    else:
        return f"{int(diff.total_seconds() // 86400)} days ago"


def process_pcap_files(folder_path):
    for root, _, files in os.walk(folder_path):
        for filename in files:
            if filename.endswith(".pcap"):
                file_path = os.path.join(root, filename)
                if is_pcap_processed(file_path):
                    print(f"Skipping already processed file: {filename}")
                    continue
                try:
                    packets = scapy.rdpcap(file_path)
                except Exception as e:
                    print(f"Error reading {file_path}: {e}")
                    continue

                temp_traffic_data = {}
                temp_active_devices = {}
                for packet in packets:
                    packet_time = datetime.fromtimestamp(float(packet.time))
                    if packet.haslayer(scapy.UDP) and packet[scapy.UDP].dport == 5353: #check for mDNS
                        if packet.haslayer(scapy.DNS) and packet[scapy.DNS].qr == 0 and packet.haslayer(scapy.IP) and packet[scapy.DNSQR]:
                            ip = packet[scapy.IP].src
                            if ip in device_dictionary:
                                bytes_len = len(packet)
                                if ip not in temp_traffic_data:
                                    temp_traffic_data[ip] = {}
                                date_key = packet_time.date()
                                if date_key not in temp_traffic_data[ip]:
                                    temp_traffic_data[ip][date_key] = {'udp_sent': 0, 'udp_received': 0, 'tcp_sent': 0, 'tcp_received': 0, 'icmp_sent'
                                                                        : 0, 'icmp_received': 0, 'dns_queries': 0, 'distinct_dns_queries': set()}
                                temp_traffic_data[ip][date_key]['dns_queries'] += 1
                                dns_query_name = packet[scapy.DNSQR].qname.decode('utf-8', errors='ignore')
                                temp_traffic_data[ip][date_key]['distinct_dns_queries'].add(dns_query_name)
                                insert_or_update_dns_query(ip, dns_query_name, packet_time)
                                if ip not in temp_active_devices or packet_time > temp_active_devices[ip]:
                                    temp_active_devices[ip] = packet_time
                    elif packet.haslayer(scapy.IP): #regular IP traffic
                        ip = packet[scapy.IP].src
                        dst_ip = packet[scapy.IP].dst
                        bytes_len = len(packet)
                        packet_date = packet_time.date()

                        # Track destination traffic
                        if ip in device_dictionary:
                            if dst_ip not in device_dictionary: # Only track traffic to external IPs
                                tcp_sent = bytes_len if packet.haslayer(scapy.TCP) else 0
                                tcp_received = 0
                                udp_sent = bytes_len if packet.haslayer(scapy.UDP) else 0
                                udp_received = 0
                                insert_or_update_destination_traffic(ip, dst_ip, packet_date, tcp_sent, tcp_received, udp_sent, udp_received)
                        if dst_ip in device_dictionary:
                            if ip not in device_dictionary: # Only track traffic from external IPs
                                tcp_received = bytes_len if packet.haslayer(scapy.TCP) else 0
                                tcp_sent = 0
                                udp_received = bytes_len if packet.haslayer(scapy.UDP) else 0
                                udp_sent = 0
                                insert_or_update_destination_traffic(ip, dst_ip, packet_date, tcp_sent, tcp_received, udp_sent, udp_received)

                        for ip_addr in [ip, dst_ip]:
                            if ip_addr in device_dictionary:
                                if ip_addr not in temp_traffic_data:
                                    temp_traffic_data[ip_addr] = {}
                                date_key = packet_time.date()
                                if date_key not in temp_traffic_data[ip_addr]:
                                    temp_traffic_data[ip_addr][date_key] = {'udp_sent': 0, 'udp_received': 0, 'tcp_sent': 0, 'tcp_received': 0, 'icmp_'
                                                                        'sent': 0, 'icmp_received': 0, 'dns_queries': 0, 'distinct_dns_queries': set()}
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
                                elif packet.haslayer(scapy.DNS) and packet[scapy.DNS].qr == 0 and packet[scapy.DNSQR]:
                                    temp_traffic_data[ip_addr][date_key]['dns_queries'] += 1
                                    dns_query_name = packet[scapy.DNSQR].qname.decode('utf-8', errors='ignore')
                                    temp_traffic_data[ip_addr][date_key]['distinct_dns_queries'].add(dns_query_name)
                                    insert_or_update_dns_query(ip_addr, dns_query_name, packet_time)
                                if ip_addr not in temp_active_devices or packet_time > temp_active_devices[ip_addr]:
                                    temp_active_devices[ip_addr] = packet_time

                for ip, date_data in temp_traffic_data.items():
                    device_name = device_dictionary[ip]
                    for date, data in date_data.items():
                        insert_or_update_device_info(ip, device_name, date, data['udp_sent'], data['udp_received'], data['tcp_sent'], data['tcp_received'], data['icmp_sent'], data['icmp_received'], data['dns_queries'], len(data['distinct_dns_queries']))
                if temp_active_devices:
                    update_device_status_for_all_devices(temp_active_devices)
                else:
                    print(f"No devices found in {filename}.")
                print(f"Processed and inserted data from {filename}")
                mark_pcap_as_processed(file_path)

def update_device_status(ip, device_name, current_time, last_seen_time):
    connection = connect_db()
    cursor = connection.cursor()
    cursor.execute("SELECT id, last_seen_time FROM device_status WHERE ip_address = %s", (ip,))
    existing_device = cursor.fetchone()
    if existing_device:
        device_id, previous_seen_time_db = existing_device
        previous_seen_time = get_relative_time(previous_seen_time_db)
        cursor.execute("UPDATE device_status SET previous_seen_time = %s, last_seen_time = %s WHERE id = %s", (previous_seen_time, last_seen_time, device_id))
    else:
        previous_seen_time = get_relative_time(last_seen_time)
        cursor.execute("INSERT INTO device_status (ip_address, device_name, last_seen_time, previous_seen_time) VALUES (%s, %s, %s, %s)", (ip, device_name, last_seen_time, previous_seen_time))
    connection.commit()
    cursor.close()
    connection.close()

def update_device_status_for_all_devices(active_devices):
    for ip, last_seen_time in active_devices.items():
        device_name = device_dictionary.get(ip, "Unknown Device")
        update_device_status(ip, device_name, datetime.now(), last_seen_time)
    print(f"Updated {len(active_devices)} device(s) status.")

def main():
    create_tables_if_not_exists()
    #folder_path = '/data/UGAIoTpcaps/INDIA_PCAPS'
    #folder_path="/home/vishal1/pcaps"
    folder_path="/home/vishal1/IndiaPcaps"
    process_pcap_files(folder_path)
    print("Updated device traffic data, destination traffic data, DNS query information, and device status, including subfolders.")

if __name__ == "__main__":
    main()
