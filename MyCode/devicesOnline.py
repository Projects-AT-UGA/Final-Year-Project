from scapy.all import rdpcap, IP

# Load the pcap file
pcap_file = "AUSTRALIApi_20221201_22_05_01_UTC.pcap"  # Replace with your actual file path
packets = rdpcap(pcap_file)

# Your device dictionary
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
    "192.168.2.43": "Insignia_FireTV",
    "192.168.2.44": "Xiaomi_360HomeSecurityCamera2k",
    "192.168.2.47": "TP-Link_KasaSmartLightStrip",
    "192.168.2.48": "Ring_Doorbell4",
    "192.168.2.49": "Ecobee_3liteSmartThermostat",
    "192.168.2.50": "Google_NestThermostat"
}


# Function to identify devices from IPs found in the pcap
def identify_devices(packets, device_dict):
    identified_devices = set()

    for pkt in packets:
        # print(pkt)
        if IP in pkt:  # Check if the packet contains an IP layer
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            # Check if the source IP or destination IP is in the device dictionary
            if src_ip in device_dict:
                print()
                identified_devices.add((src_ip, device_dict[src_ip]))
            if dst_ip in device_dict:
                identified_devices.add((dst_ip, device_dict[dst_ip]))

    return identified_devices

# Get the identified devices
devices_in_pcap = identify_devices(packets, device_dictionary)


# print(devices_in_pcap)
# Print the identified devices
for ip, device in devices_in_pcap:
    print(f"IP: {ip} -> Device: {device}")

#pick a host device (192.1.1.3) and find dns message in it and create a pcap file and device names