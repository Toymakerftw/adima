from scapy.all import *
from collections import defaultdict
import multiprocessing
import sqlite3
import socket
import xgboost as xgb

# Function to calculate average network bandwidth
def calculate_average_bandwidth(packet_count, total_bytes):
    if packet_count == 0:
        return 0
    return total_bytes / packet_count

# Function to detect suspicious devices and high bandwidth usage
def detect_suspicious_devices(pcap_file, time_window, db_path, malicious_ips_file):
    packets = rdpcap(pcap_file)

    devices = defaultdict(int)
    device_bandwidth = defaultdict(int)
    unique_destinations = defaultdict(set)
    malicious_ips = set()

    with open(malicious_ips_file, "r") as f:
        for line in f:
            ip = line.strip()
            malicious_ips.add(ip)

    for packet in packets:
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Detect repeated or unauthorized attempts
            if packet.haslayer(TCP) and packet[TCP].flags & 2 and not packet[TCP].flags & 16:
                devices[src_ip] += 1

            # Detect port scanning
            if packet.haslayer(TCP) and packet[TCP].flags & 2 and not packet[TCP].flags & 16 and not packet[TCP].flags & 1:
                devices[src_ip] += 1

            # Detect brute-force attacks
            if packet.haslayer(TCP) and packet[TCP].flags & 4:
                devices[src_ip] += 1

            # Calculate network bandwidth
            device_bandwidth[src_ip] += len(packet)
            device_bandwidth[dst_ip] += len(packet)

            # Detect devices communicating with multiple unique destinations
            if packet.haslayer(TCP):
                unique_destinations[src_ip].add(dst_ip)

            # Detect devices communicating with known malicious IP addresses
            if src_ip in malicious_ips or dst_ip in malicious_ips:
                devices[src_ip] += 1

    # Insert malicious IPs into the SQLite table
    conn = sqlite3.connect(db_path)
    with conn:
        cursor = conn.cursor()
        for ip in devices.keys():
            cursor.execute("INSERT OR IGNORE INTO mal_node (ip) VALUES (?)", (ip,))

    conn.close()

    # Find nodes with high bandwidth usage and the corresponding domains/URLs
    high_bandwidth_nodes = {}
    for ip, bandwidth in device_bandwidth.items():
        if bandwidth > (2 * calculate_average_bandwidth(sum(device_bandwidth.values()), sum(device_bandwidth.values()))):
            try:
                domain = socket.gethostbyaddr(ip)[0]
            except socket.herror:
                domain = "Unknown"
            high_bandwidth_nodes[ip] = domain

    # Insert high bandwidth nodes into the SQLite table
    conn = sqlite3.connect(db_path)
    with conn:
        cursor = conn.cursor()
        for ip, domain in high_bandwidth_nodes.items():
            cursor.execute("INSERT INTO hiband_node (ip, domain) VALUES (?, ?)", (ip, domain))

    conn.close()

    return devices, device_bandwidth, unique_destinations, high_bandwidth_nodes

# Function to process a time window of pcap file
def process_time_window(pcap_file, time_window, db_path, malicious_ips_file, model):
    devices, device_bandwidth, unique_destinations, _ = detect_suspicious_devices(pcap_file, time_window, db_path, malicious_ips_file)

    # Prepare the data for prediction
    data = []
    for device, bandwidth in device_bandwidth.items():
        features = [bandwidth, devices[device]]
        data.append(features)

    # Perform prediction using the pretrained model
    dmatrix = xgb.DMatrix(data)
    predictions = model.predict(dmatrix)

    # Update the results dictionary with prediction scores
    for i, device in enumerate(device_bandwidth.keys()):
        score = predictions[i]
        device_bandwidth[device] = score

    # Calculate average network bandwidth
    avg_bandwidth = calculate_average_bandwidth(sum(device_bandwidth.values()), sum(device_bandwidth.values()))

    # Detect devices with high network bandwidth
    high_bandwidth_devices = [device for device, bandwidth in device_bandwidth.items() if bandwidth > (2 * avg_bandwidth)]

    results = {
        "repeated_attempts": {device: attempts for device, attempts in devices.items() if attempts > 0},
        "port_scanning": {device: attempts for device, attempts in devices.items() if attempts > 1},
        "brute_force": {device: attempts for device, attempts in devices.items() if attempts > 0},
        "high_bandwidth": {device: bandwidth for device, bandwidth in device_bandwidth.items() if bandwidth > (2 * avg_bandwidth)},
        "multi_destination": {device: destinations for device, destinations in unique_destinations.items() if len(destinations) > 1}
    }

    return results

# Function to read malicious IP addresses from a file
def read_malicious_ips(file_path):
    malicious_ips = set()

    with open(file_path, "r") as f:
        for line in f:
            ip = line.strip()
            malicious_ips.add(ip)

    return malicious_ips

# Run the script
def main():
    pcap_file = "pcap/packets.pcap"
    time_window = 60  # Time window in seconds
    db_path = "triage.db"
    malicious_ips_file = "resources/mal_ip.txt"
    model_file = "pretrained_model.model"  # Path to the pretrained XGBoost model file

    # Create the SQLite connection and table
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS mal_node (ip TEXT)")
    cursor.execute("CREATE TABLE IF NOT EXISTS hiband_node (ip TEXT, domain TEXT)")

    # Load the pretrained XGBoost model
    model = xgb.Booster(model_file=model_file)

    # Split the pcap file into time windows
    packets = rdpcap(pcap_file)
    time_windows = []
    current_window = []
    current_time = packets[0].time

    for packet in packets:
        packet_time = packet.time

        if packet_time - current_time > time_window:
            time_windows.append(current_window)
            current_window = []
            current_time = packet_time

        current_window.append(packet)

    if current_window:
        time_windows.append(current_window)

    # Process each time window using multiprocessing
    pool = multiprocessing.Pool()
    results = pool.starmap(process_time_window, [(pcap_file, time_window, db_path, malicious_ips_file, model) for _ in time_windows])
    pool.close()
    pool.join()

    # Aggregate the results from all time windows
    final_results = {
        "repeated_attempts": defaultdict(int),
        "port_scanning": defaultdict(int),
        "brute_force": defaultdict(int),
        "high_bandwidth": defaultdict(int),
        "multi_destination": defaultdict(set)
    }

    for time_window_result in results:
        for activity_type, devices in time_window_result.items():
            for device, value in devices.items():
                final_results[activity_type][device] += value

    # Print the aggregated results or "No malicious devices found"
    found_malicious_devices = False

    print("Devices with repeated/unauthorized attempts:")
    for device, attempts in final_results["repeated_attempts"].items():
        print(f"Device: {device}, Attempts: {attempts}")
        found_malicious_devices = True

    print("\nDevices conducting port scanning:")
    for device, attempts in final_results["port_scanning"].items():
        print(f"Device: {device}, Attempts: {attempts}")
        found_malicious_devices = True

    print("\nDevices involved in brute-force attacks:")
    for device, attempts in final_results["brute_force"].items():
        print(f"Device: {device}, Attempts: {attempts}")
        found_malicious_devices = True

    print("\nDevices with high network bandwidth:")
    for device, bandwidth in final_results["high_bandwidth"].items():
        print(f"Device: {device}, Bandwidth: {bandwidth} bytes")
        found_malicious_devices = True

    print("\nDevices communicating with multiple unique destinations:")
    for device, destinations in final_results["multi_destination"].items():
        print(f"Device: {device}, Unique Destinations: {', '.join(destinations)}")
        found_malicious_devices = True

    if not found_malicious_devices:
        print("No malicious devices found")

    # Close the SQLite connection
    conn.close()

# Execute the main function
if __name__ == "__main__":
    main()
