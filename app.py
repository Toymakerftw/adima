from scapy.all import *
from collections import defaultdict
import multiprocessing
import sqlite3

# Function to calculate average network bandwidth
def calculate_average_bandwidth(packet_count, total_bytes):
    if packet_count == 0:
        return 0
    return total_bytes / packet_count

# Function to detect suspicious devices
def detect_suspicious_devices(pcap_file, time_window):
    packets = rdpcap(pcap_file)

    devices = defaultdict(int)
    device_bandwidth = defaultdict(int)
    unique_destinations = defaultdict(set)
    malicious_ips = {"10.0.0.1", "192.168.1.100"}  # Example list of known malicious IP addresses

    # Create a new SQLite connection for each time window
    conn = sqlite3.connect('triage.db')

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
            cursor = conn.cursor()
            cursor.execute("INSERT OR IGNORE INTO mal_node (ip) VALUES (?)", (src_ip,))
            cursor.execute("INSERT OR IGNORE INTO mal_node (ip) VALUES (?)", (dst_ip,))
            conn.commit()

    # Close the SQLite connection
    conn.close()

    return devices, device_bandwidth, unique_destinations

# Function to process a time window of pcap file
def process_time_window(pcap_file, time_window):
    devices, device_bandwidth, unique_destinations = detect_suspicious_devices(pcap_file, time_window)

    # Calculate average network bandwidth
    avg_bandwidth = calculate_average_bandwidth(sum(device_bandwidth.values()), sum(device_bandwidth.values()))

    # Detect devices with high network bandwidth
    high_bandwidth_devices = [device for device, bandwidth in device_bandwidth.items() if bandwidth > (2 * avg_bandwidth)]

    # Detect devices communicating with multiple unique destinations
    multi_destination_devices = [device for device, destinations in unique_destinations.items() if len(destinations) > 1]

    results = {
        "repeated_attempts": {device: attempts for device, attempts in devices.items() if attempts > 0},
        "port_scanning": {device: attempts for device, attempts in devices.items() if attempts > 1},
        "brute_force": {device: attempts for device, attempts in devices.items() if attempts > 0},
        "high_bandwidth": {device: bandwidth for device, bandwidth in device_bandwidth.items() if bandwidth > (2 * avg_bandwidth)},
        "multi_destination": {device: destinations for device, destinations in unique_destinations.items() if len(destinations) > 1}
    }

    return results

# Run the script
def main():
    pcap_file = "pcap/packets.pcap"
    time_window = 60  # Time window in seconds

    # Create the SQLite connection and table
    conn = sqlite3.connect('triage.db')
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS mal_node (ip TEXT)")

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
    results = pool.starmap(process_time_window, [(pcap_file, time_window) for _ in time_windows])
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


    # Close the SQLite connection
    conn.close()
    
    '''
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

        '''

# Execute the main function
if __name__ == "__main__":
    main()
