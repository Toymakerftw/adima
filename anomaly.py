import os
import sqlite3
from datetime import datetime
from scapy.all import *

def is_public_ip(ip):
    ip = list(map(int, ip.strip().split('.')[:2]))
    if ip[0] == 10:
        return False
    if ip[0] == 172 and ip[1] in range(16, 32):
        return False
    if ip[0] == 192 and ip[1] == 168:
        return False
    return True

def detect_anomalies(pcap_file, local_ip):
    # Create a SQLite database connection
    conn = sqlite3.connect('triage.db')
    cursor = conn.cursor()

    # Check if the "anomalies" table exists, create it if not
    cursor.execute("CREATE TABLE IF NOT EXISTS anomalies (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, timestamp TIMESTAMP)")

    # Check if the "mal_node" table exists, create it if not
    cursor.execute("CREATE TABLE IF NOT EXISTS mal_node (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, timestamp TIMESTAMP)")

    # Check if the local IP is public or private
    local_ip_type = 'public' if is_public_ip(local_ip) else 'private'

    # Read the pcap file using Scapy
    packets = rdpcap(pcap_file)

    # Define a set to store suspicious IP addresses
    suspicious_ips = set()

    # Iterate over each packet in the pcap file
    for packet in packets:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto

            # Check for suspicious behaviors
            if src_ip != local_ip and is_public_ip(src_ip):
                # Check for specific suspicious behaviors and add IP to the set
                if protocol == 17:  # UDP protocol
                    suspicious_ips.add(src_ip)
                elif TCP in packet:
                    flags = packet[TCP].flags
                    if flags == 'S' or flags == 'SA':  # TCP SYN or SYN-ACK
                        suspicious_ips.add(src_ip)

    # Insert the suspicious IPs into the "anomalies" table
    timestamp = datetime.now()
    for ip in suspicious_ips:
        cursor.execute("INSERT INTO anomalies (ip, timestamp) VALUES (?, ?)", (ip, timestamp))

    # Insert the malicious IPs into the "mal_node" table
    if ip in suspicious_ips:
        cursor.execute("INSERT INTO mal_node (ip, timestamp) VALUES (?, ?)", (ip, timestamp))

    # Commit the changes and close the database connection
    conn.commit()
    conn.close()

    print("Anomaly detection completed.")

# Provide the pcap file path and local IP address
pcap_file = "pcap/packets.pcap"
local_ip = " 192.168.228.166"

# Call the detect_anomalies function
detect_anomalies(pcap_file, local_ip)
