from scapy.all import *
import csv
import time

# Load the pcap file
packets = rdpcap('pcap/packets.pcap')

# Open the CSV file for writing
with open('example.csv', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)

    # Write the header row
    writer.writerow(['No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length'])

    # Iterate over each packet in the pcap file
    for i, packet in enumerate(packets):
        # Extract the packet information
        timestamp = time.gmtime(int(packet.time))
        time_str = time.strftime('%Y-%m-%d %H:%M:%S.%f', timestamp)
        src = packet[Ether].src
        dst = packet[Ether].dst
        proto = packet[Ether].type
        length = len(packet)

        # Write the packet information to the CSV file
        writer.writerow([i+1, time_str, src, dst, proto, length])
