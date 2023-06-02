import subprocess
import os

def capture_packets(interface):
    # Create the pcap directory if it doesn't exist
    if not os.path.exists("pcap"):
        os.makedirs("pcap")

    # Run tcpdump command to capture packets for 3 minutes at a time
    command = ["tcpdump", "-i", interface, "-G", "60", "-w", "pcap/packets.pcap"]
    process = subprocess.Popen(command)

    # Wait for user input to stop capturing
    input("Press enter to stop capturing...")

    # Stop tcpdump process
    process.terminate()

    print("Packet capture completed.")

# Change the interface name to the one you want to capture packets on
interface = "enp0s3"

capture_packets(interface)