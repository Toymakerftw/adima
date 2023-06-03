import xgboost as xgb
import pandas as pd
from scapy.all import *
from flask import Flask, render_template, request, redirect
from anomaly import detect_anomalies
from subprocess import Popen, PIPE
import os
import signal
import time
import sqlite3

app = Flask(__name__)

def extract_features(packet):
    pcap_file = 'pcap/packets.pcap'  # Path to the pcap file captured by tcpdump
    features = {}

    # Extract features from the packet
    if IP in packet:
        features['src_ip'] = str(packet[IP].src)
        features['dst_ip'] = str(packet[IP].dst)

    # Port scanning detection
    if TCP in packet:
        flags = packet[TCP].flags
        if flags == 'S':
            features['src_port'] = packet[TCP].sport
            features['dst_port'] = packet[TCP].dport
            features['tcp_flags'] = flags
        elif flags == 'SA':
            features['src_port'] = packet[TCP].dport
            features['dst_port'] = packet[TCP].sport
            features['tcp_flags'] = flags
        else:
            # Set default values when 'src_port' is not available
            features['src_port'] = None
            features['dst_port'] = None
            features['tcp_flags'] = None
    else:
        # Set default values when 'src_port' is not available
        features['src_port'] = None
        features['dst_port'] = None
        features['tcp_flags'] = None

    # Add your additional feature extraction logic here

    return features

def analyze_pcap(pcap_file, model, local_ip):
    pcap_file = 'pcap/packets.pcap'  # Path to the pcap file captured by tcpdump
    malicious_nodes = []
    device_stats = {}

    # Load the pcap file
    packets = rdpcap(pcap_file)

    # Analyze each packet and predict using the pretrained model
    data = []
    for packet in packets:
        features = extract_features(packet)

        # Append features to the data list
        data.append(features)

        # Update device packet statistics
        if IP in packet:
            src_ip = str(packet[IP].src)
            dst_ip = str(packet[IP].dst)

            # Update sender statistics
            if src_ip in device_stats:
                device_stats[src_ip]['sent'] += 1
            else:
                device_stats[src_ip] = {'sent': 1, 'received': 0}

            # Update receiver statistics
            if dst_ip in device_stats:
                device_stats[dst_ip]['received'] += 1
            else:
                device_stats[dst_ip] = {'sent': 0, 'received': 1}

    # Convert data to a DataFrame
    df = pd.DataFrame(data)

    # Convert categorical columns to the 'category' data type
    df['src_ip'] = df['src_ip'].astype('category')
    df['dst_ip'] = df['dst_ip'].astype('category')
    df['src_port'] = df['src_port'].astype('category')
    df['dst_port'] = df['dst_port'].astype('category')
    df['tcp_flags'] = df['tcp_flags'].astype('category')

    # Convert DataFrame to DMatrix with enable_categorical=True
    x_test = xgb.DMatrix(df, enable_categorical=True)
    prediction = model.predict(x_test)

    # Check if the node is predicted as malicious and collect the details
    results = []
    for i, p in enumerate(prediction):
        if p == 1:
            packet = packets[i]
            result = {
                'summary': packet.summary(),
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'src_port': packet[TCP].sport if TCP in packet else None,
                'dst_port': packet[TCP].dport if TCP in packet else None,
                'tcp_flags': packet[TCP].flags if TCP in packet else None
            }
            results.append(result)

    # Perform anomaly detection
    detect_anomalies(pcap_file, local_ip)

    return results, malicious_nodes, device_stats


@app.route('/')
def index():
    pcap_file = 'pcap/packets.pcap'  # Path to the pcap file captured by tcpdump

    # Load the pretrained model
    model = xgb.Booster()
    model.load_model('pretrained_model.model')

    # Get the local IP address
    local_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)

    # Analyze the pcap file
    results, malicious_packets, device_statistics = analyze_pcap(pcap_file, model, local_ip)

    message = "No Malicious Activity Detected"
    if len(malicious_packets) > 0:
        message = None

    return render_template('index.html', malicious_results=results, device_stats=device_statistics, message=message)

@app.route('/capture_packets')
def capture_packets():
    temp_file = 'pcap/temp.pcap'  # Temporary file path for capturing packets
    final_file = 'pcap/packets.pcap'  # Final file path for storing captured packets

    # Start tcpdump to capture packets and save them to the temporary file
    command = ['sudo','tcpdump', '-w', temp_file, '-G', '180']
    process = Popen(command, stdout=PIPE, stderr=PIPE, preexec_fn=os.setsid)

    # Wait for 3 minutes
    time.sleep(180)

    # Terminate tcpdump process
    os.killpg(os.getpgid(process.pid), signal.SIGTERM)

    # Move the temporary file to the final location
    os.rename(temp_file, final_file)

    return redirect('/')

@app.route('/firewall')
def firewall():

    # Create a SQLite database connection
    conn = sqlite3.connect('triage.db')
    cursor = conn.cursor()

    # Select ip's from "mal_node" table
    cursor.execute("SELECT ip FROM mal_node")

    # Commit the changes and close the database connection
    conn.commit()
    conn.close()

    # Fetch all the rows and store the IP addresses in the ip_addresses array
    ip_addresses = [row[0] for row in cursor.fetchall()]

    # Fetch IP addresses from mal_node table (replace this with your actual code)
    #ip_addresses = ['192.168.1.1', '192.168.1.2', '192.168.1.3']

    results = []
    for ip in ip_addresses:
        # Run arp command to get MAC address and hostname
        arp_output = subprocess.check_output(['arp', '-a', ip]).decode('utf-8')

        # Parse the output to extract MAC address and hostname
        mac_address = arp_output.split(' ')[3]
        hostname = arp_output.split(' ')[0]

        # Add the result to the list
        results.append({'ip': ip, 'mac_address': mac_address, 'hostname': hostname})

    # Render the template with the results
    return render_template('firewall.html', results=results)

@app.route('/block', methods=['POST'])
def block():
    mac_address = request.form['mac_address']

    # Create a SQLite database connection
    conn = sqlite3.connect('triage.db')
    cursor = conn.cursor()

    # Create the "blocked" table if it doesn't exist
    cursor.execute('''CREATE TABLE IF NOT EXISTS blocked ( id INTEGER PRIMARY KEY AUTOINCREMENT, mac_address TEXT)''')

    # Run firewall-cmd command to block the MAC address with sudo privileges
    subprocess.run(['sudo', 'firewall-cmd', '--permanent', '--add-rich-rule',
                    'rule source mac="{0}" drop'.format(mac_address)], check=True)

    # Reload the firewall with sudo privileges
    subprocess.run(['sudo', 'firewall-cmd', '--reload'], check=True)

    # Insert the blocked MAC address into the "blocked" table
    cursor.execute("INSERT INTO blocked (mac_address) VALUES (?)", (mac_address,))

    # Commit the changes and close the database connection
    conn.commit()
    conn.close()

    return "Blocked MAC address: {0}".format(mac_address)

if __name__ == '__main__':
    app.run(debug=True)
