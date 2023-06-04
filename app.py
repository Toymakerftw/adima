import xgboost as xgb
import pandas as pd
from scapy.all import *
from flask import Flask, render_template, request, redirect, jsonify
from anomaly import detect_anomalies
from subprocess import Popen, PIPE, subprocess
import os
import signal
import time
import sqlite3
from flask_socketio import SocketIO

app = Flask(__name__)
socketio = SocketIO(app)

@socketio.on('connect', namespace='/capture_packets')
def test_connect():
       print('Client connected')

@socketio.on('disconnect', namespace='/capture_packets')
def test_disconnect():
       print('Client disconnected')

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
    results, malicious_nodes, device_statistics = analyze_pcap(pcap_file, model, local_ip)
    
    if not malicious_nodes:
        message = "No Malicious Activity Detected"
    else:
        message = None

    return render_template('index.html', malicious_results=results, device_stats=device_statistics, message=message)

@app.route('/capture_packets')
def capture_packets():
    temp_file = 'pcap/temp.pcap'  # Temporary file path for capturing packets
    final_file = 'pcap/packets.pcap'  # Final file path for storing captured packets

    # Start tcpdump to capture packets and save them to the temporary file
    command = ['sudo','tcpdump', '-w', temp_file, '-G', '180']
    process = Popen(command, stdout=PIPE, stderr=PIPE, preexec_fn=os.setsid)

    # Use a separate thread to periodically update the progress bar
    def update_progress():
        for i in range(180):
            time.sleep(1)
            progress = int((i + 1) / 180 * 100)
            socketio.emit('progress', {'progress': progress}, namespace='/capture_packets')

    thread = threading.Thread(target=update_progress)
    thread.start()

    # Wait for 3 minutes
    time.sleep(180)

    # Terminate tcpdump process
    os.killpg(os.getpgid(process.pid), signal.SIGTERM)

    # Move the temporary file to the final location
    os.rename(temp_file, final_file)

    return jsonify({'success': True}) , redirect('/')

@app.route('/capture_packets_status')
def capture_packets_status():
    return jsonify({'progress': session.get('progress', 0)})

@app.route('/firewall')
def firewall():
    # Create a SQLite database connection
    conn = sqlite3.connect('triage.db')
    cursor = conn.cursor()

    # Get the list of blocked websites from the "websites" table
    cursor.execute("SELECT website FROM websites")
    blocked_websites = [row[0] for row in cursor.fetchall()]

    # Get the list of blocked MAC addresses from the "mac_addresses" table
    cursor.execute("SELECT mac_address FROM mac_addresses")
    blocked_mac_addresses = [row[0] for row in cursor.fetchall()]

    # Get the list of IPs from the "mal_node" table
    cursor.execute("SELECT ip FROM mal_node")
    mal_ips = [row[0] for row in cursor.fetchall()]

    # Get the list of IPs from the "hiband_node" table
    cursor.execute("SELECT ip FROM hiband_node")
    highband_ips = [row[0] for row in cursor.fetchall()]

    # Close the database connection
    conn.close()

    # Create a list to store the IP-MAC mappings
    ip_mac_mappings = []

    # Iterate over the list of IPs and find their corresponding MAC addresses using arp -a command
    for ip in mal_ips + highband_ips:
        try:
            output = subprocess.check_output(['arp', '-a', ip])
            mac_address = output.decode('utf-8').split()[3]
            ip_mac_mappings.append((ip, mac_address))
        except subprocess.CalledProcessError:
            pass

    # Render the index.html template with the list of blocked websites and MAC addresses
    return render_template('index.html', blocked_websites=blocked_websites, blocked_mac_addresses=blocked_mac_addresses, ip_mac_mappings=ip_mac_mappings, highband_ips=highband_ips)

@app.route('/block', methods=['POST'])
def block():
    website = request.form.get('website')
    mac_address = request.form.get('mac_address')

    # Create a SQLite database connection
    conn = sqlite3.connect('triage.db')
    cursor = conn.cursor()

    # Create the "websites" table if it doesn't exist
    cursor.execute('''CREATE TABLE IF NOT EXISTS websites ( id INTEGER PRIMARY KEY AUTOINCREMENT, website TEXT)''')

    # Create the "mac_addresses" table if it doesn't exist
    cursor.execute('''CREATE TABLE IF NOT EXISTS mac_addresses ( id INTEGER PRIMARY KEY AUTOINCREMENT, mac_address TEXT)''')

    # Block the website with firewall-cmd command with sudo privileges
    if website:
        subprocess.run(['sudo', 'firewall-cmd', '--add-rich-rule', 'rule family="ipv4" source address="all" destination address="{0}" reject'.format(website)], check=True)
        # Insert the blocked website into the "websites" table
        cursor.execute("INSERT INTO websites (website) VALUES (?)", (website,))
    # Block the MAC address with firewall-cmd command with sudo privileges
    if mac_address:
        subprocess.run(['sudo', 'firewall-cmd', '--add-rich-rule', 'rule family="ipv4" source address="all" mac address="{0}" reject'.format(mac_address)], check=True)
        # Insert the blocked MAC address into the "mac_addresses" table
        cursor.execute("INSERT INTO mac_addresses (mac_address) VALUES (?)", (mac_address,))

    # Commit the changes and close the database connection
    conn.commit()
    conn.close()

    if website:
        return "Blocked website: {0}".format(website)
    elif mac_address:
        return "Blocked MAC address: {0}".format(mac_address)

@app.route('/unblock', methods=['POST'])
def unblock():
    website = request.form.get('website')
    mac_address = request.form.get('mac_address')

    # Create a SQLite database connection
    conn = sqlite3.connect('triage.db')
    cursor = conn.cursor()

    # Unblock the website with firewall-cmd command with sudo privileges
    if website:
        subprocess.run(['sudo', 'firewall-cmd', '--remove-rich-rule', 'rule family="ipv4" source address="all" destination address="{0}" reject'.format(website)], check=True)

        # Reload the firewall with sudo privileges
        subprocess.run(['sudo', 'firewall-cmd', '--reload'], check=True)

        # Delete the blocked website from the "websites" table
        cursor.execute("DELETE FROM websites WHERE website=?", (website,))
    # Unblock the MAC address with firewall-cmd command with sudo privileges
    if mac_address:
        subprocess.run(['sudo', 'firewall-cmd', '--remove-rich-rule', 'rule family="ipv4" source address="all" mac address="{0}" reject'.format(mac_address)], check=True)

        # Reload the firewall with sudo privileges
        subprocess.run(['sudo', 'firewall-cmd', '--reload'], check=True)

        # Delete the blocked MAC address from the "mac_addresses" table
        cursor.execute("DELETE FROM mac_addresses WHERE mac_address=?", (mac_address,))

    # Commit the changes and close the database connection
    conn.commit()
    conn.close()

    if website:
        return "Unblocked website: {0}".format(website)
    elif mac_address:
        return "Unblocked MAC address: {0}".format(mac_address)

if __name__ == '__main__':
    app.run(debug=True)
