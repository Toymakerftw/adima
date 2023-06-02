from flask import Flask, render_template, request
from flask_socketio import SocketIO
import psutil
import subprocess
import time
import sqlite3
import xgboost as xgb
import pandas as pd
from scapy.all import *
from scheduler import start_scheduler

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
socketio = SocketIO(app)

@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

def get_network_devices():
    """
    Get the number of devices on the network using ARP.
    """
    arp_output = subprocess.check_output(['arp', '-a']).decode('utf-8')
    arp_lines = arp_output.split('\n')
    device_lines = [line for line in arp_lines if ' at ' in line]
    num_devices = len(device_lines)
    return num_devices

def extract_features(packet):
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
            features['src_port'] = None
            features['dst_port'] = None
            features['tcp_flags'] = None
    
    # Add your additional feature extraction logic here
    
    return features

def analyze_pcap(pcap_file, model):
    malicious_nodes = []
    device_stats = {}  # Dictionary to store packet statistics for each device
    
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
    
    return results, malicious_nodes, device_stats

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/firewall')
def firewall():
    # Connect to the SQLite database
    conn = sqlite3.connect('triage.db')
    cursor = conn.cursor()

    # Fetch IP and MAC addresses from the mal_mac table
    cursor.execute('SELECT ip, mac FROM mal_mac')
    devices = cursor.fetchall()

    # Close the database connection
    conn.close()

    # Render the template with the devices data
    return render_template('firewall.html', devices=devices)

@app.route('/block_device', methods=['POST'])
def block_device():
    mac = request.form.get('mac')

    # Block the MAC address using firewalld
    subprocess.run(['firewall-cmd', '--permanent', '--add-rich-rule',
                    'rule family="ipv4" source address="{0}" drop'.format(mac)])
    subprocess.run(['firewall-cmd', '--reload'])

    # Return a JSON response
    return {'message': 'Device blocked successfully'}

@app.route('/pcap', methods=['GET', 'POST'])
def pcap():
    if request.method == 'POST':
        # POST request: Analysis triggered by the button press
        
        # Load the pretrained model
        model = xgb.Booster()
        model.load_model('pretrained_model.model')
        
        # Analyze the pcap file
        results, malicious_packets, device_statistics = analyze_pcap('pcap/packets.pcap', model)
        
        return render_template('model.html', malicious_results=results, device_stats=device_statistics)
    else:
        # GET request: Analysis triggered when accessing the page
        
        # Load the pretrained model
        model = xgb.Booster()
        model.load_model('pretrained_model.model')
        
        # Analyze the pcap file
        results, malicious_packets, device_statistics = analyze_pcap('pcap/packets.pcap', model)
        
        return render_template('model.html', malicious_results=results, device_stats=device_statistics)

@socketio.on('request_stats')
def send_stats():
    while True:
        # Get the network devices count
        num_devices = get_network_devices()

        # Get the system uptime
        uptime = get_system_uptime()

        # Get the CPU usage
        cpu_usage = get_cpu_usage()

        # Get the memory usage
        memory_usage = get_memory_usage()

        # Get the storage usage
        storage_usage = get_storage_usage()

        # Emit the statistics to the client
        socketio.emit('update_stats', {
            'uptime': uptime,
            'cpu_usage': cpu_usage,
            'memory_usage': memory_usage,
            'storage_usage': storage_usage,
            'num_devices': num_devices
        })

        time.sleep(1)

def get_system_uptime():
    """
    Get the system uptime in a human-readable format.
    """
    uptime = time.time() - psutil.boot_time()
    minutes, seconds = divmod(uptime, 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)
    return f"{int(days)} days, {int(hours)} hours, {int(minutes)} minutes, {int(seconds)} seconds"

def get_cpu_usage():
    """
    Get the current CPU usage as a percentage.
    """
    return psutil.cpu_percent(interval=1)

def get_memory_usage():
    """
    Get the current memory usage in a human-readable format.
    """
    memory = psutil.virtual_memory()
    return {
        'total': memory.total,
        'available': memory.available,
        'used': memory.used,
        'percent': memory.percent
    }

def get_storage_usage():
    """
    Get the current storage usage in a human-readable format.
    """
    partitions = psutil.disk_partitions()
    usage = {}
    for partition in partitions:
        try:
            partition_usage = psutil.disk_usage(partition.mountpoint)
            usage[partition.device] = {
                'total': partition_usage.total,
                'used': partition_usage.used,
                'free': partition_usage.free,
                'percent': partition_usage.percent
            }
        except Exception as e:
            print(f"Error retrieving usage information for {partition.device}: {e}")
    return usage

if __name__ == '__main__':
    start_scheduler()
    socketio.run(app)
