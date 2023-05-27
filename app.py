import xgboost as xgb
import pandas as pd
from scapy.all import *
from flask import Flask, render_template, request

app = Flask(__name__)

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

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        pcap_file = request.files['pcap_file']
        pcap_file.save('uploaded.pcap')
        
        # Load the pretrained model
        model = xgb.Booster()
        model.load_model('pretrained_model.model')
        
        # Analyze the pcap file
        results, malicious_packets, device_statistics = analyze_pcap('uploaded.pcap', model)
        
        return render_template('index.html', malicious_results=results, device_stats=device_statistics)
    
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
