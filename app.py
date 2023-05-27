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
    
    # Load the pcap file
    packets = rdpcap(pcap_file)
    
    # Analyze each packet and predict using the pretrained model
    data = []
    for packet in packets:
        features = extract_features(packet)
        
        # Append features to the data list
        data.append(features)
    
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
    
    # Check if the node is predicted as malicious and collect the summaries
    results = []
    for i, p in enumerate(prediction):
        if p == 1:
            results.append(packets[i].summary())
            malicious_nodes.append(packets[i])
    
    return results, malicious_nodes

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Load the pretrained XGBoost model
        model = xgb.Booster(model_file='pretrained_model.model')
        
        # Get the uploaded pcap file
        pcap_file = request.files['pcap_file']
        
        # Save the pcap file locally
        pcap_file.save('uploaded.pcap')
        
        # Analyze the uploaded pcap file
        results, malicious_nodes = analyze_pcap('uploaded.pcap', model)
        
        # Display the malicious nodes
        return render_template('index.html', results=results)
    
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
