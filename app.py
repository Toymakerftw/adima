from flask import Flask, render_template, request
import xgboost as xgb
import pandas as pd
import numpy as np
import socket
from scapy.layers.inet import IP
from scapy.all import *
import os

app = Flask(__name__)

# Load the saved model
model = xgb.Booster()
model.load_model("unsw_nb15_xgb_model2.model")


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload():
    # Check if a file was submitted
    if "pcap_file" not in request.files:
        return "No file uploaded"

    file = request.files["pcap_file"]

    # Save the uploaded file
    file.save("uploaded.pcap")

    # Read the pcap file and extract packet data
    packets = rdpcap("uploaded.pcap")
    data = []
    for pkt in packets:
        try:
            if IP in pkt:
                # Extract relevant fields from packet
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                src_port = pkt.sport
                dst_port = pkt.dport
                protocol = pkt[IP].proto
                payload_size = len(pkt["Raw"].load)
                # Append packet data to list
                data.append(
                    [src_ip, dst_ip, src_port, dst_port, protocol, payload_size]
                )
        except:
            pass

    # Create a DataFrame from the extracted data
    df = pd.DataFrame(
        data,
        columns=[
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "protocol",
            "payload_size",
        ],
    )

    # Convert IP addresses to integers for easier processing
    df["src_ip"] = df["src_ip"].apply(
        lambda x: int.from_bytes(socket.inet_aton(x), byteorder="big")
    )
    df["dst_ip"] = df["dst_ip"].apply(
        lambda x: int.from_bytes(socket.inet_aton(x), byteorder="big")
    )

    # Use the trained model to classify packets as malicious or benign
    dtest = xgb.DMatrix(df)
    predictions = model.predict(dtest)

    # Filter out the malicious packets
    malicious_ips = []
    for i in range(len(predictions)):
        if predictions[i] == 1:
            if IP in packets[i]:
                malicious_ips.append((packets[i][IP].src, packets[i][IP].dst))

    # Render the result.html template with the malicious IPs
    return render_template("result.html", malicious_ips=malicious_ips)


if __name__ == "__main__":
    app.run(debug=True)
