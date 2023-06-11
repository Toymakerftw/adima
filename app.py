# Import the necessary libraries
from flask import Flask, render_template, request
from sklearn.ensemble import IsolationForest
import struct
import xgboost as xgb
import pandas as pd
import socket
from scapy.layers.inet import IP
from scapy.all import *
import sqlite3
from sqlite3 import Error

app = Flask(__name__)

# Load the saved model
model = xgb.Booster()
model.load_model("unsw_nb15_xgb_model2.model")


# Create a connection to the SQLite database and create the "mal_ip" table
def create_connection():
    conn = None
    try:
        conn = sqlite3.connect("triage.db")
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS mal_ip (
                Source TEXT,
                Destination TEXT
            )
            """
        )
        conn.commit()
        return conn
    except Error as e:
        print(e)


# Insert malicious IPs into the "mal_ip" table
def insert_malicious_ips(cursor, ips):
    try:
        cursor.executemany(
            "INSERT INTO mal_ip (Source, Destination) VALUES (?, ?)", ips
        )
        cursor.connection.commit()
    except Error as e:
        print(e)


# Find Anomalies in pcap using isolation forest


def analyze_pcap(file_path):
    # Read the pcap file using Scapy
    packets = rdpcap(file_path)

    # Extract the necessary data from the packets
    data = []
    for packet in packets:
        # Extract the necessary fields from the packet
        # and append them to the data list
        if IP in packet and TCP in packet:
            src_ip = struct.unpack("!I", inet_aton(packet[IP].src))[0]
            dst_ip = struct.unpack("!I", inet_aton(packet[IP].dst))[0]
            data.append([src_ip, dst_ip, packet[TCP].sport, packet[TCP].dport])

    # Convert the data into a pandas DataFrame
    df = pd.DataFrame(data, columns=["src_ip", "dst_ip", "src_port", "dst_port"])

    # Convert the DataFrame into a dataset
    X = df.values

    # Train an unsupervised model to detect malicious nodes
    clf = IsolationForest(random_state=0).fit(X)

    # Use the trained model to predict malicious nodes
    y_pred = clf.predict(X)

    # Convert the predicted labels into a DataFrame
    labels_df = pd.DataFrame(y_pred, columns=["label"])

    # Merge the predicted labels with the original DataFrame
    df = pd.concat([df, labels_df], axis=1)

    # Filter out rows labeled as "Malicious" (-1)
    anomalies_df = df[df["label"] == -1]

    # Initialize the SQLite3 database and create the "anomalies" table
    conn = sqlite3.connect("triage.db")
    cursor = conn.cursor()

    # Create the "anomalies" table if it doesn't exist
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS anomalies (
            src_ip TEXT,
            dst_ip TEXT
        )
    """
    )

    # Insert the source and destination IP addresses into the "anomalies" table
    for _, row in anomalies_df.iterrows():
        src_ip = socket.inet_ntoa(struct.pack("!I", row["src_ip"]))
        dst_ip = socket.inet_ntoa(struct.pack("!I", row["dst_ip"]))
        cursor.execute(
            "INSERT INTO anomalies (src_ip, dst_ip) VALUES (?, ?)", (src_ip, dst_ip)
        )

    conn.commit()
    conn.close()

    print("Anomalies saved to database.")


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload():
    # Check if a file was submitted
    if "pcap_file" not in request.files:
        return "No file uploaded"

    # Save the uploaded file
    file = request.files["pcap_file"]
    file.save("uploaded.pcap")

    # Read the pcap file and extract packet data
    packets = rdpcap("uploaded.pcap")
    data = [
        (
            int.from_bytes(socket.inet_aton(pkt[IP].src), byteorder="big"),
            int.from_bytes(socket.inet_aton(pkt[IP].dst), byteorder="big"),
            pkt.sport,
            pkt.dport,
            pkt[IP].proto,
            len(pkt["Raw"].load) if "Raw" in pkt else 0,
        )
        for pkt in packets
        if IP in pkt
    ]

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

    # Use the trained model to classify packets as malicious or benign
    dtest = xgb.DMatrix(df)
    predictions = model.predict(dtest)

    # Create a connection to the SQLite database
    conn = create_connection()
    if conn is not None:
        # Filter out the malicious packets and collect the malicious IPs
        malicious_ips = [
            (packets[i][IP].src, packets[i][IP].dst)
            for i, prediction in enumerate(predictions)
            if prediction == 1 and IP in packets[i]
        ]

        # Insert the malicious IPs into the "mal_ip" table
        cursor = conn.cursor()
        insert_malicious_ips(cursor, malicious_ips)
        cursor.close()
        conn.close()

        file_path = "uploaded.pcap"  # Replace with the path to your pcap file
        analyze_pcap(file_path)

        # Render the result.html template with the malicious IPs
        return render_template("result.html", malicious_ips=malicious_ips)


@app.route("/packet_details", methods=["POST"])
def packet_details():
    src_ip = request.form.get("src_ip")
    dst_ip = request.form.get("dst_ip")

    packets = rdpcap("uploaded.pcap")
    packet_details = [
        (
            pkt.summary(),
            pkt.sport,
            pkt.dport,
            pkt[IP].proto,
            len(pkt["Raw"].load) if "Raw" in pkt else 0,
        )
        for pkt in packets
        if IP in pkt and pkt[IP].src == src_ip and pkt[IP].dst == dst_ip
    ]

    return render_template(
        "packet_details.html",
        src_ip=src_ip,
        dst_ip=dst_ip,
        packet_details=packet_details,
    )


if __name__ == "__main__":
    app.run(debug=True)
