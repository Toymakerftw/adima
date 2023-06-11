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

# Protocol names dictionary
protocol_names = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    # Add more protocol numbers and their corresponding names as needed
}


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


# Find anomalies in pcap using isolation forest
def analyze_pcap(file_path):
    packets = rdpcap(file_path)

    data = []
    for packet in packets:
        if IP in packet and TCP in packet:
            src_ip = struct.unpack("!I", inet_aton(packet[IP].src))[0]
            dst_ip = struct.unpack("!I", inet_aton(packet[IP].dst))[0]
            data.append([src_ip, dst_ip, packet[TCP].sport, packet[TCP].dport])

    df = pd.DataFrame(data, columns=["src_ip", "dst_ip", "src_port", "dst_port"])

    X = df.values

    clf = IsolationForest(random_state=0).fit(X)
    y_pred = clf.predict(X)

    labels_df = pd.DataFrame(y_pred, columns=["label"])
    df = pd.concat([df, labels_df], axis=1)

    anomalies_df = df[df["label"] == -1]

    conn = create_connection()
    if conn is not None:
        malicious_ips = [
            (
                socket.inet_ntoa(struct.pack("!I", row["src_ip"])),
                socket.inet_ntoa(struct.pack("!I", row["dst_ip"])),
            )
            for _, row in anomalies_df.iterrows()
        ]

        with conn:
            cursor = conn.cursor()
            insert_malicious_ips(cursor, malicious_ips)

        print("Anomalies saved to database.")


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload():
    if "pcap_file" not in request.files:
        return "No file uploaded"

    file = request.files["pcap_file"]
    file.save("uploaded.pcap")

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

    dtest = xgb.DMatrix(df)
    predictions = model.predict(dtest)

    conn = create_connection()
    if conn is not None:
        malicious_ips = [
            (packets[i][IP].src, packets[i][IP].dst)
            for i, prediction in enumerate(predictions)
            if prediction == 1 and IP in packets[i]
        ]

        with conn:
            cursor = conn.cursor()
            insert_malicious_ips(cursor, malicious_ips)

        file_path = "uploaded.pcap"
        analyze_pcap(file_path)

        protocol_names_df = df.replace({"protocol": protocol_names})

        return render_template(
            "result.html",
            malicious_ips=malicious_ips,
            protocol_names=protocol_names_df["protocol"].tolist(),
        )


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
            protocol_names.get(pkt[IP].proto, "Unknown"),
            len(pkt.getlayer(Raw).load) if pkt.haslayer(Raw) else 0,
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
