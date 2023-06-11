from flask import Flask, render_template, request
from sklearn.ensemble import IsolationForest
import xgboost as xgb
import pandas as pd
import numpy as np
import socket
from scapy.layers.inet import IP
from scapy.all import *
import struct
import sqlite3
from sqlite3 import Error

app = Flask(__name__)

# Load the saved model
model = xgb.Booster()
model.load_model("unsw_nb15_xgb_model2.model")


def create_connection():
    try:
        conn = sqlite3.connect("triage.db")
        return conn
    except Error as e:
        print(e)


def create_table(conn):
    try:
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
        return cursor
    except Error as e:
        print(e)


def insert_malicious_ips(cursor, src_ip, dst_ip):
    try:
        cursor.execute(
            "INSERT OR IGNORE INTO mal_ip (Source, Destination) VALUES (?, ?)",
            (src_ip, dst_ip),
        )
    except Error as e:
        print(e)


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
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS anomalies (
            src_ip TEXT,
            dst_ip TEXT
        )
        """
    )

    for _, row in anomalies_df.iterrows():
        src_ip = socket.inet_ntoa(struct.pack("!I", row["src_ip"]))
        dst_ip = socket.inet_ntoa(struct.pack("!I", row["dst_ip"]))
        cursor.execute(
            "INSERT OR IGNORE INTO anomalies (src_ip, dst_ip) VALUES (?, ?)",
            (src_ip, dst_ip),
        )

    conn.commit()
    conn.close()

    anomalies = anomalies_df[["src_ip", "dst_ip"]].values.tolist()

    return anomalies


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload():
    if "pcap_file" not in request.files:
        return "No file uploaded"

    file = request.files["pcap_file"]
    file.save("uploaded.pcap")

    malicious_ips = analyze_pcap("uploaded.pcap")

    conn = create_connection()
    cursor = create_table(conn)

    for src_ip, dst_ip in malicious_ips:
        src_ip_str = socket.inet_ntoa(struct.pack("!I", src_ip))
        dst_ip_str = socket.inet_ntoa(struct.pack("!I", dst_ip))
        insert_malicious_ips(cursor, src_ip_str, dst_ip_str)
        conn.commit()

    conn.close()

    malicious_ips_str = [
        (
            socket.inet_ntoa(struct.pack("!I", src_ip)),
            socket.inet_ntoa(struct.pack("!I", dst_ip)),
        )
        for src_ip, dst_ip in malicious_ips
    ]

    return render_template("result.html", malicious_ips=malicious_ips_str)


@app.route("/packet_details", methods=["POST"])
def packet_details():
    src_ip = request.form.get("src_ip")
    dst_ip = request.form.get("dst_ip")

    packets = rdpcap("uploaded.pcap")
    packet_details = []
    for pkt in packets:
        if IP in pkt and pkt[IP].src == src_ip and pkt[IP].dst == dst_ip:
            src_port = pkt.sport
            dst_port = pkt.dport
            protocol = pkt[IP].proto
            payload_size = 0
            if "Raw" in pkt:
                payload_size = len(pkt["Raw"].load)
            packet_details.append(
                (pkt.summary(), src_port, dst_port, protocol, payload_size)
            )

    return render_template(
        "packet_details.html",
        src_ip=src_ip,
        dst_ip=dst_ip,
        packet_details=packet_details,
    )


if __name__ == "__main__":
    app.run(debug=True)
