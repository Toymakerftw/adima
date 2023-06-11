# Import the necessary libraries
from flask import Flask, render_template, request
import xgboost as xgb
import pandas as pd
import numpy as np
import socket
from scapy.layers.inet import IP
from scapy.all import *
import os
import sqlite3
from sqlite3 import Error

app = Flask(__name__)

# Load the saved model
model = xgb.Booster()
model.load_model("unsw_nb15_xgb_model2.model")


# Create a connection pool
def create_connection():
    conn = None
    try:
        conn = sqlite3.connect("triage.db")
        return conn
    except Error as e:
        print(e)


# Connect to the SQLite database and create the "mal_ip" table
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


# Insert malicious IPs into the "mal_ip" table
def insert_malicious_ips(cursor, src_ip, dst_ip):
    try:
        cursor.execute(
            "INSERT INTO mal_ip (Source, Destination) VALUES (?, ?)", (src_ip, dst_ip)
        )
    except Error as e:
        print(e)


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

    # Create a connection from the connection pool
    conn = create_connection()
    cursor = None
    if conn is not None:
        # Create the "mal_ip" table if it doesn't exist
        cursor = create_table(conn)

    # Filter out the malicious packets
    malicious_ips = []
    for i in range(len(predictions)):
        if predictions[i] == 1:
            if IP in packets[i]:
                malicious_ips.append((packets[i][IP].src, packets[i][IP].dst))
                # Insert the malicious IPs into the "mal_ip" table
                if cursor is not None:
                    insert_malicious_ips(cursor, packets[i][IP].src, packets[i][IP].dst)
                    conn.commit()

    # Close the connection
    if conn is not None:
        conn.close()

    # Render the result.html template with the malicious IPs
    return render_template("result.html", malicious_ips=malicious_ips)


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
