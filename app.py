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
import ipaddress

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
                Destination TEXT,
                UNIQUE(Source, Destination) ON CONFLICT IGNORE
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS anomalies (
                Source TEXT,
                Destination TEXT,
                UNIQUE(Source, Destination) ON CONFLICT IGNORE
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
        cursor.execute("DELETE FROM mal_ip")
        cursor.executemany(
            "INSERT INTO mal_ip (Source, Destination) VALUES (?, ?)", ips
        )
        cursor.connection.commit()
    except Error as e:
        print(e)


# Insert Anomalous IPs into the "anomalies" table
def insert_anomalous_ips(cursor, ips):
    try:
        cursor.execute("DELETE FROM anomalies")
        cursor.executemany(
            "INSERT INTO anomalies (Source, Destination) VALUES (?, ?)", ips
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
            insert_anomalous_ips(cursor, malicious_ips)

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
            int.from_bytes(socket.inet_aton(pkt[IP].src), byteorder="big")
            if IP in pkt
            else None,
            int.from_bytes(socket.inet_aton(pkt[IP].dst), byteorder="big")
            if IP in pkt
            else None,
            pkt.sport if TCP in pkt else None,
            pkt.dport if TCP in pkt else None,
            pkt[IP].proto if IP in pkt else None,
            len(pkt["Raw"].load) if IP in pkt and "Raw" in pkt else 0,
        )
        for pkt in packets
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

    with conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT DISTINCT mal_ip.Source, mal_ip.Destination
            FROM mal_ip
            INNER JOIN anomalies ON mal_ip.Source = anomalies.Source AND mal_ip.Destination = anomalies.Destination
            """
        )
        rows = cursor.fetchall()
        common_ips = [(row[0], row[1]) for row in rows]

    unique_protocol_names = list(set(protocol_names_df["protocol"].tolist()))

    return render_template(
        "result.html",
        common_ips=common_ips,
        protocol_names=unique_protocol_names,
    )


@app.route("/packet_details", methods=["POST"])
def packet_details():
    src_ip = request.form.get("src_ip")
    dst_ip = request.form.get("dst_ip")

    packets = rdpcap("uploaded.pcap")
    packet_details = [
        (
            pkt.summary(),
            pkt.sport if "sport" in pkt else "N/A",
            pkt.dport if "dport" in pkt else "N/A",
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


@app.route("/anomalies")
def anomalies():
    conn = create_connection()
    with conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT * FROM anomalies
            """
        )
        rows = cursor.fetchall()
        anomalies = [(row[0], row[1]) for row in rows]

    return render_template("anomlaies.html", anomalies=anomalies)


@app.route("/firewall")
def firewall():
    # Create a SQLite database connection
    conn = sqlite3.connect("triage.db")
    cursor = conn.cursor()

    # Create the "websites" table if it doesn't exist
    cursor.execute(
        """CREATE TABLE IF NOT EXISTS websites ( id INTEGER PRIMARY KEY AUTOINCREMENT, website TEXT)"""
    )

    # Create the "mac_addresses" table if it doesn't exist
    cursor.execute(
        """CREATE TABLE IF NOT EXISTS mac_addresses ( id INTEGER PRIMARY KEY AUTOINCREMENT, mac_address TEXT)"""
    )

    # Create the "hiband_node" table if it doesn't exist
    cursor.execute(
        """CREATE TABLE IF NOT EXISTS hiband_node ( id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT)"""
    )

    # Get the list of blocked websites from the "websites" table
    cursor.execute("SELECT website FROM websites")
    blocked_websites = [row[0] for row in cursor.fetchall()]

    # Get the list of blocked MAC addresses from the "mac_addresses" table
    cursor.execute("SELECT mac_address FROM mac_addresses")
    blocked_mac_addresses = [row[0] for row in cursor.fetchall()]

    # Get the list of IPs from the "mal_ip" table
    cursor.execute("SELECT DISTINCT mal_ip.Source, mal_ip.Destination FROM mal_ip")
    mal_ips = [(row[0], row[1]) for row in cursor.fetchall()]

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
            if ipaddress.ip_address(ip[0]).is_private:
                output = subprocess.check_output(["arp", "-a", ip[0]])
                mac_address = output.decode("utf-8").split()[3]
                ip_mac_mappings.append((ip[0], mac_address))
        except (subprocess.CalledProcessError, ValueError):
            pass
    # Render the index.html template with the list of blocked websites and MAC addresses
    return render_template(
        "firewall.html",
        blocked_websites=blocked_websites,
        blocked_mac_addresses=blocked_mac_addresses,
        ip_mac_mappings=ip_mac_mappings,
        highband_ips=highband_ips,
    )


if __name__ == "__main__":
    app.run(debug=True)
