import sqlite3
import subprocess
import re

# Connect to SQLite database
conn = sqlite3.connect('triage.db')
cursor = conn.cursor()

# Create mal_mac table if it doesn't exist
cursor.execute('''
    CREATE TABLE IF NOT EXISTS mal_mac (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT UNIQUE,
        mac TEXT UNIQUE
    )
''')

# Select all IP addresses from mal_node table
cursor.execute('SELECT ip FROM mal_node')
ip_addresses = cursor.fetchall()

for ip in ip_addresses:
    ip = ip[0]

    # Execute arp command to retrieve MAC address
    command = f'arp -a {ip}'
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    output = result.stdout

    # Parse MAC address from arp command output
    mac = None
    if output:
        # Use regular expression to extract MAC address
        mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', output)
        if mac_match:
            mac = mac_match.group(0)

    # Insert IP and MAC address into mal_mac table if MAC is valid
    if mac:
        cursor.execute('INSERT OR IGNORE INTO mal_mac (ip, mac) VALUES (?, ?)', (ip, mac))
        conn.commit()

        # Print IP and MAC address on the terminal
        print(f'Inserted: IP: {ip}, MAC: {mac}')

# Close the database connection
conn.close()
