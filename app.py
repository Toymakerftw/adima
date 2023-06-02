from flask import Flask, render_template , request
from flask_socketio import SocketIO
from scheduler import start_scheduler
import psutil
import subprocess
import time
import sqlite3


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

@app.route('/unblock_device', methods=['POST'])
def unblock_device():
    mac = request.form.get('mac')

    # Unblock the MAC address using firewalld
    subprocess.run(['firewall-cmd', '--permanent', '--remove-rich-rule',
                    'rule family="ipv4" source address="{0}" drop'.format(mac)])
    subprocess.run(['firewall-cmd', '--reload'])

    # Return a JSON response
    return {'message': 'Device unblocked successfully'}

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
