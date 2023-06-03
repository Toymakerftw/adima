import json
import plotly.graph_objects as go
import requests
import sqlite3

# Anomalies map
def plot_ip_locations(ips):
    outputLat = []
    outputLon = []

    for ip in ips:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = json.loads(response.text)

        if data['status'] == 'success':
            lat = data['lat']
            lon = data['lon']
            outputLat.append(lat)
            outputLon.append(lon)

    mapbox_access_token = 'YOUR_MAPBOX_ACCESS_TOKEN'

    data = go.Scattermapbox(
        lat=outputLat,
        lon=outputLon,
        mode='markers',
        marker=go.scattermapbox.Marker(
            size=14,
            color='rgb(255, 0, 0)',
            opacity=0.7
        ),
        text=ips
    )

    layout = go.Layout(
        autosize=True,
        height=600,
        hovermode='closest',
        margin=dict(l=30, r=30, b=40, t=0),
        showlegend=False,
        plot_bgcolor='#fffcfc',
        paper_bgcolor='#fffcfc',
        mapbox=dict(
            accesstoken='pk.eyJ1IjoiYWxleGZyYW5jb3ciLCJhIjoiY2pnbHlncDF5MHU4OTJ3cGhpNjE1eTV6ZCJ9.9RoVOSpRXa2JE9j_qnELdw',
            bearing=0,
            center=dict(
                lat=sum(outputLat) / len(outputLat),
                lon=sum(outputLon) / len(outputLon)
            ),
            pitch=0,
            style='dark',
            zoom=1,
        )
    )

    fig = go.Figure(data=data, layout=layout)
    fig.show()


ips = []  # Empty list to store IP addresses

# Create a SQLite database connection
conn = sqlite3.connect('triage.db')
cursor = conn.cursor()
cursor.execute("SELECT ip FROM anomalies")
ips = [row[0] for row in cursor.fetchall()]

cursor.close()
conn.close()

#ip_response = requests.get("https://ipv6.icanhazip.com/")
#device_ip = ip_response.text.strip()
#ips.append(device_ip)

#ips = ['2409:4073:116:9192:eddc:6da3:a5a3:39c6']
plot_ip_locations(ips)
