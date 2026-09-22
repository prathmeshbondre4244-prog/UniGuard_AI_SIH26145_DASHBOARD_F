# UniGuard AI - SIH26145 Prototype

A defensive, passive network-threat monitoring prototype for SIH 26145:
"AI-Based Detection of Cyber Threats in Unidirectional IP Traffic".

## What this prototype does

- Observes packets from a selected network interface.
- Builds short-lived network-flow features.
- Uses Random Forest for classification and Isolation Forest for anomaly detection.
- Adds transparent behavioral rules for common indicators.
- Produces explainable alerts.
- Displays live alerts and traffic statistics in a web dashboard.
- Does NOT send packets, scan networks, decrypt payloads, or block hosts.

## Important prototype note

This is a lab prototype. A normal laptop NIC is not a physical data diode. For the SIH demo, connect the monitoring interface to a real TAP/data-diode output or use a controlled lab capture source. The application itself is read-only.

The included model is trained on synthetic demonstration data so the project runs immediately. For a serious evaluation, train on CIC-IDS2017 or another approved labeled flow dataset and report measured metrics.

## Folder structure

backend/        FastAPI application
detector/      ML model + feature detection
network/       passive packet/flow capture
scripts/       model training
dashboard/     HTML/CSS/JS dashboard

## Windows setup

1. Install Python 3.11+.
2. Install Npcap from the official Npcap website if Scapy cannot capture packets.
3. Open PowerShell in this folder.
4. Create an environment:
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
5. Install packages:
   pip install -r requirements.txt
6. Train the demo model:
   python scripts\train_model.py
7. Start the server:
   python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
8. Open:
   http://127.0.0.1:8000

The dashboard can run without packet capture. To start live capture, select an interface and click Start Capture.

## Linux setup

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python scripts/train_model.py
sudo .venv/bin/python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000

Root/admin privileges may be required for packet capture.

## Interface selection

Run:

python -c "from scapy.all import get_if_list; print('\\n'.join(get_if_list()))"

Use the exact interface name shown by Scapy.

## API

GET /api/status
GET /api/alerts
GET /api/stats
POST /api/capture/start
POST /api/capture/stop
POST /api/capture/interface

POST /api/analyze/demo
POST /api/clear

The demo endpoint creates safe synthetic feature records for testing the dashboard and ML pipeline. It does not generate network traffic.

## Moving to CIC-IDS2017

Do not blindly map dataset columns. First inspect the exact dataset version and columns, then build a preprocessing script that maps selected flow features to:

packet_count
byte_count
duration
packets_per_sec
bytes_per_sec
avg_packet_size
min_packet_size
max_packet_size
inter_arrival_mean
inter_arrival_std
destination_port_diversity
destination_host_diversity
connection_failure_rate

Then retrain and evaluate with a held-out test set.

## Security

This project is intended for authorized, defensive monitoring in networks you own or are explicitly permitted to monitor.
