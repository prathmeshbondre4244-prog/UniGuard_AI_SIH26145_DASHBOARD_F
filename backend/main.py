from pathlib import Path
import time
import threading
from collections import deque, Counter
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from detector.model import Detector
from network.sniffer import FlowTable, PassiveSniffer

BASE = Path(__file__).resolve().parents[1]
DASHBOARD = BASE / "dashboard"

app = FastAPI(title="UniGuard AI", version="0.1.0")
app.mount(
    "/dashboard",
    StaticFiles(directory=str(DASHBOARD), html=True),
    name="dashboard"
)

@app.get("/dashboard")
def dashboard():
    return FileResponse(DASHBOARD / "index.html")

detector = Detector()
flow_table = FlowTable()
sniffer = PassiveSniffer(flow_table)

alerts = deque(maxlen=500)
recent_flows = deque(maxlen=300)
stats = {
    "packets": 0,
    "flows": 0,
    "threats": 0,
    "start_time": time.time(),
}
lock = threading.Lock()

class InterfaceRequest(BaseModel):
    interface: str

def severity(label, confidence, anomaly):
    if label in {"DDoS", "Data Exfiltration"} and confidence >= 0.75:
        return "CRITICAL"
    if label != "Normal" and (confidence >= 0.70 or anomaly):
        return "HIGH"
    if label != "Normal":
        return "MEDIUM"
    return "SAFE"

def evidence(features, label):
    reasons = []
    if features["destination_port_diversity"] >= 5:
        reasons.append("High destination-port diversity")
    if features["packets_per_sec"] >= 100:
        reasons.append("Rapid packet/connection activity")
    if features["connection_failure_rate"] >= 0.5:
        reasons.append("High connection-failure rate")
    if features["bytes_per_sec"] >= 5_000_000:
        reasons.append("High outbound traffic rate")
    if features["inter_arrival_std"] <= 0.1 and features["packet_count"] >= 10:
        reasons.append("Regular communication timing")
    if features["avg_packet_size"] >= 800 and features["packet_count"] >= 50:
        reasons.append("Large-volume transfer pattern")
    if not reasons:
        reasons.append(f"Traffic pattern classified as {label}")
    return reasons[:4]

def analyze_flow(flow):
    if not detector.ready():
        raise RuntimeError("Model missing. Run scripts/train_model.py")

    # Small source-level diversity improvement using current flow.
    result = detector.predict(flow)
    label = result["label"]
    conf = result["confidence"]
    sev = severity(label, conf, result["anomaly"])
    ev = evidence(flow, label)

    if label != "Normal" or result["anomaly"]:
        alert = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "flow_id": f'{flow["source"]}:{flow["source_port"]}-{flow["destination"]}:{flow["destination_port"]}',
            "source": flow["source"],
            "destination": flow["destination"],
            "protocol": flow["protocol"],
            "threat_type": label if label != "Normal" else "Anomalous Behaviour",
            "confidence": round(conf * 100, 2),
            "severity": sev,
            "evidence": ev,
            "anomaly_score": round(result["anomaly_score"], 4),
        }
        with lock:
            alerts.appendleft(alert)
            stats["threats"] += 1
        return alert
    return None

def capture_worker():
    last_packets = 0
    while True:
        time.sleep(2)
        if not sniffer.running and not flow_table.flows:
            continue
        flows = flow_table.snapshot()
        if not flows:
            continue
        with lock:
            stats["flows"] += len(flows)
            stats["packets"] += sum(f["packet_count"] for f in flows)
            recent_flows.extend(flows)
        for flow in flows:
            try:
                analyze_flow(flow)
            except Exception as exc:
                print("Analysis error:", exc)

threading.Thread(target=capture_worker, daemon=True).start()

@app.get("/")
def home():
    return FileResponse(DASHBOARD / "index.html")

@app.get("/api/status")
def status():
    return {
        "model_ready": detector.ready(),
        "capture_running": sniffer.running,
        "interface": sniffer.interface,
        "uptime_seconds": round(time.time() - stats["start_time"], 1),
        "one_way_mode": True,
        "return_path": "NOT USED",
    }

@app.get("/api/alerts")
def get_alerts():
    with lock:
        return list(alerts)

@app.get("/api/stats")
def get_stats():
    with lock:
        return dict(stats)

@app.get("/api/flows")
def get_flows():
    with lock:
        return list(recent_flows)[-100:]

@app.post("/api/capture/interface")
def set_interface(req: InterfaceRequest):
    if sniffer.running:
        raise HTTPException(400, "Stop capture before changing interface.")
    sniffer.interface = req.interface.strip()
    return {"ok": True, "interface": sniffer.interface}

@app.post("/api/capture/start")
def start_capture():
    if not detector.ready():
        raise HTTPException(500, "Train the model first: python scripts/train_model.py")
    if not sniffer.interface:
        raise HTTPException(400, "Select an interface first.")
    sniffer.start(sniffer.interface)
    return {"ok": True, "message": "Passive capture started."}

@app.post("/api/capture/stop")
def stop_capture():
    sniffer.stop()
    return {"ok": True, "message": "Capture stopped."}

@app.post("/api/clear")
def clear_alerts():
    with lock:
        alerts.clear()
        stats["threats"] = 0
        stats["packets"] = 0
        stats["flows"] = 0
        recent_flows.clear()
    return {"ok": True}

@app.post("/api/analyze/demo")
def demo():
    # Safe synthetic feature records; this does not send packets.
    demos = [
        {
            "source": "10.10.0.20", "destination": "10.10.0.10", "protocol": "TCP",
            "source_port": 50001, "destination_port": 443,
            "packet_count": 120, "byte_count": 90000, "duration": 10,
            "packets_per_sec": 12, "bytes_per_sec": 9000, "avg_packet_size": 750,
            "min_packet_size": 500, "max_packet_size": 1000,
            "inter_arrival_mean": 0.08, "inter_arrival_std": 0.03,
            "destination_port_diversity": 1, "destination_host_diversity": 1,
            "connection_failure_rate": 0.05,
        },
        {
            "source": "10.10.0.55", "destination": "10.10.0.10", "protocol": "TCP",
            "source_port": 40000, "destination_port": 22,
            "packet_count": 70, "byte_count": 50000, "duration": 1,
            "packets_per_sec": 70, "bytes_per_sec": 50000, "avg_packet_size": 714,
            "min_packet_size": 60, "max_packet_size": 1100,
            "inter_arrival_mean": 0.01, "inter_arrival_std": 0.02,
            "destination_port_diversity": 18, "destination_host_diversity": 8,
            "connection_failure_rate": 0.75,
        },
        {
            "source": "10.10.0.77", "destination": "10.10.0.10", "protocol": "UDP",
            "source_port": 41000, "destination_port": 53,
            "packet_count": 1800, "byte_count": 1500000, "duration": 5,
            "packets_per_sec": 360, "bytes_per_sec": 300000, "avg_packet_size": 833,
            "min_packet_size": 400, "max_packet_size": 1200,
            "inter_arrival_mean": 0.002, "inter_arrival_std": 0.003,
            "destination_port_diversity": 1, "destination_host_diversity": 2,
            "connection_failure_rate": 0.1,
        }
    ]
    results = []
    for f in demos:
        a = analyze_flow(f)
        results.append(a or {"threat_type": "Normal", "source": f["source"]})
    return results
