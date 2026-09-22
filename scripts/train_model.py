from pathlib import Path
import sys
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, classification_report

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from detector.model import FEATURES, MODEL_PATH

rng = np.random.default_rng(42)

def clip(a, lo=0.0, hi=None):
    a = np.maximum(a, lo)
    if hi is not None:
        a = np.minimum(a, hi)
    return a

def make_class(label, n):
    # Synthetic demonstration distributions only.
    duration = clip(rng.lognormal(0.3, 0.8, n), 0.01, 120)
    packet_count = clip(rng.lognormal(3.0, 1.0, n), 2, 50000)
    avg_size = clip(rng.normal(500, 180, n), 40, 1500)
    byte_count = packet_count * avg_size
    pps = packet_count / duration
    bps = byte_count / duration
    min_size = clip(avg_size - rng.normal(80, 30, n), 40, 1500)
    max_size = clip(avg_size + rng.normal(120, 60, n), 40, 1500)
    iat = clip(duration / packet_count, 0.00001, 10)
    iat_std = clip(iat * rng.uniform(0.1, 2.0, n), 0.00001, 10)
    ports = clip(rng.normal(2, 1.5, n), 1, 20)
    hosts = clip(rng.normal(1.5, 1.0, n), 1, 20)
    failures = clip(rng.beta(2, 8, n), 0, 1)

    if label == "Port Scan":
        duration = clip(rng.lognormal(-0.2, 0.6, n), 0.01, 20)
        packet_count = clip(rng.lognormal(2.2, 0.7, n), 2, 1000)
        pps = clip(packet_count / duration, 5, 10000)
        bps = clip((packet_count * avg_size) / duration, 100, 1e7)
        ports = clip(rng.normal(15, 5, n), 5, 100)
        hosts = clip(rng.normal(8, 3, n), 2, 100)
        failures = clip(rng.beta(8, 2, n), 0, 1)

    elif label == "DDoS":
        duration = clip(rng.lognormal(1.0, 0.7, n), 0.2, 300)
        packet_count = clip(rng.lognormal(9.0, 0.8, n), 1000, 1e7)
        pps = clip(packet_count / duration, 100, 1e6)
        bps = clip((packet_count * avg_size) / duration, 1e5, 1e9)
        ports = clip(rng.normal(2, 1, n), 1, 10)
        hosts = clip(rng.normal(2, 1, n), 1, 10)

    elif label == "C2 Beaconing":
        duration = clip(rng.normal(80, 15, n), 20, 180)
        packet_count = clip(rng.normal(80, 20, n), 10, 300)
        pps = packet_count / duration
        bps = (packet_count * avg_size) / duration
        iat = clip(rng.normal(1.0, 0.15, n), 0.1, 5)
        iat_std = clip(rng.normal(0.08, 0.03, n), 0.001, 1)
        ports = clip(rng.normal(1, 0.3, n), 1, 3)
        hosts = clip(rng.normal(1, 0.3, n), 1, 3)

    elif label == "DNS Tunnelling":
        duration = clip(rng.lognormal(1.0, 0.5, n), 1, 100)
        packet_count = clip(rng.lognormal(5.0, 0.5, n), 20, 3000)
        avg_size = clip(rng.normal(900, 100, n), 200, 1500)
        byte_count = packet_count * avg_size
        pps = packet_count / duration
        bps = byte_count / duration
        ports = clip(rng.normal(1, 0.3, n), 1, 3)
        hosts = clip(rng.normal(2, 1, n), 1, 10)

    elif label == "Data Exfiltration":
        duration = clip(rng.lognormal(2.5, 0.6, n), 10, 1000)
        packet_count = clip(rng.lognormal(8, 0.8, n), 500, 1e7)
        avg_size = clip(rng.normal(1200, 120, n), 400, 1500)
        byte_count = packet_count * avg_size
        pps = packet_count / duration
        bps = byte_count / duration
        ports = clip(rng.normal(1, 0.5, n), 1, 5)
        hosts = clip(rng.normal(1, 0.5, n), 1, 5)

    else:  # Normal
        pass

    return pd.DataFrame({
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration": duration,
        "packets_per_sec": pps,
        "bytes_per_sec": bps,
        "avg_packet_size": avg_size,
        "min_packet_size": min_size,
        "max_packet_size": max_size,
        "inter_arrival_mean": iat,
        "inter_arrival_std": iat_std,
        "destination_port_diversity": ports,
        "destination_host_diversity": hosts,
        "connection_failure_rate": failures,
        "label": label,
    })

labels = ["Normal", "Port Scan", "DDoS", "C2 Beaconing", "DNS Tunnelling", "Data Exfiltration"]
df = pd.concat([make_class(label, 1200) for label in labels], ignore_index=True)

X_train, X_test, y_train, y_test = train_test_split(
    df[FEATURES], df["label"], test_size=0.25, random_state=42, stratify=df["label"]
)

rf = RandomForestClassifier(
    n_estimators=250,
    random_state=42,
    class_weight="balanced",
    n_jobs=-1,
    max_depth=18,
)
rf.fit(X_train, y_train)

iso = IsolationForest(
    n_estimators=250,
    contamination=0.08,
    random_state=42,
)
iso.fit(df[df["label"] == "Normal"][FEATURES])

pred = rf.predict(X_test)
acc = accuracy_score(y_test, pred)
p, r, f1, _ = precision_recall_fscore_support(y_test, pred, average="weighted", zero_division=0)

print(f"Demo model accuracy: {acc:.4f}")
print(f"Weighted precision:   {p:.4f}")
print(f"Weighted recall:      {r:.4f}")
print(f"Weighted F1:          {f1:.4f}")
print(classification_report(y_test, pred, zero_division=0))

joblib.dump({"rf": rf, "iso": iso}, MODEL_PATH)
print(f"Saved: {MODEL_PATH}")
print("NOTE: These metrics are for synthetic demonstration data, not CIC-IDS2017.")
