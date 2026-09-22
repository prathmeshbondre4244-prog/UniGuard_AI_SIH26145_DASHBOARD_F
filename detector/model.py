from pathlib import Path
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest

FEATURES = [
    "packet_count",
    "byte_count",
    "duration",
    "packets_per_sec",
    "bytes_per_sec",
    "avg_packet_size",
    "min_packet_size",
    "max_packet_size",
    "inter_arrival_mean",
    "inter_arrival_std",
    "destination_port_diversity",
    "destination_host_diversity",
    "connection_failure_rate",
]

MODEL_PATH = Path(__file__).resolve().parent / "models.joblib"


class Detector:
    def __init__(self):
        self.rf = None
        self.iso = None
        self.load()

    def load(self):
        if MODEL_PATH.exists():
            bundle = joblib.load(MODEL_PATH)
            self.rf = bundle["rf"]
            self.iso = bundle["iso"]

    def ready(self):
        return self.rf is not None and self.iso is not None

    def _vector(self, features):
        return np.array([[float(features.get(k, 0.0)) for k in FEATURES]])

    def predict(self, features):
        if not self.ready():
            raise RuntimeError("ML model not trained. Run: python scripts/train_model.py")

        x = self._vector(features)
        label = str(self.rf.predict(x)[0])
        probabilities = self.rf.predict_proba(x)[0]
        classes = list(self.rf.classes_)
        idx = classes.index(label)
        confidence = float(probabilities[idx])

        anomaly_raw = float(self.iso.decision_function(x)[0])
        anomaly_flag = int(self.iso.predict(x)[0]) == -1

        return {
            "label": label,
            "confidence": confidence,
            "anomaly": anomaly_flag,
            "anomaly_score": anomaly_raw,
        }
