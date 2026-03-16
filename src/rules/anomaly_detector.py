from pathlib import Path
import joblib
import pandas as pd


class AnomalyDetector:
    FEATURE_ORDER = [
        "proto",
        "packet_length",
        "src_port",
        "dst_port",
        "tcp_flags",
        "src_packet_count",
        "src_byte_count",
        "unique_dst_ports",
        "syn_count",
        "icmp_count",
        "is_syn",
        "is_icmp",
    ]

    def __init__(self, model_path="models/isolation_forest.pkl", threshold=-0.15):
        base_dir = Path(__file__).resolve().parents[2]
        self.model_path = base_dir / model_path
        self.threshold = threshold
        self.model = None
        self._load_model()

    def _load_model(self):
        if not self.model_path.exists():
            raise FileNotFoundError(f"Model not found: {self.model_path}")
        self.model = joblib.load(self.model_path)

    def analyze(self, features):
        if self.model is None:
            raise RuntimeError("Anomaly model is not loaded.")

        row = {name: features[name] for name in self.FEATURE_ORDER}
        X = pd.DataFrame([row], columns=self.FEATURE_ORDER)

        score = float(self.model.decision_function(X)[0])
        prediction = int(self.model.predict(X)[0])

        return {
            "score": score,
            "prediction": prediction,
            "is_anomaly": prediction == -1 and score < self.threshold,
        }