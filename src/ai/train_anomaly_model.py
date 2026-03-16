from pathlib import Path
import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest


FEATURE_COLUMNS = [
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


def train_model(csv_path="data/training_features.csv", model_output="models/isolation_forest.pkl"):
    base_dir = Path(__file__).resolve().parents[2]  # project root
    csv_file = base_dir / csv_path
    model_file = base_dir / model_output

    if not csv_file.exists():
        raise FileNotFoundError(f"Training CSV not found: {csv_file}")

    df = pd.read_csv(csv_file)

    missing = [col for col in FEATURE_COLUMNS if col not in df.columns]
    if missing:
        raise ValueError(f"Missing required feature columns: {missing}")

    X = df[FEATURE_COLUMNS]

    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42,
    )
    model.fit(X)

    model_file.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_file)

    print(f"[+] Model trained and saved to: {model_file}")


if __name__ == "__main__":
    train_model()