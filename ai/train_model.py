import pandas as pd
import pickle
from sklearn.ensemble import IsolationForest
import sys

def train_model(dataset_path="baseline_flow_features.csv", model_output="model.pkl"):
    print(f"Loading dataset from {dataset_path}...")
    try:
        df = pd.read_csv(dataset_path)
    except FileNotFoundError:
        print(f"Error: {dataset_path} not found. Run generate_baseline.py first.")
        sys.exit(1)
        
    print(f"Dataset shape: {df.shape}")
    
    # Features used for the model
    # Should match: [src_port, dst_port, payload_size, packet_count, duration_ms]
    X = df[["src_port", "dst_port", "payload_size", "packet_count", "duration_ms"]].values
    
    print("Training Isolation Forest model on baseline data...")
    # Isolation Forest parameters:
    # contamination = 'auto' or a very small percentage (e.g., 0.01 for 1% expected anomalies in real life)
    model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
    model.fit(X)
    
    with open(model_output, "wb") as f:
        pickle.dump(model, f)
        
    print(f"Model trained successfully and saved to {model_output}")

if __name__ == "__main__":
    train_model(
        "baseline_flow_features.csv",
        "model.pkl"
    )
