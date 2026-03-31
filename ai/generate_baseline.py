import pandas as pd
import numpy as np
import os

def generate_baseline_data(output_file="baseline_flow_features.csv", num_samples=10000):
    """
    Generates synthetic baseline (normal) network flow features.
    These features match the typical profile of ordinary corporate/home network traffic.
    """
    print(f"Generating {num_samples} baseline flow samples...")
    
    # 1. Source and Destination Ports
    # Normal traffic often involves high ephemeral source ports to well-known destination ports (80, 443, 53)
    dst_ports = np.random.choice([80, 443, 53, 22], size=num_samples, p=[0.15, 0.70, 0.10, 0.05])
    src_ports = np.random.randint(49152, 65535, size=num_samples)
    
    # 2. Payload Size
    # Normal HTTPS traffic has varied payload, DNS has small payload
    payload_size = np.zeros(num_samples)
    for i in range(num_samples):
        if dst_ports[i] == 443:
            payload_size[i] = np.random.normal(loc=1500, scale=300)
        elif dst_ports[i] == 80:
            payload_size[i] = np.random.normal(loc=800, scale=200)
        elif dst_ports[i] == 53:
            payload_size[i] = np.random.normal(loc=64, scale=10)
        else: # 22
            payload_size[i] = np.random.normal(loc=512, scale=100)
            
    payload_size = np.maximum(0, payload_size) # ensure non-negative
    
    # 3. Packet Count
    # Normal flows typically have proportional packet counts
    packet_count = np.maximum(1, (payload_size / 800) + np.random.normal(loc=2, scale=1, size=num_samples)).astype(int)
    
    # 4. Duration (ms)
    duration_ms = np.random.lognormal(mean=np.log(200), sigma=1.0, size=num_samples)
    
    # Create DataFrame
    df = pd.DataFrame({
        "src_port": src_ports,
        "dst_port": dst_ports,
        "payload_size": payload_size.astype(int),
        "packet_count": packet_count,
        "duration_ms": duration_ms
    })
    
    os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
    df.to_csv(output_file, index=False)
    print(f"Saved baseline data to {output_file}")
    
if __name__ == "__main__":
    generate_baseline_data("baseline_flow_features.csv")
