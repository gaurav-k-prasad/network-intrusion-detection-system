import asyncio
import json
import os
from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.responses import HTMLResponse
from sse_starlette.sse import EventSourceResponse
from pydantic import BaseModel
import sys

app = FastAPI(title="NIDS Dashboard API")

LOG_FILE_PATH = "/home/gaurav/coding/NIDS/nids.log"
DASHBOARD_HTML_PATH = "/home/gaurav/coding/NIDS/dashboard.html"

# In-memory storage or queue for broadcasting logs to SSE clients
clients = []

@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    try:
        with open(DASHBOARD_HTML_PATH, "r") as f:
            return f.read()
    except FileNotFoundError:
        return HTMLResponse("<h1>dashboard.html not found!</h1>", status_code=404)

async def tail_log_file():
    """Tails the log file and yields new lines as they are appended."""
    if not os.path.exists(LOG_FILE_PATH):
        # Create if not exists
        open(LOG_FILE_PATH, 'a').close()
        
    with open(LOG_FILE_PATH, "r") as f:
        # Seek to the end of the file
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                await asyncio.sleep(0.5)
                if os.path.getsize(LOG_FILE_PATH) < f.tell():
                    f.seek(0)
                continue
            
            yield line

@app.get("/api/logs/stream")
async def log_stream(request: Request):
    """Server-Sent Events endpoint that streams new log lines to connected clients."""
    async def event_generator():
        async for line in tail_log_file():
            if await request.is_disconnected():
                break
            
            try:
                # Try parsing it to ensure it's valid JSON before sending
                data = json.loads(line)
                yield {
                    "event": "log",
                    "data": json.dumps(data)
                }
            except json.JSONDecodeError:
                # Skip invalid lines
                pass

    return EventSourceResponse(event_generator())


# --- ML Integration placeholders ---

class FlowFeatures(BaseModel):
    # These will map to whatever we extract in Go or synthetic data
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    payload_size: int
    packet_count: int
    duration_ms: float
    protocol: str

import pickle
import numpy as np

MODEL_PATH = "/home/gaurav/coding/NIDS/ai/model.pkl"

@app.post("/api/predict")
async def predict_anomaly(features: FlowFeatures, background_tasks: BackgroundTasks):
    """
    Called by the Go NIDS module to predict if a flow is an anomaly.
    """
    try:
        if not os.path.exists(MODEL_PATH):
            return {"status": "error", "message": "Model not trained yet."}
            
        with open(MODEL_PATH, "rb") as f:
            model = pickle.load(f)
            
        # Extract numerical features for the model (simplified example)
        # We need to match the feature array format used in training
        # [src_port, dst_port, payload_size, packet_count, duration_ms]
        feature_vector = np.array([[
            features.src_port,
            features.dst_port,
            features.payload_size,
            features.packet_count,
            features.duration_ms
        ]])
        
        # Scikit-Learn IsolationForest returns -1 for anomalies, 1 for normal
        prediction = model.predict(feature_vector)[0]
        
        is_anomaly = (prediction == -1)
        
        if is_anomaly:
            log_entry = {
                "time": "now", # We'll let Go dictate time ideally, but here we can add it or just append
                "level": "WARN",
                "msg": "Zero-Day Anomaly Detected",
                "module": "ai_engine",
                "NetFlow": f"{features.src_ip}->{features.dst_ip}",
                "TcpFlow": f"{features.src_port}->{features.dst_port}",
                "tag": "AI_ANOMALY"
            }
            background_tasks.add_task(append_log, log_entry)
            
        return {"anomaly": bool(is_anomaly)}
        
    except Exception as e:
        return {"status": "error", "message": str(e)}

def append_log(entry):
    import datetime
    entry["time"] = datetime.datetime.utcnow().isoformat() + "Z"
    with open(LOG_FILE_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
