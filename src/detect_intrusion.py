# src/detect_intrusion.py
import pickle
import pandas as pd
from datetime import datetime
import os
import json
import re

ROOT = os.path.join(os.path.dirname(__file__), "..")
MODEL_PATH = os.path.join(ROOT, "models", "rf_model.pkl")
LOG_FILE = os.path.join(ROOT, "logs", "intrusion_logs.txt")
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)

ALERT_THRESHOLD = 0.5
CONSECUTIVE_REQUIRED = 3

consec_count = 0

def fmt_prob(prob):
    try:
        return f"N:{prob[0]*100:05.1f}% A:{prob[1]*100:05.1f}%"
    except Exception:
        return str(prob)

def one_line_console(record):
    ts = record.get("timestamp", "")[11:19]
    feat = record.get("packet_features", {})
    proto_num = feat.get("protocol_type", 0)
    proto = {0: "OTHER", 1: "TCP", 2: "UDP"}.get(proto_num, f"PROTO:{proto_num}")
    src = f"{feat.get('src_ip','?.?.?.?')}:{feat.get('src_port','?')}"
    dst = f"{feat.get('dst_ip','?.?.?.?')}:{feat.get('dst_port','?')}"
    size = feat.get("src_bytes", 0)
    pred = record.get("prediction", "unknown").upper()
    prob = fmt_prob([record.get("prob_normal", 0.0), record.get("prob_attack", 0.0)])
    consec = record.get("consecutive_high_prob", 0)
    return f"[{ts}] {proto} {src} -> {dst} | Size: {size} bytes | {pred} | {prob} | consec={consec}"

def expanded_alert_console(record):
    # Append to JSON-lines log
    feat = record.get("packet_features", {})
    ts = record.get("timestamp", "")
    proto_num = feat.get("protocol_type", 0)
    proto = {0: "OTHER", 1: "TCP", 2: "UDP"}.get(proto_num, f"PROTO:{proto_num}")
    src = f"{feat.get('src_ip','?.?.?.?')}:{feat.get('src_port','?')}"
    dst = f"{feat.get('dst_ip','?.?.?.?')}:{feat.get('dst_port','?')}"
    size = feat.get("src_bytes", 0)
    pred = record.get("prediction", "unknown").upper()
    pnorm = record.get("prob_normal", 0.0) * 100.0
    patt = record.get("prob_attack", 0.0) * 100.0
    cf = record.get("consecutive_high_prob", 0)
    lines = [
        "==================== INTRUSION ALERT ====================",
        f"Time       : {ts}",
        f"Source     : {src}",
        f"Destination: {dst}",
        f"Protocol   : {proto}",
        f"Length     : {size} bytes",
        "",
        f"Prediction : {pred} (N:{pnorm:.1f}% / A:{patt:.1f}%)",
        f"Consecutive suspicious packets: {cf}",
        "",
        "Top features:",
        f"  - protocol_type : {feat.get('protocol_type')}",
        f"  - service       : {feat.get('service')}",
        f"  - flag          : {feat.get('flag')}",
        f"  - src_bytes     : {feat.get('src_bytes')}",
        f"  - dst_bytes     : {feat.get('dst_bytes')}",
        "========================================================"
    ]
    try:
        with open(LOG_FILE, "a") as f:
            # f.write(json.dumps(record) + "\n")
            f.write("\n".join(lines))
    except Exception as e:
        print("[!] Failed to write log:", e)    
    return "\n".join(lines)

def detect(packet_features: pd.DataFrame):
    """
    packet_features: DataFrame with model features (columns matching training) plus optional logging fields.
    Returns: pred (0/1), prob [p_normal, p_attack], consecutive_count
    """
    global consec_count

    # Ensure we don't pass logging columns to model
    input_df = packet_features.copy()
    for c in ["src_ip", "dst_ip", "src_port", "dst_port"]:
        if c in input_df.columns:
            input_df = input_df.drop(columns=[c])

    # Also ensure columns exactly match model training order (model trained on 41 columns)
    # If model was trained with pandas DataFrame with column names, scikit-learn checks feature names.
    # So we rely on same FEATURE_COLUMNS ordering at extraction time.
    prob = model.predict_proba(input_df)[0]
    pred = int(model.predict(input_df)[0])

    prob_attack = float(prob[1])
    if prob_attack >= ALERT_THRESHOLD:
        consec_count += 1
    else:
        consec_count = 0

    # Build record using original packet_features (with IP/port if present)
    record = {
        "timestamp": str(datetime.now()),
        "packet_features": packet_features.to_dict(orient="records")[0],
        "prediction": "attack" if pred == 1 else "normal",
        "prob_normal": float(prob[0]),
        "prob_attack": float(prob[1]),
        "consecutive_high_prob": int(consec_count)
    }


    # Console output
    try:
        print(one_line_console(record))
    except Exception:
        print(f"Packet prediction: {'attack' if pred==1 else 'normal'}, Probability: [{prob[0]:.3f} {prob[1]:.3f}], consecutive_high={consec_count}")

    if record["prob_attack"] >= ALERT_THRESHOLD and record["consecutive_high_prob"] >= CONSECUTIVE_REQUIRED:
        try:
            print(expanded_alert_console(record))
        except Exception:
            print(f"*** ALERT: Suspicious traffic (prob_attack={record['prob_attack']:.3f}) - consecutive={record['consecutive_high_prob']} ***")

    return pred, [float(prob[0]), float(prob[1])], int(consec_count)
