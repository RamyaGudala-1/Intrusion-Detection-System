# src/extract_features.py
import pandas as pd
import os
import pickle
from scapy.layers.inet import IP, TCP, UDP

# Feature columns used by model (same order)
FEATURE_COLUMNS = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes",
    "land","wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted","num_root","num_file_creations",
    "num_shells","num_access_files","num_outbound_cmds","is_host_login",
    "is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
    "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
    "srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate"
]

# Load encoders if present (for mapping strings to numeric labels consistent with training)
ENC_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "encoders.pkl")
try:
    with open(ENC_PATH, "rb") as f:
        _encoders = pickle.load(f)
        _le_protocol = _encoders.get('protocol')
        _le_service = _encoders.get('service')
        _le_flag = _encoders.get('flag')
except Exception:
    _le_protocol = _le_service = _le_flag = None

def safe_encode(le, value):
    if le is None:
        return 0
    try:
        if value in le.classes_:
            return int(le.transform([value])[0])
        low = str(value).lower()
        for i, c in enumerate(le.classes_):
            if str(c).lower() == low:
                return int(i)
    except Exception:
        pass
    return 0

def packet_to_features(pkt):
    """
    Returns a pandas DataFrame with one row:
      - Columns used by model (FEATURE_COLUMNS)
      - Additional logging fields added to the dict: src_ip, dst_ip, src_port, dst_port
    """
    # Base model features initialized to 0
    feat = {c: 0 for c in FEATURE_COLUMNS}

    # Basic numeric fields
    feat['duration'] = 0
    try:
        pkt_len = len(pkt)
    except Exception:
        pkt_len = 0
    feat['src_bytes'] = pkt_len
    feat['dst_bytes'] = pkt_len

    # Protocol mapping (string name -> encoder)
    proto_name = "other"
    if pkt.haslayer(TCP):
        proto_name = "tcp"
    elif pkt.haslayer(UDP):
        proto_name = "udp"

    feat['protocol_type'] = safe_encode(_le_protocol, proto_name)
    feat['service'] = safe_encode(_le_service, "other")
    feat['flag'] = safe_encode(_le_flag, "SF")

    if pkt.haslayer(IP):
        try:
            feat['src_ip'] = pkt[IP].src
            feat['dst_ip'] = pkt[IP].dst
        except Exception:
            feat['src_ip'] = "?.?.?.?"
            feat['dst_ip'] = "?.?.?.?"
    else:
        feat['src_ip'] = "?.?.?.?"
        feat['dst_ip'] = "?.?.?.?"

    if pkt.haslayer(TCP) or pkt.haslayer(UDP):
        try:
            feat['src_port'] = pkt.sport
            feat['dst_port'] = pkt.dport
        except Exception:
            feat['src_port'] = "?"
            feat['dst_port'] = "?"
    else:
        feat['src_port'] = "?"
        feat['dst_port'] = "?"

    # Return DataFrame with all keys (model features + logging fields)
    return pd.DataFrame([feat])
