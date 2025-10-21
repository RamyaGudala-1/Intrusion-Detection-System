# src/ids_cli.py
import argparse
import os
import time
import pickle
import pandas as pd

from scapy.all import sniff
from extract_features import packet_to_features, FEATURE_COLUMNS
from detect_intrusion import detect

ROOT = os.path.join(os.path.dirname(__file__), "..")
KDD_DATA_PATH = os.path.join(ROOT, "data", "kddtrain.txt")
ENC_PATH = os.path.join(ROOT, "models", "encoders.pkl")

def load_encoders():
    if not os.path.exists(ENC_PATH):
        return None
    try:
        with open(ENC_PATH, "rb") as f:
            return pickle.load(f)
    except Exception:
        return None

def kdd_row_to_features(row, encoders):
    # Turn pandas Series (KDD row) into a DataFrame matching FEATURE_COLUMNS.
    features = {c: 0 for c in FEATURE_COLUMNS}
    for c in FEATURE_COLUMNS:
        if c in row.index:
            try:
                val = float(row[c])
                if val.is_integer():
                    features[c] = int(val)
                else:
                    features[c] = float(val)
            except Exception:
                features[c] = 0

    # Map categorical columns using encoders if available
    le_protocol = le_service = le_flag = None
    enc = encoders or {}
    le_protocol = enc.get('protocol')
    le_service = enc.get('service')
    le_flag = enc.get('flag')

    def safe_transform(le, val):
        if le is None:
            return 0
        try:
            if val in le.classes_:
                return int(le.transform([val])[0])
            low = str(val).lower()
            for i, c in enumerate(le.classes_):
                if str(c).lower() == low:
                    return int(i)
        except Exception:
            pass
        return 0

    proto_raw = row.get('protocol_type', 'other')
    serv_raw = row.get('service', 'other')
    flag_raw = row.get('flag', 'SF')

    features['protocol_type'] = safe_transform(le_protocol, proto_raw)
    features['service'] = safe_transform(le_service, serv_raw)
    features['flag'] = safe_transform(le_flag, flag_raw)

    # Add dummy IP/port for logging clarity
    features['src_ip'] = "10.0.0.99"
    features['dst_ip'] = "192.168.0.1"
    features['src_port'] = 12345
    features['dst_port'] = 80

    return pd.DataFrame([features])

def stimulate_from_dataset(count=5, delay=0.1):
    if not os.path.exists(KDD_DATA_PATH):
        print("[!] KDD dataset not found at", KDD_DATA_PATH)
        return

    cols = FEATURE_COLUMNS + ["label", "difficulty"]
    try:
        df = pd.read_csv(KDD_DATA_PATH, names=cols)
    except Exception as e:
        print("[!] Failed to read KDD file:", e)
        return

    # attacks = df[df['label'] != 'normal']
    attacks = df
    if attacks.empty:
        print("[!] No attack rows found in dataset.")
        return

    enc = load_encoders()
    count = min(count, len(attacks))
    sampled = attacks.sample(n=count, random_state=42)

    print(f"[*] Stimulating {count} attack samples...")
    for _, row in sampled.iterrows():
        try:
            features = kdd_row_to_features(row, enc)
            pred, prob, consec = detect(features)
        except Exception as e:
            print("[!] Error processing sample row:", e)
        time.sleep(delay)

def start_sniffing(iface=None):
    print(f"[*] Listening for packets on interface: {iface} ...")
    def process_packet(pkt):
        try:
            features = packet_to_features(pkt)
            pred, prob, consec = detect(features)
        except Exception as e:
            print("[!] Error processing live packet:", e)
    sniff(prn=process_packet, store=0, iface=iface)

def main():
    parser = argparse.ArgumentParser(description="Python IDS CLI")
    parser.add_argument("--iface", help="Interface for sniffing (optional)", default=None)
    parser.add_argument("--stimulate-attack", help="true/false", default="false")
    parser.add_argument("--stimulate-count", type=int, default=50000)
    args = parser.parse_args()

    stimulate = str(args.stimulate_attack).lower() in ("1", "true", "yes", "y")
    if stimulate:
        stimulate_from_dataset(count=args.stimulate_count)

    if args.iface:
        start_sniffing(args.iface)
    elif not stimulate:
        print("[*] Nothing to do. Provide --iface for live sniffing or --stimulate-attack true to simulate.")

if __name__ == "__main__":
    main()
