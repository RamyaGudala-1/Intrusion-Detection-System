# src/evaluate_model.py
"""
Evaluate saved RF model on a KDD/NSL-KDD test file.

Usage:
    python src/evaluate_model.py <path-to-test-file>

Supports .txt and .arff files (common formats from NSL-KDD / KDD datasets).
Writes summary JSON and per-row CSV to ../logs/.
"""
import os
import sys
import json
import pickle
import pandas as pd
import numpy as np
from io import StringIO
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score
)

ROOT = os.path.join(os.path.dirname(__file__), "..")
MODELS_DIR = os.path.join(ROOT, "models")
LOG_DIR = os.path.join(ROOT, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

MODEL_PATH = os.path.join(MODELS_DIR, "rf_model.pkl")
ENC_PATH = os.path.join(MODELS_DIR, "encoders.pkl")

# exact feature columns used for training (41 features)
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

ALL_COLUMNS = FEATURE_COLUMNS + ["label", "difficulty"]

def load_model_and_encoders():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Model not found at {MODEL_PATH}. Run train_model.py first.")
    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)
    encoders = None
    if os.path.exists(ENC_PATH):
        with open(ENC_PATH, "rb") as f:
            encoders = pickle.load(f)
    return model, encoders

def read_kdd_file(path):
    """
    Read a KDD/NSL-KDD file (.txt or .arff) into a DataFrame using ALL_COLUMNS names.
    For .arff: skip @ and % header lines and parse the data lines as CSV.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(path)

    ext = os.path.splitext(path)[1].lower()
    if ext == ".arff":
        # read and strip ARFF header lines (starting with @ or %)
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data_lines = []
            for line in f:
                s = line.strip()
                if not s:
                    continue
                # skip comment and attribute/relational header
                if s.startswith("@") or s.startswith("%"):
                    continue
                data_lines.append(s)
        csv_text = "\n".join(data_lines)
        df = pd.read_csv(StringIO(csv_text), names=ALL_COLUMNS)
    else:
        # fallback: try to read as CSV with names
        df = pd.read_csv(path, names=ALL_COLUMNS)
    return df

def prepare_X_y(df, encoders):
    """
    Convert dataframe to X (features) and y (binary label 0=normal,1=attack).
    Uses encoders to transform protocol/service/flag to numeric indices.
    """
    # ensure required columns exist
    missing = [c for c in ALL_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Input file missing columns (expected): {missing}")

    X = df[FEATURE_COLUMNS].copy()

    # Cast numeric columns to float (safe)
    for c in FEATURE_COLUMNS:
        # some columns may be non-numeric in strings in .arff => coerce
        X[c] = pd.to_numeric(X[c], errors="coerce").fillna(0)

    # Apply saved label encoders if present (they were applied during training)
    if encoders:
        # protocol
        le = encoders.get("protocol")
        if le is not None:
            # original data uses textual names like 'tcp','udp','icmp' -> need to map
            # If column is textual, transform; if numeric already, leave as-is
            if X['protocol_type'].dtype == object:
                X['protocol_type'] = X['protocol_type'].apply(lambda v: safe_transform(le, v))
        # service
        le = encoders.get("service")
        if le is not None:
            if X['service'].dtype == object:
                X['service'] = X['service'].apply(lambda v: safe_transform(le, v))
        # flag
        le = encoders.get("flag")
        if le is not None:
            if X['flag'].dtype == object:
                X['flag'] = X['flag'].apply(lambda v: safe_transform(le, v))
    else:
        # If no encoders found, attempt to convert protocol/service/flag to numeric if already numeric, else 0
        for c in ("protocol_type","service","flag"):
            X[c] = pd.to_numeric(X[c], errors="coerce").fillna(0)

    # Target: map label strings -> binary
    y_raw = df['label'].astype(str).str.strip()
    y = y_raw.apply(lambda v: 0 if v == 'normal' else 1).astype(int)

    return X, y, y_raw

def safe_transform(le, val):
    """Transform with LabelEncoder le; unknown values map to 0"""
    try:
        if val in le.classes_:
            return int(le.transform([val])[0])
        # case-insensitive match
        low = str(val).lower()
        for i, c in enumerate(le.classes_):
            if str(c).lower() == low:
                return int(i)
    except Exception:
        pass
    return 0

def evaluate(model, X, y):
    preds = model.predict(X)
    probs = None
    try:
        probs = model.predict_proba(X)[:,1]  # prob of attack
    except Exception:
        # some models may not implement predict_proba
        probs = None

    acc = accuracy_score(y, preds)
    prec = precision_score(y, preds, zero_division=0)
    rec = recall_score(y, preds, zero_division=0)
    f1 = f1_score(y, preds, zero_division=0)
    cm = confusion_matrix(y, preds)
    report = classification_report(y, preds, zero_division=0, output_dict=True)
    # ROC AUC only if probs available and both classes present
    auc = None
    if probs is not None and len(np.unique(y)) > 1:
        try:
            auc = roc_auc_score(y, probs)
        except Exception:
            auc = None

    return {
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "roc_auc": auc,
        "confusion_matrix": cm.tolist(),
        "classification_report": report,
        "predictions": preds,
        "probabilities": probs
    }

def save_results(preds, probs, y_raw, out_prefix):
    # save per-row CSV with original label and predicted label
    df_out = pd.DataFrame({
        "true_label": y_raw,
        "predicted_label": preds,
    })
    if probs is not None:
        df_out["prob_attack"] = probs
    csv_path = os.path.join(LOG_DIR, f"{out_prefix}_predictions.csv")
    df_out.to_csv(csv_path, index=False)
    return csv_path

def main():
    if len(sys.argv) < 2:
        print("Usage: python src/evaluate_model.py <test-file-path>")
        sys.exit(1)
    path = sys.argv[1]
    print("[*] Loading model and encoders...")
    model, encoders = load_model_and_encoders()
    print("[*] Reading test file:", path)
    df = read_kdd_file(path)
    print(f"[*] Loaded {len(df)} rows")
    print("[*] Preparing features and labels...")
    X, y, y_raw = prepare_X_y(df, encoders)
    print("[*] Running evaluation...")
    res = evaluate(model, X, y)

    # print friendly summary
    print("\n=== Evaluation summary ===")
    print(f"Samples       : {len(y)}")
    print(f"Accuracy      : {res['accuracy']:.4f}")
    print(f"Precision     : {res['precision']:.4f}")
    print(f"Recall        : {res['recall']:.4f}")
    print(f"F1-score      : {res['f1']:.4f}")
    if res['roc_auc'] is not None:
        print(f"ROC AUC       : {res['roc_auc']:.4f}")
    print("Confusion matrix (rows=true, cols=pred):")
    print(np.array(res['confusion_matrix']))
    print("\nTop-level classification report (per-class):")
    # pretty print report
    try:
        print(json.dumps(res['classification_report'], indent=2))
    except Exception:
        pass

    # save detailed outputs
    out_prefix = os.path.splitext(os.path.basename(path))[0]
    csv_path = save_results(res['predictions'], res['probabilities'], y_raw, out_prefix)
    summary_path = os.path.join(LOG_DIR, f"{out_prefix}_eval_summary.json")
    with open(summary_path, "w") as f:
        json.dump({
            "samples": int(len(y)),
            "accuracy": res['accuracy'],
            "precision": res['precision'],
            "recall": res['recall'],
            "f1": res['f1'],
            "roc_auc": res['roc_auc'],
            "confusion_matrix": res['confusion_matrix'],
            "classification_report": res['classification_report']
        }, f, indent=2)
    print(f"\nSaved predictions CSV to: {csv_path}")
    print(f"Saved summary JSON to: {summary_path}")
    print("[*] Done.")

if __name__ == "__main__":
    main()
