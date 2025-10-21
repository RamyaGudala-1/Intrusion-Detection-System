# src/train_model.py
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
import pickle
import os

ROOT = os.path.join(os.path.dirname(__file__), "..")
DATA_PATH = os.path.join(ROOT, "data", "kddtrain.txt")
MODELS_DIR = os.path.join(ROOT, "models")
os.makedirs(MODELS_DIR, exist_ok=True)

# Columns (training)
columns = ["duration","protocol_type","service","flag","src_bytes","dst_bytes",
           "land","wrong_fragment","urgent","hot","num_failed_logins","logged_in",
           "num_compromised","root_shell","su_attempted","num_root","num_file_creations",
           "num_shells","num_access_files","num_outbound_cmds","is_host_login",
           "is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
           "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
           "srv_diff_host_rate","dst_host_count","dst_host_srv_count",
           "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
           "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
           "dst_host_rerror_rate","dst_host_srv_rerror_rate","label","difficulty"]

print("[*] Loading dataset from:", DATA_PATH)
df = pd.read_csv(DATA_PATH, names=columns)

# Encode categorical features
le_protocol = LabelEncoder()
le_service = LabelEncoder()
le_flag = LabelEncoder()
df['protocol_type'] = le_protocol.fit_transform(df['protocol_type'].astype(str))
df['service'] = le_service.fit_transform(df['service'].astype(str))
df['flag'] = le_flag.fit_transform(df['flag'].astype(str))

# Encode target labels (attack vs normal)
df['label'] = df['label'].apply(lambda x: 0 if x == 'normal' else 1)

X = df.drop(['label', 'difficulty'], axis=1)
y = df['label']

print("[*] Training RandomForest on", X.shape[0], "rows and", X.shape[1], "features")
rf = RandomForestClassifier(n_estimators=100, random_state=42)
rf.fit(X, y)

# Save model and encoders
with open(os.path.join(MODELS_DIR, "rf_model.pkl"), "wb") as f:
    pickle.dump(rf, f)

with open(os.path.join(MODELS_DIR, "encoders.pkl"), "wb") as f:
    pickle.dump({
        'protocol': le_protocol,
        'service': le_service,
        'flag': le_flag
    }, f)

print("[+] Model and encoders saved to", MODELS_DIR)
