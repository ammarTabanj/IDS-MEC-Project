import joblib
import pandas as pd
import time
import os

# --- 1. SETUP PATHS ---
LIVE_LOG = './records/temp_log.log'
MODEL_PATH = 'records/model.joblib'
SCALER_PATH = 'records/scalar.joblib'
ENCODER_PATH = 'records/encoders.joblib'

FEATURE_COLUMNS = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
    'logged_in', 'num_compromised', 'root_shell', 'su_attempted',
    'num_root', 'num_file_creations', 'num_shells', 'num_access_files',
    'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count',
    'srv_count', 'rerror_rate', 'srv_serror_rate', 'serror_rate',
    'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
    'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
    'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
    'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate'
]

print("[*] Loading AI Engines...")
model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)
encoders = joblib.load(ENCODER_PATH)
def line_processing(line):
    parts = line.strip().split(',')
    raw_features= parts[:41]
    df = pd.DataFrame([raw_features], columns=FEATURE_COLUMNS)

    for col in ['protocol_type', 'service', 'flag']:
        le = encoders[col]
        df[col] = le.transform(df[col])
    scaled_data = scaler.transform(df)
    prediction = model.predict(scaled_data)[0]
    if prediction == 1:
        return "ATTACK"
    else:
        return "NORMAL"
def monitoring(delay=3):
    print("[*] Monitoring...")
    last_line=""
    while True:
        if os.path.exists(LIVE_LOG):
            with open(LIVE_LOG, 'r') as f:
                current_line=f.read().strip()
            if current_line and current_line!=last_line:
                result = line_processing(current_line)
                if result == "ATTACK":
                    print(f"ALERT: {result} has been detected \n Details:\n {current_line}")
                    print("_____________________________________________________________________________________________________________>")

                else:
                    print(f"CLEAN:{result} Traffic \n Details:\n {current_line}")
                    print("_____________________________________________________________________________________________________________>")
                last_line = current_line
        else:
            print("Current log file is not working")

if __name__ == '__main__':
    monitoring(delay = 2)