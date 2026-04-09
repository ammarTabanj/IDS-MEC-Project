from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
import joblib
# import numpy as np
import pandas as pd
def main():
    # remember y predicts x
    x_train,x_test,y_train,y_test=prepare('./archive/KDDTrain+.txt')
    ML_model =train(x_train,y_train)
    test(ML_model,x_test,y_test)
columns = [
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
        'dst_host_srv_rerror_rate', 'label', 'difficulty' # remember to drop difficulty
        ]# label will be used for flagging attacks
def prepare(floc):
    data = pd.read_csv(floc,names= columns)
    data =data.drop(columns='difficulty')
    # attack -> 1, Normal-> 0
    data['label']= data['label'].apply(lambda x: 0 if str(x).lower() =='normal' else 1)
    categorical_cols = ['protocol_type', 'service', 'flag']
    encoders={}
    for col in categorical_cols:
        le = LabelEncoder()
        data[col] = le.fit_transform(data[col])
        encoders[col] = le  # Save each encoder separately

    # Save encoders
    joblib.dump(encoders,'records/encoders.joblib')
    scaler = StandardScaler()
    X = data.drop('label', axis=1)
    X_scaled = scaler.fit_transform(X)
    y = data['label']
    joblib.dump(scaler,'records/scalar.joblib')
    return train_test_split(X_scaled, y, test_size=0.2, random_state=42, shuffle=True)
def train(X_train, y_train):
    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)
    joblib.dump(model,'records/model.joblib')
    return model
def test(model, X_test, y_test):
    y_pred= model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"accuracy: {accuracy * 100: .2f} %")
    print("=================================================================================")
    print("Classfication Report:")
    print(classification_report(y_test, y_pred, labels=[0, 1], target_names=['Normal', 'Attack']))
    print("=================================================================================")
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
if __name__ == "__main__":
    main()