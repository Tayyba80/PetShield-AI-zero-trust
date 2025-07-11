import sys
sys.path.append("C:/Users/Hameed Computers/Documents/catDog")
import pickle 
import pandas as pd
from sklearn.ensemble import IsolationForest
from datetime import datetime, timedelta
from models.user_model import AnomalyDetectionModel
from extension import db

def train_login_anomaly_model():
    """Train IsolationForest model to detect suspicious login behavior (hourly analysis)"""
    logs = pd.read_sql(f"""
    SELECT
        ip_address,
        STRFTIME('%Y-%m-%d %H:00:00', timestamp) AS hour,
        COUNT(*) AS failed_events
    FROM security_log
    WHERE event_type = 'failed_login'
    AND timestamp > '{datetime.now() - timedelta(days=7)}'
    GROUP BY ip_address, hour
    """, db.engine)


    if logs.empty:
        print("No data available for training.")
        return

    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(logs[['failed_events']])

    model_bin = pickle.dumps(model)
    existing = AnomalyDetectionModel.query.filter_by(name="login_anomaly").first()

    if existing:
        existing.model_data = model_bin
        existing.last_trained = datetime.now()
    else:
        db.session.add(AnomalyDetectionModel(
            name="login_anomaly",
            model_data=model_bin,
            last_trained=datetime.now()
        ))
    db.session.commit()
    print("Model trained and saved successfully.")


#Comment the model loading line in model.py before running this
if __name__ == "__main__":
    from app import app
    with app.app_context():
        train_login_anomaly_model()
