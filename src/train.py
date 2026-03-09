import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import os
import sys

# Add the current directory to path to allow imports if running from root
sys.path.append(os.getcwd())

# Configuration
DATA_PATH = 'data/phishing_dataset.csv'
MODEL_PATH = 'models/phishing_model.joblib'

def train_model():
    print("Loading data...")
    if not os.path.exists(DATA_PATH):
        print(f"Error: {DATA_PATH} not found.")
        return

    df = pd.read_csv(DATA_PATH)
    
    # Check if this is the pre-processed UCI dataset
    if 'having_IPhaving_IP_Address' in df.columns:
        print("Detected pre-processed UCI dataset. Selecting and mapping compatible features...")
        
        # Map UCI dataset columns to the 8 features used in src/features.py
        # UCI values: -1 (Phishing), 0 (Suspicious), 1 (Legitimate)
        # API values: 1 (Phishing/Bad), 0 (Legitimate/Good) OR 2 (Phishing), 1 (Suspicious), 0 (Legitimate)
        
        # 1. IP Address
        # UCI: -1 (Phishing), 1 (Legitimate) -> API: 1 (Phishing), 0 (Legitimate)
        df['IP Address'] = df['having_IPhaving_IP_Address'].apply(lambda x: 1 if x == -1 else 0)
        
        # 2. URL Length
        # UCI: -1 (Phishing), 0 (Suspicious), 1 (Legitimate) -> API: 2 (Phishing), 1 (Suspicious), 0 (Legitimate)
        df['URL Length'] = df['URLURL_Length'].apply(lambda x: 2 if x == -1 else (1 if x == 0 else 0))
        
        # 3. Shortening Service
        df['Shortening Service'] = df['Shortining_Service'].apply(lambda x: 1 if x == -1 else 0)
        
        # 4. @ Symbol
        df['@ Symbol'] = df['having_At_Symbol'].apply(lambda x: 1 if x == -1 else 0)
        
        # 5. Double Slash
        df['Double Slash'] = df['double_slash_redirecting'].apply(lambda x: 1 if x == -1 else 0)
        
        # 6. Prefix/Suffix
        df['Prefix/Suffix'] = df['Prefix_Suffix'].apply(lambda x: 1 if x == -1 else 0)
        
        # 7. Sub-domains
        # UCI: -1 (Phishing), 0 (Suspicious), 1 (Legitimate) -> API: 2 (Phishing), 1 (Suspicious), 0 (Legitimate)
        df['Sub-domains'] = df['having_Sub_Domain'].apply(lambda x: 2 if x == -1 else (1 if x == 0 else 0))
        
        # 8. HTTPS Token
        df['HTTPS Token'] = df['HTTPS_token'].apply(lambda x: 1 if x == -1 else 0)
        
        # Label
        # UCI: -1 (Phishing), 1 (Legitimate) -> API: 1 (Phishing), 0 (Legitimate)
        df['label'] = df['Result'].apply(lambda x: 1 if x == -1 else 0)

        # Select features in the exact order expected by src/features.py
        feature_cols = ["IP Address", "URL Length", "Shortening Service", "@ Symbol", "Double Slash", "Prefix/Suffix", "Sub-domains", "HTTPS Token"]
        X = df[feature_cols]
        y = df['label']
        
    elif 'url' in df.columns:
        print("Detected raw URL dataset. Extracting features...")
        # Lazy import to avoid dependency if not needed
        try:
            from src.features import FeatureExtractor
        except ImportError:
            from features import FeatureExtractor
            
        extractor = FeatureExtractor()
        features_list = df['url'].apply(extractor.extract_features).tolist()
        X = pd.DataFrame(features_list, columns=["IP Address", "URL Length", "Shortening Service", "@ Symbol", "Double Slash", "Prefix/Suffix", "Sub-domains", "HTTPS Token"])
        
        # Standardize label
        if 'label' not in df.columns:
             # Try to find label column
             possible_labels = ['type', 'class', 'phishing', 'result']
             for col in df.columns:
                 if col.lower() in possible_labels:
                     df['label'] = df[col]
                     break
        
        # Ensure label is 0/1
        y = df['label'].apply(lambda x: 1 if str(x).lower() in ['bad', 'phishing', '1', '-1'] else 0)
    else:
        raise ValueError("Dataset format not recognized. Need either 'url' column or UCI features.")

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Initialize and train model
    print("Training Random Forest Classifier...")
    clf = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
    clf.fit(X_train, y_train)

    # Feature Importance
    print("\nFeature Importances:")
    for name, score in zip(X.columns, clf.feature_importances_):
        print(f"{name}: {score:.4f}")
    print("-" * 30)

    # Evaluate
    y_pred = clf.predict(X_test)
    print(f"Model Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print(classification_report(y_test, y_pred))

    # Save the model
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(clf, MODEL_PATH)
    print(f"Model saved to {MODEL_PATH}")

if __name__ == "__main__":
    train_model()
