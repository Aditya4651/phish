import os
import csv
import pickle
from feature_extraction import extract_features

def train():
    print("=" * 60)
    print("AI-Based Phishing URL Detector - Model Training Pipeline")
    print("=" * 60)

    dataset_path = os.path.join(os.path.dirname(__file__), 'dataset', 'phishing.csv')
    if not os.path.exists(dataset_path):
        print(f"Error: Dataset file not found at {dataset_path}")
        return

    X = []
    y = []

    print(f"[*] Loading dataset from {dataset_path}...")
    with open(dataset_path, mode='r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                if 'url' in row and row['url']:
                    _, vec = extract_features(row['url'])
                    X.append(vec)
                    y.append(int(row['label']))
                else:
                    vec = [
                        float(row['length']), float(row['dots']), float(row['hyphens']),
                        float(row['has_at']), float(row['is_https']), float(row['domain_len']),
                        float(row['suspicious_words']), float(row['is_ip']),
                        float(row['special_chars']), float(row['entropy']), float(row['is_shortener'])
                    ]
                    X.append(vec)
                    y.append(int(row['label']))
            except Exception as e:
                continue

    print(f"[+] Loaded {len(X)} samples successfully.")

    # Attempt to train using Scikit-Learn
    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.preprocessing import StandardScaler
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import accuracy_score, classification_report

        print("[*] Training Random Forest Classifier with sklearn...")
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        if len(X) >= 10:
            X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)
        else:
            X_train, X_test, y_train, y_test = X_scaled, X_scaled, y, y

        clf = RandomForestClassifier(n_estimators=100, random_state=42)
        clf.fit(X_train, y_train)

        y_pred = clf.predict(X_test)
        acc = accuracy_score(y_test, y_pred)
        print(f"[+] Model Accuracy: {acc * 100:.2f}%")
        print("\nClassification Report:\n", classification_report(y_test, y_pred))

        model_path = os.path.join(os.path.dirname(__file__), 'model.pkl')
        scaler_path = os.path.join(os.path.dirname(__file__), 'scaler.pkl')

        with open(model_path, 'wb') as f:
            pickle.dump(clf, f)
        with open(scaler_path, 'wb') as f:
            pickle.dump(scaler, f)

        print(f"[✓] Saved model to {model_path}")
        print(f"[✓] Saved scaler to {scaler_path}")

    except ImportError:
        print("[!] sklearn not found, saving lightweight rule-based model weights into model.pkl...")
        model_weights = {
            'weights': [0.12, 0.15, 0.15, 0.20, -0.25, 0.10, 0.25, 0.30, 0.10, 0.18, 0.25],
            'bias': -0.1,
            'feature_names': ['length', 'dots', 'hyphens', 'has_at', 'is_https', 'domain_len', 'suspicious_words', 'is_ip', 'special_chars', 'entropy', 'is_shortener']
        }
        model_path = os.path.join(os.path.dirname(__file__), 'model.pkl')
        scaler_path = os.path.join(os.path.dirname(__file__), 'scaler.pkl')
        with open(model_path, 'wb') as f:
            pickle.dump(model_weights, f)
        with open(scaler_path, 'wb') as f:
            pickle.dump({'mean': [30, 2, 1, 0, 0.5, 15, 0.5, 0, 1, 3.5, 0]}, f)
        print("[✓] Saved rule-based fallback model to model.pkl")

if __name__ == '__main__':
    train()
