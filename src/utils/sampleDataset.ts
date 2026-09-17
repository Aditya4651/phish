import { URLScanResult, DatasetItem, ProjectFile } from '../types';
import { analyzeURL } from './phishingEngine';

export const INITIAL_PRESET_SCANS: URLScanResult[] = [
  analyzeURL('https://amazon-arrived.com/track/order?id=92811', 'Pre-seed Log'),
  analyzeURL('https://paypal-login-secure.com/auth/verify', 'Pre-seed Log'),
  analyzeURL('https://google-account-login.com/checkpoint/user', 'Pre-seed Log'),
  analyzeURL('https://micr0soft-login.com/oauth2/login', 'Pre-seed Log'),
  analyzeURL('https://faceb00k-security.com/checkpoint/appeal', 'Pre-seed Log'),
  analyzeURL('https://g00gle-auth.com/mfa/challenge', 'Pre-seed Log'),
  analyzeURL('https://paypaI.com/myaccount/home', 'Pre-seed Log'),
  analyzeURL('https://www.google.com', 'Pre-seed Log'),
  analyzeURL('https://github.com', 'Pre-seed Log')
];

export const SAMPLE_DATASET_CSV: DatasetItem[] = [
  { url: 'https://www.google.com', length: 21, dots: 2, hyphens: 0, is_https: 1, suspicious_words: 0, is_ip: 0, label: 0 },
  { url: 'https://www.github.com', length: 21, dots: 2, hyphens: 0, is_https: 1, suspicious_words: 0, is_ip: 0, label: 0 },
  { url: 'https://www.wikipedia.org', length: 24, dots: 2, hyphens: 0, is_https: 1, suspicious_words: 0, is_ip: 0, label: 0 },
  { url: 'https://www.amazon.com', length: 21, dots: 2, hyphens: 0, is_https: 1, suspicious_words: 0, is_ip: 0, label: 0 },
  { url: 'https://www.microsoft.com', length: 24, dots: 2, hyphens: 0, is_https: 1, suspicious_words: 0, is_ip: 0, label: 0 },
  { url: 'https://amazon-arrived.com/track/order', length: 38, dots: 2, hyphens: 1, is_https: 1, suspicious_words: 0, is_ip: 0, label: 1 },
  { url: 'http://paypal-security-update-account.verify-user.xyz/login.php', length: 62, dots: 3, hyphens: 4, is_https: 0, suspicious_words: 4, is_ip: 0, label: 1 },
  { url: 'http://192.168.1.105/paypal/secure-login/auth.html', length: 49, dots: 3, hyphens: 1, is_https: 0, suspicious_words: 2, is_ip: 1, label: 1 },
  { url: 'http://secure-apple-id-login-update.com-auth.top/verify', length: 54, dots: 3, hyphens: 4, is_https: 0, suspicious_words: 3, is_ip: 0, label: 1 },
  { url: 'http://wellsfargo-bank-verification-client.info/account', length: 53, dots: 2, hyphens: 3, is_https: 0, suspicious_words: 2, is_ip: 0, label: 1 }
];

export const PYTHON_FILES_LIST: ProjectFile[] = [
  {
    name: 'app.py',
    path: 'PhishingURLDetector/app.py',
    type: 'code',
    content: `from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3, os
from predict import predict_url

app = Flask(__name__)
app.secret_key = 'super_secret_cybersecurity_key_2026'

DATABASE = os.path.join(os.path.dirname(__file__), 'database', 'phishing.db')

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.form.get('url', '').strip()
    result = predict_url(url)
    return render_template('result.html', result=result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)`
  },
  {
    name: 'train_model.py',
    path: 'PhishingURLDetector/train_model.py',
    type: 'code',
    content: `import os, csv, pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from feature_extraction import extract_features

def train():
    dataset_path = 'dataset/phishing.csv'
    # Extract features and fit Random Forest Classifier
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    # Save model.pkl and scaler.pkl
    with open('model.pkl', 'wb') as f:
        pickle.dump(clf, f)

if __name__ == '__main__':
    train()`
  },
  {
    name: 'predict.py',
    path: 'PhishingURLDetector/predict.py',
    type: 'code',
    content: `import pickle
from feature_extraction import extract_features

def predict_url(url):
    feature_dict, feature_vec = extract_features(url)
    # Load model.pkl and predict probability
    return {
        'url': url,
        'risk_score': 98.5,
        'status': 'Phishing URL Detected',
        'reasons': ['Missing HTTPS', 'Suspicious keywords']
    }`
  },
  {
    name: 'feature_extraction.py',
    path: 'PhishingURLDetector/feature_extraction.py',
    type: 'code',
    content: `import re, math
from urllib.parse import urlparse

def extract_features(url):
    # Extracts length, dots, hyphens, HTTPS, IP usage, keywords, entropy
    return feature_dict, feature_vector`
  },
  {
    name: 'schema.sql',
    path: 'PhishingURLDetector/database/schema.sql',
    type: 'data',
    content: `CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    prediction INTEGER NOT NULL,
    risk_score REAL NOT NULL,
    risk_level VARCHAR(20) NOT NULL,
    date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);`
  },
  {
    name: 'phishing.csv',
    path: 'PhishingURLDetector/dataset/phishing.csv',
    type: 'data',
    content: `url,length,dots,hyphens,has_at,is_https,domain_len,suspicious_words,is_ip,special_chars,entropy,is_shortener,label
https://www.google.com,21,2,0,0,1,10,0,0,0,3.21,0,0
http://paypal-security-update-account.verify-user.xyz/login.php,62,3,4,0,0,38,3,0,3,4.21,0,1`
  },
  {
    name: 'requirements.txt',
    path: 'PhishingURLDetector/requirements.txt',
    type: 'config',
    content: `flask==3.0.2
pandas==2.2.1
numpy==1.26.4
scikit-learn==1.4.1.post1
joblib==1.3.2
werkzeug==3.0.1
bootstrap-flask==2.4.0`
  }
];
