# AI-Based Phishing URL Detection System

An artificial intelligence and machine learning solution for detecting phishing URLs, typosquatting domains, and fraudulent web addresses in real-time.

---

## 📁 Project Structure

```
PhishingURLDetector/
│
├── app.py                     # Flask Web Application & API Server
├── train_model.py             # Model Training Pipeline
├── predict.py                 # Feature Extraction & Model Inference Engine
├── feature_extraction.py      # Lexical URL Feature Extraction
├── model.pkl                  # Trained Random Forest Model Artifact
├── scaler.pkl                 # StandardScaler Artifact
│
├── templates/
│   ├── home.html              # Scanner Interface
│   ├── login.html             # User Authentication Portal
│   ├── dashboard.html         # Threat Intelligence Dashboard
│   └── result.html            # Scan Analysis Report Page
│
├── static/
│   ├── css/style.css          # Cybersecurity Theme Styles
│   ├── js/script.js           # Client Interactivity
│   └── images/
│
├── database/
│   └── schema.sql             # SQLite Database Schema & Seed Data
│
├── dataset/
│   └── phishing.csv           # Model Dataset (Safe vs Phishing URLs)
│
└── requirements.txt           # Python Dependencies
```

---

## ⚡ Quick Start & Run Instructions

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Train the Machine Learning Classifier
```bash
python train_model.py
```

### 3. Launch the Web Application
```bash
python app.py
```

### 4. Access the Website
Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 🔐 Credentials for Dashboard

- **Username:** `admin`
- **Password:** `admin123`
