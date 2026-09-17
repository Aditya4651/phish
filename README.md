# Phishing URL Detection & Cyber Security Platform

A production-grade cybersecurity platform that detects phishing URLs, brand impersonations, typosquatting domains, homograph attacks, and credential-harvesting vectors using multi-dimensional lexical feature extraction and machine learning classification.

---

## 🌟 Key Features

- **Lexical URL Feature Extraction**: Analyzes over 18 critical URL metrics including domain length, entropy, Levenshtein brand similarity, IP address usage, subdomains, HTTPS/SSL validation, and suspicious keyword frequency.
- **Machine Learning Classification**: Random Forest classification model delivering real-time threat scores, risk grades (A+ to F), and granular risk breakdowns.
- **Interactive Security Dashboard**: Comprehensive threat analytics, historical scan data visualization, domain threat distribution charts, and exportable PDF/JSON threat reports.
- **AAA Security Subsystem**: JWT & PBKDF2 authentication, 6-digit email OTP verification, password strength auditing, session revocation, and RBAC role control (Admin, Analyst, Guest).
- **RESTful API Engine**: Full Express REST server supporting authenticated URL scans, profile management, and developer API key bearer authorization.

---

## 📁 Repository Structure

```
├── server.ts                       # Express REST API Server & Authentication Pipeline
├── src/                            # Frontend Source Code
│   ├── components/                 # UI Views (URLScanner, Dashboard, Reports, UserProfile, AdminPanel)
│   ├── utils/                      # Feature Extractor, ML Classifier, PDF Generator, Security Helpers
│   ├── types.ts                    # TypeScript Data Interfaces
│   └── App.tsx                     # Main React Application
├── PhishingURLDetector/            # Python Flask ML Service & Model Pipeline
│   ├── app.py                      # Flask Application Entry Point
│   ├── train_model.py              # ML Training Pipeline
│   ├── predict.py                  # Model Inference Engine
│   └── database/schema.sql         # SQLite Database Schema
├── package.json                    # Node.js Dependencies & Build Scripts
├── tsconfig.json                   # TypeScript Compiler Configuration
└── vite.config.ts                  # Vite Build Configuration
```

---

## 🛠️ Tech Stack

- **Frontend**: React 19, TypeScript, Tailwind CSS, Lucide React, Recharts, Motion, jsPDF
- **Backend Server**: Node.js, Express, PBKDF2 Crypto, JWT Authentication
- **Python ML Pipeline**: Python 3.10+, Scikit-Learn, Pandas, NumPy, Flask, SQLite3

---

## 🚀 Getting Started

### Prerequisites

- Node.js (v18+) & npm
- Python 3.10+ (for Python ML module)

### Installation

1. **Install Node.js dependencies**:
   ```bash
   npm install
   ```

2. **Start Development Server**:
   ```bash
   npm run dev
   ```
   The application will run at `http://localhost:3000`.

3. **Build for Production**:
   ```bash
   npm run build
   npm start
   ```

---

## 🔒 Security Specifications

- **Password Hashing**: PBKDF2 with 100,000 iterations and 16-byte cryptographic salt.
- **Session Tokens**: Dual JWT structure (15-minute access token + 7-day refresh token).
- **Rate Limiting & OTP**: Cooldown enforcement and attempt capping on verification codes.

---

## 📜 License

Enterprise Production Release • Confidential Security Document.
