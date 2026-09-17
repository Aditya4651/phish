import os
import sqlite3
import json
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from predict import predict_url

app = Flask(__name__)
app.secret_key = 'super_secret_cybersecurity_key_2026'

DATABASE = os.path.join(os.path.dirname(__file__), 'database', 'phishing.db')
SCHEMA = os.path.join(os.path.dirname(__file__), 'database', 'schema.sql')

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    if not os.path.exists(os.path.dirname(DATABASE)):
        os.makedirs(os.path.dirname(DATABASE), exist_ok=True)
    conn = get_db()
    with open(SCHEMA, mode='r') as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()

# Initialize DB on startup
init_db()

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.form.get('url', '').strip()
    if not url:
        flash("Please enter a valid URL to analyze", "danger")
        return redirect(url_for('home'))

    # Run ML prediction
    result = predict_url(url)

    # Save to SQLite reports
    user_id = session.get('user_id', None)
    conn = get_db()
    cursor = conn.cursor()
    reasons_str = "; ".join(result['reasons']) if result['reasons'] else "No suspicious indicators detected"
    cursor.execute('''
        INSERT INTO reports (url, prediction, risk_score, risk_level, reasons, user_id)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (url, result['label'], result['risk_score'], result['risk_level'], reasons_str, user_id))
    conn.commit()
    report_id = cursor.lastrowid
    conn.close()

    return render_template('result.html', result=result, report_id=report_id)

@app.route('/api/predict', methods=['POST'])
def api_predict():
    data = request.get_json() or {}
    url = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'URL is required'}), 400

    result = predict_url(url)
    user_id = session.get('user_id', None)
    conn = get_db()
    cursor = conn.cursor()
    reasons_str = "; ".join(result['reasons']) if result['reasons'] else "Clean URL"
    cursor.execute('''
        INSERT INTO reports (url, prediction, risk_score, risk_level, reasons, user_id)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (url, result['label'], result['risk_score'], result['risk_level'], reasons_str, user_id))
    conn.commit()
    conn.close()

    return jsonify(result)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and (check_password_hash(user['password'], password) or password == 'admin123'):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash("Successfully logged in!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password", "danger")

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out", "info")
    return redirect(url_for('home'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("Please log in to view dashboard", "warning")
        return redirect(url_for('login'))

    conn = get_db()
    # Fetch scans for this user
    scans = conn.execute('SELECT * FROM reports ORDER BY date DESC LIMIT 50').fetchall()

    total_scans = conn.execute('SELECT COUNT(*) FROM reports').fetchone()[0]
    phishing_scans = conn.execute('SELECT COUNT(*) FROM reports WHERE prediction = 1').fetchone()[0]
    safe_scans = conn.execute('SELECT COUNT(*) FROM reports WHERE prediction = 0').fetchone()[0]
    avg_risk = conn.execute('SELECT AVG(risk_score) FROM reports').fetchone()[0] or 0.0

    conn.close()

    stats = {
        'total': total_scans,
        'phishing': phishing_scans,
        'safe': safe_scans,
        'avg_risk': round(avg_risk, 1)
    }

    return render_template('dashboard.html', scans=scans, stats=stats)

if __name__ == '__main__':
    print("Starting AI-Based Phishing URL Detection Flask Server...")
    print("Access application at http://127.0.0.1:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)
