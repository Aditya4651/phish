-- Phishing URL Detection System Database Schema
-- SQLite3 Database Schema

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    prediction INTEGER NOT NULL, -- 0 = Safe, 1 = Phishing
    risk_score REAL NOT NULL,
    risk_level VARCHAR(20) NOT NULL,
    reasons TEXT,
    user_id INTEGER,
    date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Seed initial admin / analyst account
-- Note: Password hashes created via PBKDF2 / SHA256 security algorithms
INSERT OR IGNORE INTO users (id, username, password) VALUES 
(1, 'admin', 'scrypt:32768:8:1$7f91a2$8f93a0219c83a7a'),
(2, 'security_analyst', 'scrypt:32768:8:1$7f91a2$8f93a0219c83a7b');

-- Seed initial report logs
INSERT OR IGNORE INTO reports (id, url, prediction, risk_score, risk_level, reasons, user_id, date) VALUES
(1, 'https://www.google.com', 0, 4.2, 'Low Risk', 'None', 1, '2026-08-05 10:15:00'),
(2, 'http://paypal-security-update-account.verify-user.xyz/login.php', 1, 98.5, 'High Risk', 'Missing HTTPS, 6 suspicious keywords, long domain', 1, '2026-08-05 11:30:00'),
(3, 'http://192.168.1.105/paypal/secure-login/auth.html', 1, 92.0, 'High Risk', 'IP address usage, Missing HTTPS, 2 suspicious keywords', 2, '2026-08-05 14:22:00'),
(4, 'https://www.github.com', 0, 5.1, 'Low Risk', 'None', 2, '2026-08-05 16:45:00');
