import os
import pickle
from feature_extraction import extract_features, SUSPICIOUS_KEYWORDS

def predict_url(url):
    """
    Evaluates a URL using extracted features and trained ML classifier.
    Returns prediction dictionary with probability, label, status, features, and risk reasons.
    """
    feature_dict, feature_vec = extract_features(url)

    model_path = os.path.join(os.path.dirname(__file__), 'model.pkl')
    scaler_path = os.path.join(os.path.dirname(__file__), 'scaler.pkl')

    probability = 0.0
    label = 0
    status = "Safe"

    if os.path.exists(model_path):
        try:
            with open(model_path, 'rb') as f:
                model = pickle.load(f)
            with open(scaler_path, 'rb') as f:
                scaler = pickle.load(f)

            if hasattr(model, 'predict_proba'):
                vec_scaled = scaler.transform([feature_vec])
                prob = model.predict_proba(vec_scaled)[0][1]
                probability = float(prob)
            elif isinstance(model, dict) and 'weights' in model:
                # Heuristic fallback linear classifier
                score = model['bias']
                weights = model['weights']
                for i in range(len(feature_vec)):
                    score += feature_vec[i] * weights[i]
                probability = 1.0 / (1.0 + pow(2.71828, -score))
        except Exception as e:
            probability = _rule_based_fallback(feature_dict)
    else:
        probability = _rule_based_fallback(feature_dict)

    # Risk score calculation
    risk_score = round(probability * 100, 1)

    if risk_score >= 65:
        label = 1
        status = "Phishing URL Detected"
        risk_level = "High Risk"
    elif risk_score >= 35:
        label = 1
        status = "Suspicious URL"
        risk_level = "Medium Risk"
    else:
        label = 0
        status = "Legitimate / Safe URL"
        risk_level = "Low Risk"

    reasons = []
    if feature_dict['is_https'] == 0:
        reasons.append("Missing HTTPS protocol (Insecure HTTP connection)")
    if feature_dict['is_ip'] == 1:
        reasons.append("URL uses an IP address instead of a domain name")
    if feature_dict['suspicious_words'] > 0:
        reasons.append(f"Contains {feature_dict['suspicious_words']} suspicious security keyword(s)")
    if feature_dict['is_shortener'] == 1:
        reasons.append("Uses a known URL shortening service (obfuscated target)")
    if feature_dict['hyphens'] >= 3:
        reasons.append(f"High number of hyphens ({feature_dict['hyphens']}) in URL structure")
    if feature_dict['domain_len'] > 25:
        reasons.append(f"Unusually long domain length ({feature_dict['domain_len']} chars)")
    if feature_dict['has_at'] == 1:
        reasons.append("Contains '@' symbol used to redirect authentication tokens")
    if feature_dict['entropy'] > 3.8:
        reasons.append(f"High character entropy ({feature_dict['entropy']}), indicating random generation")

    return {
        'url': url,
        'label': label,
        'status': status,
        'risk_score': risk_score,
        'risk_level': risk_level,
        'probability': round(probability, 4),
        'features': feature_dict,
        'reasons': reasons
    }

def _rule_based_fallback(fd):
    score = 0.0
    if fd['is_https'] == 0: score += 0.25
    if fd['is_ip'] == 1: score += 0.35
    if fd['suspicious_words'] > 0: score += 0.25 * fd['suspicious_words']
    if fd['is_shortener'] == 1: score += 0.30
    if fd['hyphens'] >= 3: score += 0.15
    if fd['domain_len'] > 25: score += 0.15
    if fd['has_at'] == 1: score += 0.20
    if fd['entropy'] > 3.8: score += 0.15
    return min(max(score, 0.05), 0.98)

if __name__ == '__main__':
    test_url = "http://paypal-security-update-account.verify-user.xyz/login.php"
    result = predict_url(test_url)
    print("Test Prediction for:", test_url)
    print("Status:", result['status'])
    print("Risk Score:", result['risk_score'], "%")
    print("Reasons:", result['reasons'])
