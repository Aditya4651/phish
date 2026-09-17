import re
import math
from urllib.parse import urlparse

# List of common suspicious keywords used in phishing attacks
SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'account', 'update', 'banking', 'secure', 'paypal',
    'signin', 'security', 'confirm', 'service', 'wallet', 'bonus', 'claim',
    'free', 'crypto', 'password', 'validation', 'alert', 'support', 'billing'
]

# Common URL shorteners
URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'is.gd', 't.co', 'goo.gl', 'ow.ly',
    'buff.ly', 'adf.ly', 'bit.do', 'cutt.ly'
]

def calculate_entropy(text):
    """Calculates Shannon Entropy of a string to detect randomness/obfuscation."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    char_counts = {}
    for char in text:
        char_counts[char] = char_counts.get(char, 0) + 1
    for count in char_counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def is_ip_address(domain):
    """Checks if domain name is an IP address."""
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    return 1 if re.match(ip_pattern, domain) else 0

def extract_features(url):
    """
    Extracts a feature vector from a given URL string.
    Returns a dictionary of named features and a numeric list for ML inference.
    """
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'http://' + url

    parsed = urlparse(url)
    domain = parsed.netloc.split(':')[0]
    path = parsed.path

    # Feature 1: URL Length
    length = len(url)

    # Feature 2: Number of dots
    dots = url.count('.')

    # Feature 3: Number of hyphens
    hyphens = url.count('-')

    # Feature 4: Presence of @ symbol
    has_at = 1 if '@' in url else 0

    # Feature 5: HTTPS availability
    is_https = 1 if parsed.scheme == 'https' else 0

    # Feature 6: Domain Length
    domain_len = len(domain)

    # Feature 7: Count of Suspicious Keywords
    suspicious_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url.lower())

    # Feature 8: IP Address Usage
    is_ip = is_ip_address(domain)

    # Feature 9: Special Characters Count
    special_chars = sum(1 for c in url if c in ['?', '=', '%', '&', '_', '~', '!', '$', '+', ';'])

    # Feature 10: Entropy
    entropy = calculate_entropy(url)

    # Feature 11: URL Shortener check
    is_shortener = 1 if any(shortener in domain.lower() for shortener in URL_SHORTENERS) else 0

    feature_dict = {
        'length': length,
        'dots': dots,
        'hyphens': hyphens,
        'has_at': has_at,
        'is_https': is_https,
        'domain_len': domain_len,
        'suspicious_words': suspicious_count,
        'is_ip': is_ip,
        'special_chars': special_chars,
        'entropy': entropy,
        'is_shortener': is_shortener
    }

    feature_vector = [
        length, dots, hyphens, has_at, is_https,
        domain_len, suspicious_count, is_ip,
        special_chars, entropy, is_shortener
    ]

    return feature_dict, feature_vector
