import { URLFeatures } from '../types';

export const SUSPICIOUS_KEYWORDS = [
  'login', 'verify', 'account', 'update', 'banking', 'secure', 'paypal',
  'signin', 'security', 'confirm', 'service', 'wallet', 'bonus', 'claim',
  'free', 'crypto', 'password', 'validation', 'alert', 'support', 'billing',
  'center', 'verify-user', 'apple-id', 'chase', 'wellsfargo', 'binance'
];

export const URL_SHORTENERS = [
  'bit.ly', 'tinyurl.com', 'is.gd', 't.co', 'goo.gl', 'ow.ly',
  'buff.ly', 'adf.ly', 'bit.do', 'cutt.ly'
];

export function calculateEntropy(str: string): number {
  if (!str) return 0;
  const len = str.length;
  const counts: Record<string, number> = {};
  for (const char of str) {
    counts[char] = (counts[char] || 0) + 1;
  }
  let entropy = 0;
  for (const count of Object.values(counts)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(4));
}

export function isIPAddress(hostname: string): boolean {
  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
  return ipRegex.test(hostname);
}

export function extractURLFeatures(rawUrl: string): URLFeatures {
  let formattedUrl = rawUrl.trim();
  if (!formattedUrl.startsWith('http://') && !formattedUrl.startsWith('https://')) {
    formattedUrl = 'http://' + formattedUrl;
  }

  let hostname = '';
  let protocol = 'http';
  let tld = '.com';

  try {
    const parsed = new URL(formattedUrl);
    hostname = parsed.hostname.toLowerCase();
    protocol = parsed.protocol.replace(':', '');
    const parts = hostname.split('.');
    if (parts.length > 1) {
      tld = '.' + parts[parts.length - 1];
    }
  } catch {
    hostname = rawUrl.split('/')[0].toLowerCase();
  }

  const lowerUrl = rawUrl.toLowerCase();

  // Matched keywords
  const matched_keywords = SUSPICIOUS_KEYWORDS.filter(kw => lowerUrl.includes(kw));

  // Special characters
  const specialCharsRegex = /[?=%&_~!$+;]/g;
  const specialMatches = rawUrl.match(specialCharsRegex);
  const special_chars = specialMatches ? specialMatches.length : 0;

  // Shortener check
  const is_shortener = URL_SHORTENERS.some(short => hostname.includes(short));

  return {
    length: rawUrl.length,
    dots: (rawUrl.match(/\./g) || []).length,
    hyphens: (rawUrl.match(/-/g) || []).length,
    has_at: rawUrl.includes('@'),
    is_https: protocol === 'https',
    domain_len: hostname.length,
    suspicious_words: matched_keywords.length,
    matched_keywords,
    is_ip: isIPAddress(hostname),
    special_chars,
    entropy: calculateEntropy(rawUrl),
    is_shortener,
    tld
  };
}
