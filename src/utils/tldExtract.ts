/**
 * Custom tldextract implementation for PhishGuard ML Preprocessing.
 * Splits URLs cleanly into subdomain, root domain, TLD suffix, path, and query parameters.
 * Supports multi-part public suffixes (e.g., .co.uk, .com.au, .appspot.com).
 */

export interface ParsedURLParts {
  rawUrl: string;
  protocol: string;
  hostname: string;
  subdomain: string;
  domain: string;        // e.g. "google"
  tld: string;           // e.g. "com" or "co.uk"
  rootDomain: string;    // e.g. "google.com" or "bbc.co.uk"
  path: string;
  query: string;
  hash: string;
  port: string;
  isIP: boolean;
}

// Common multi-part suffixes
const MULTI_PART_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'me.uk',
  'com.au', 'net.au', 'org.au', 'edu.au',
  'co.nz', 'net.nz', 'org.nz',
  'co.jp', 'ne.jp', 'or.jp',
  'co.in', 'net.in', 'org.in', 'gen.in',
  'com.br', 'net.br', 'org.br',
  'com.cn', 'net.cn', 'org.cn',
  'com.sg', 'org.sg', 'edu.sg',
  'co.za', 'org.za',
  'appspot.com', 'pages.dev', 'github.io', 'gitlab.io',
  'firebaseapp.com', 'web.app', 'azurewebsites.net', 'cloudfront.net',
  'herokuapp.com', 'myshopify.com', 'wordpress.com', 'blogspot.com'
]);

export function parseWithTldExtract(rawUrl: string): ParsedURLParts {
  let cleaned = (rawUrl || '').trim();
  if (!cleaned.startsWith('http://') && !cleaned.startsWith('https://')) {
    cleaned = 'https://' + cleaned;
  }

  let protocol = 'https:';
  let hostname = '';
  let path = '/';
  let query = '';
  let hash = '';
  let port = '';

  try {
    const parsed = new URL(cleaned);
    protocol = parsed.protocol;
    hostname = parsed.hostname.toLowerCase();
    path = parsed.pathname;
    query = parsed.search.replace(/^\?/, '');
    hash = parsed.hash;
    port = parsed.port;
  } catch {
    // Fallback extraction
    const match = cleaned.match(/^(https?:\/\/)?([^/?#]+)([^?#]*)(\?[^#]*)?(#.*)?$/);
    if (match) {
      hostname = (match[2] || '').toLowerCase().split(':')[0];
      path = match[3] || '/';
      query = (match[4] || '').replace(/^\?/, '');
      hash = match[5] || '';
    }
  }

  // Check if IP
  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
  const isIP = ipRegex.test(hostname);

  if (isIP || !hostname) {
    return {
      rawUrl,
      protocol: protocol.replace(':', ''),
      hostname,
      subdomain: '',
      domain: hostname,
      tld: '',
      rootDomain: hostname,
      path,
      query,
      hash,
      port,
      isIP
    };
  }

  const parts = hostname.split('.');
  if (parts.length === 1) {
    return {
      rawUrl,
      protocol: protocol.replace(':', ''),
      hostname,
      subdomain: '',
      domain: parts[0],
      tld: '',
      rootDomain: parts[0],
      path,
      query,
      hash,
      port,
      isIP: false
    };
  }

  // Check 2-level suffix (e.g., co.uk, appspot.com)
  let tld = '';
  let domain = '';
  let subdomain = '';

  if (parts.length >= 3) {
    const twoLevelSuffix = `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
    if (MULTI_PART_SUFFIXES.has(twoLevelSuffix)) {
      tld = twoLevelSuffix;
      domain = parts[parts.length - 3];
      subdomain = parts.slice(0, parts.length - 3).join('.');
    }
  }

  // If not matched 2-level suffix, standard 1-level suffix
  if (!tld) {
    tld = parts[parts.length - 1];
    domain = parts[parts.length - 2];
    subdomain = parts.slice(0, parts.length - 2).join('.');
  }

  const rootDomain = `${domain}.${tld}`;

  return {
    rawUrl,
    protocol: protocol.replace(':', ''),
    hostname,
    subdomain,
    domain,
    tld,
    rootDomain,
    path,
    query,
    hash,
    port,
    isIP: false
  };
}

/**
 * Brand-Impersonation Root-Domain Matcher:
 * If the scanned URL's root domain matches the target brand's official root domain,
 * the impersonation flag MUST be suppressed.
 * Only flag brand impersonation when root domains differ!
 */
export function evaluateBrandImpersonation(
  scannedRootDomain: string,
  brandCanonicalDomain: string,
  subdomain: string,
  pathAndQuery: string
): { isImpersonation: boolean; brandTarget: string | null; isAuthorizedSubservice: boolean } {
  const normScannedRoot = scannedRootDomain.toLowerCase();
  const normBrandDomain = brandCanonicalDomain.toLowerCase();

  // Known root aliases for major corporations (e.g. microsoft.com and microsoftonline.com, office.com, live.com)
  const BRAND_ALIAS_MAP: Record<string, string[]> = {
    'google.com': ['google.com', 'google.co.uk', 'google.ca', 'youtube.com', 'gmail.com', 'googleusercontent.com'],
    'microsoft.com': ['microsoft.com', 'microsoftonline.com', 'office.com', 'office365.com', 'live.com', 'azure.com', 'windows.net'],
    'apple.com': ['apple.com', 'icloud.com', 'appleid.apple.com'],
    'amazon.com': ['amazon.com', 'amazon.co.uk', 'amazon.de', 'aws.amazon.com', 'media-amazon.com'],
    'paypal.com': ['paypal.com', 'paypal-objects.com'],
    'meta.com': ['facebook.com', 'meta.com', 'instagram.com', 'whatsapp.com']
  };

  // Find if brandCanonicalDomain is in any corporate alias group
  let allowedRoots: string[] = [normBrandDomain];
  for (const [canonical, aliases] of Object.entries(BRAND_ALIAS_MAP)) {
    if (canonical === normBrandDomain || aliases.includes(normBrandDomain)) {
      allowedRoots = [canonical, ...aliases];
      break;
    }
  }

  // If scanned root domain matches any legitimate root or alias of the brand, suppress impersonation
  const isAuthorizedSubservice = allowedRoots.includes(normScannedRoot);
  if (isAuthorizedSubservice) {
    return {
      isImpersonation: false,
      brandTarget: normBrandDomain,
      isAuthorizedSubservice: true
    };
  }

  // Root domains DIFFER: now check if brand keyword or typosquat is present in scanned hostname or path
  const brandName = normBrandDomain.split('.')[0];
  const combinedTarget = `${scannedRootDomain} ${subdomain} ${pathAndQuery}`.toLowerCase();

  const brandPresent = combinedTarget.includes(brandName) || 
    (brandName.length >= 5 && combinedTarget.replace(/0/g, 'o').replace(/1/g, 'l').replace(/5/g, 's').includes(brandName));

  if (brandPresent) {
    return {
      isImpersonation: true,
      brandTarget: brandName,
      isAuthorizedSubservice: false
    };
  }

  return {
    isImpersonation: false,
    brandTarget: null,
    isAuthorizedSubservice: false
  };
}
