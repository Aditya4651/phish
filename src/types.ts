export type RiskLevel = 'Safe' | 'Low Risk' | 'Medium Risk' | 'High Risk' | 'Critical';
export type SecurityGrade = 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
export type UserRole = 'Admin' | 'Moderator' | 'Premium User' | 'Free User' | 'Guest';

export type ParameterCategory = 
  | 'Lexical & URL Anatomy'
  | 'Evasion & Obfuscation'
  | 'Domain & Host Reputation'
  | 'SSL & Transport Security'
  | 'Content & Social Engineering';

export type ParameterStatus = 'Pass' | 'Warning' | 'Fail';
export type ParameterSeverity = 'Low' | 'Medium' | 'High' | 'Critical';

export interface WebsiteCheckParameter {
  id: string;
  name: string;
  category: ParameterCategory;
  value: string | number | boolean;
  displayValue: string;
  status: ParameterStatus;
  severity: ParameterSeverity;
  riskContribution: number; // 0 to 100
  description: string;
  forensicDetail: string;
  benchmarkStandard: string; // e.g. RFC 3986, OWASP, NIST, CA/B
}

export interface ParameterSummary {
  total: number;
  passed: number;
  warnings: number;
  failed: number;
}

export interface DomainInfo {
  hostname: string;
  subdomain: string;
  tld: string;
  ip: string;
  country: string;
  registrar: string;
  domain_age_days: number;
  created: string;
  expires: string;
}

export interface SSLInfo {
  enabled: boolean;
  issuer: string;
  valid_until: string;
  expired: boolean;
  self_signed?: boolean;
}

export interface ThreatIndicators {
  ip_address_url: boolean;
  url_shortener: boolean;
  multiple_redirects: boolean;
  suspicious_keywords: boolean;
  homograph_attack: boolean;
  punycode: boolean;
  typosquatting_brand: boolean;
  subdomains_excessive: boolean;
  embedded_credentials: boolean;
  // Extended threat flags
  double_slash_redirect?: boolean;
  non_standard_port?: boolean;
  percent_encoded_payload?: boolean;
  suspicious_file_extension?: boolean;
  high_tld_abuse?: boolean;
}

export interface RiskBreakdown {
  url_structure: number; // 0-100
  domain_reputation: number; // 0-100
  ssl: number; // 0-100
  keywords: number; // 0-100
  entropy: number; // 0-100
  evasion_techniques?: number; // 0-100
}

export interface DetailedFeature {
  value: number | string | boolean;
  status: 'Good' | 'Warning' | 'Critical';
  reason: string;
}

export interface URLFeatures {
  length: number;
  dots: number;
  hyphens: number;
  has_at: boolean;
  is_https: boolean;
  domain_len: number;
  suspicious_words: number;
  matched_keywords: string[];
  is_ip: boolean;
  special_chars: number;
  entropy: number;
  is_shortener: boolean;
  tld: string;
  brand_impersonated?: string;
  levenshtein_distance?: number;
  // Extended features for 20+ parameters
  path_length?: number;
  subdomain_depth?: number;
  path_depth?: number;
  digit_ratio?: number;
  double_slash_redirect?: boolean;
  percent_encoding_count?: number;
  non_standard_port?: number | null;
  is_punycode?: boolean;
  domain_age_days?: number;
  domain_expiry_days?: number;
  whois_privacy?: boolean;
  hsts_enforced?: boolean;
  ca_reputation?: string;
  suspicious_file_extension?: string;
  credential_harvest_intent?: boolean;
}

export interface MLInfo {
  model: string;
  confidence: string;
  version: string;
  ensemble_weight?: string;
}

export interface URLScanResult {
  id: string;
  url: string;
  timestamp: string;
  label: 'Safe' | 'Suspicious' | 'Phishing';
  riskScore: number; // 0 to 100
  securityScore: number; // 0 to 100
  grade: SecurityGrade;
  riskLevel: RiskLevel;
  probability: number; // 0.0 to 1.0
  scanTime: string; // e.g. "186 ms"
  domain: DomainInfo;
  ssl: SSLInfo;
  threats: ThreatIndicators;
  riskBreakdown: RiskBreakdown;
  explainedFeatures: Record<string, DetailedFeature>;
  parameters: WebsiteCheckParameter[];
  parameterSummary: ParameterSummary;
  ml: MLInfo;
  features: URLFeatures;
  reasons: string[];
  recommendations: string[];
  scannedBy?: string;
}

export interface UserSession {
  id: string;
  deviceName: string;
  browser: string;
  os: string;
  ipAddress: string;
  location: string;
  createdTime: string;
  lastActive: string;
  isCurrent: boolean;
}

export interface User {
  id?: string;
  clerkUserId?: string;
  username: string;
  firstName?: string;
  lastName?: string;
  email?: string;
  dateOfBirth?: string;
  role: UserRole;
  isLoggedIn: boolean;
  accountStatus?: 'Active' | 'Locked' | 'Pending Verification';
  verificationStatus?: boolean;
  createdAt?: string;
  lastLogin?: string;
  lastActive?: string;
  profileImage?: string;
  apiKey?: string;
  googleId?: string;
  googleLinked?: boolean;
  activeSessions?: UserSession[];
}

export interface DatabaseUser {
  id: number;
  clerk_user_id: string;
  username: string | null;
  first_name: string | null;
  last_name: string | null;
  email: string | null;
  role?: string | null;
  date_of_birth: string | null;
  profile_image_url: string | null;
  created_at: string;
  updated_at: string;
  last_active_at: string;
}

export interface AdminUserRecord {
  id: number;
  clerk_user_id: string;
  username: string | null;
  first_name: string | null;
  last_name: string | null;
  email: string | null;
  role: string | null;
  date_of_birth: string | null;
  profile_image_url: string | null;
  created_at: string;
  updated_at: string;
  last_active_at: string;
  total_scans: number;
  high_risk_scans: number;
  safe_scans: number;
  suspicious_scans: number;
}

export interface UserDashboardStats {
  username: string;
  totalScans: number;
  safeUrls: number;
  suspiciousUrls: number;
  maliciousUrls: number;
  avgRiskScore: number;
  latestScan: URLScanResult | null;
  recentScans: URLScanResult[];
  lastActive: string;
}

export interface AuditLog {
  id: string;
  timestamp: string;
  userId?: string;
  username: string;
  eventType:
    | 'LOGIN'
    | 'FAILED_LOGIN'
    | 'REGISTER'
    | 'SCAN_URL'
    | 'CHANGE_PASSWORD'
    | 'UPDATE_PROFILE'
    | 'ADMIN_ACTION'
    | 'LOGOUT'
    | 'OTP_SENT'
    | 'OTP_VERIFIED'
    | 'PASSWORD_RESET_REQ'
    | 'PASSWORD_RESET_EXEC'
    | 'GOOGLE_AUTH'
    | 'DELETE_ACCOUNT'
    | 'SESSION_TERMINATED';
  details: string;
  ipAddress: string;
  severity: 'INFO' | 'WARN' | 'DANGER' | 'CRITICAL';
}

export interface ThreatDbEntry {
  id: string;
  urlPattern: string;
  threatType: 'Phishing' | 'Malware' | 'Typosquatting' | 'Scam' | 'Whitelist';
  addedBy: string;
  addedAt: string;
  status: 'Active' | 'Reviewed';
}

export interface DatasetItem {
  url: string;
  length: number;
  dots: number;
  hyphens: number;
  is_https: number;
  suspicious_words: number;
  is_ip: number;
  label: 0 | 1; // 0=Safe, 1=Phishing
}

export interface ProjectFile {
  name: string;
  path: string;
  type: 'code' | 'data' | 'config' | 'html';
  content: string;
}

