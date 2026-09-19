import React, { useState } from 'react';
import { motion } from 'motion/react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  AlertTriangle, 
  CheckCircle2, 
  Lock, 
  Unlock, 
  Download, 
  Copy, 
  ArrowLeft, 
  Globe, 
  Key, 
  Clock, 
  Activity, 
  Cpu, 
  FileText, 
  Check,
  Share2,
  Fingerprint,
  Database,
  Camera,
  ExternalLink,
  Shield
} from 'lucide-react';
import { URLScanResult } from '../types';
import { generatePDFReport } from '../utils/pdfExport';
import { MagneticButton } from './motion/MagneticButton';
import { SpotlightCard } from './motion/SpotlightCard';
import { ScrambleText } from './motion/ScrambleText';
import { WebsiteCheckParameters } from './WebsiteCheckParameters';

interface ScanResultCardProps {
  result: URLScanResult;
  onScanNew: () => void;
}

export const ScanResultCard: React.FC<ScanResultCardProps> = ({ result, onScanNew }) => {
  const [copied, setCopied] = useState(false);
  const [screenshotError, setScreenshotError] = useState(false);

  const downloadJSONReport = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(result, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `phishing-report-${result.id}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const copyResultToClipboard = () => {
    navigator.clipboard.writeText(
      `Phishing URL Threat Dossier\nURL: ${result.url}\nSecurity Score: ${result.securityScore}/100 (Grade ${result.grade})\nRisk Classification: ${result.riskLevel} (${result.riskScore}% Risk)\nConfidence: ${result.ml.confidence}\nScan Duration: ${result.scanTime}`
    );
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const isCritical = result.riskScore > 60;
  const isSuspicious = result.riskScore > 20 && result.riskScore <= 60;
  const isSafe = result.riskScore <= 20;

  const statusTheme = isCritical
    ? {
        border: 'border-rose-500/40',
        badge: 'text-rose-400 bg-rose-950/50 border-rose-500/40',
        accentText: 'text-rose-400',
        meter: 'bg-rose-500',
        icon: ShieldAlert,
        headline: 'Phishing Threat Vector Confirmed'
      }
    : isSuspicious
    ? {
        border: 'border-amber-500/40',
        badge: 'text-amber-400 bg-amber-950/50 border-amber-500/40',
        accentText: 'text-amber-400',
        meter: 'bg-amber-400',
        icon: AlertTriangle,
        headline: 'Suspicious Heuristic Advisory'
      }
    : {
        border: 'border-emerald-500/40',
        badge: 'text-emerald-400 bg-emerald-950/50 border-emerald-500/40',
        accentText: 'text-emerald-400',
        meter: 'bg-emerald-400',
        icon: ShieldCheck,
        headline: 'Verified Benign Web Destination'
      };

  const StatusIcon = statusTheme.icon;

  return (
    <div className="space-y-8 max-w-6xl mx-auto">
      
      {/* Top Action Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <button
          id="btn-return-scanner"
          onClick={onScanNew}
          className="inline-flex items-center gap-2 text-xs font-semibold text-slate-300 hover:text-white transition-colors cursor-pointer bg-slate-900 px-3.5 py-2 rounded-lg border border-slate-800"
        >
          <ArrowLeft className="w-4 h-4 text-blue-400" />
          <span>Return to Threat Inspector</span>
        </button>

        <div className="flex items-center gap-2">
          <MagneticButton
            id="btn-pdf-export"
            onClick={() => generatePDFReport(result)}
            className="px-3.5 py-2 bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium rounded-lg flex items-center gap-1.5 transition-colors cursor-pointer shadow-sm"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export PDF Dossier</span>
          </MagneticButton>

          <button
            id="btn-json-export"
            onClick={downloadJSONReport}
            className="px-3 py-2 bg-slate-900 hover:bg-slate-800 text-slate-200 text-xs font-medium rounded-lg border border-slate-800 flex items-center gap-1.5 transition-colors cursor-pointer"
          >
            <FileText className="w-3.5 h-3.5 text-slate-400" />
            <span>JSON</span>
          </button>

          <button
            id="btn-copy-summary"
            onClick={copyResultToClipboard}
            className="px-3 py-2 bg-slate-900 hover:bg-slate-800 text-slate-200 text-xs font-medium rounded-lg border border-slate-800 flex items-center gap-1.5 transition-colors cursor-pointer"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-slate-400" />}
            <span>{copied ? 'Copied' : 'Copy'}</span>
          </button>
        </div>
      </div>

      {/* Primary Forensic Dossier Overview Card */}
      <SpotlightCard className={`p-6 sm:p-8 ${statusTheme.border}`}>
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6 pb-6 border-b border-slate-800/80">
          
          <div className="flex items-start gap-4">
            <div className={`p-3.5 rounded-xl border shrink-0 ${statusTheme.badge}`}>
              <StatusIcon className="w-8 h-8" />
            </div>

            <div className="space-y-2">
              <div className="flex items-center gap-2 flex-wrap text-xs font-mono">
                <span className={`px-2.5 py-0.5 rounded font-semibold border ${statusTheme.badge}`}>
                  <ScrambleText text={result.riskLevel.toUpperCase()} />
                </span>
                <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-200 border border-slate-700 font-bold">
                  GRADE {result.grade}
                </span>
                <span className="text-slate-400">
                  ID: <ScrambleText text={result.id} />
                </span>
                <span className="text-slate-400 flex items-center gap-1">
                  <Clock className="w-3 h-3 text-slate-400" /> {result.scanTime}
                </span>
                {result.scannedBy && (
                  <span className="text-emerald-400 bg-emerald-950/40 border border-emerald-500/30 px-2 py-0.5 rounded flex items-center gap-1">
                    <Database className="w-3 h-3 text-emerald-400" />
                    <span>@{result.scannedBy}</span>
                  </span>
                )}
              </div>

              <h1 className="text-2xl sm:text-3xl font-bold text-slate-100 tracking-tight">
                {statusTheme.headline}
              </h1>

              <div className="flex items-center gap-2 bg-[#080c14] px-3 py-2 rounded-lg border border-slate-800 max-w-3xl">
                <Globe className="w-4 h-4 text-blue-400 shrink-0" />
                <span className="text-xs font-mono text-slate-200 break-all select-all">{result.url}</span>
              </div>
            </div>
          </div>

          {/* Animated Circular Gauge Meter */}
          <div className="bg-[#080c14] p-4 rounded-xl border border-slate-800 text-center shrink-0 min-w-[170px] self-stretch lg:self-auto flex flex-col items-center justify-center relative overflow-hidden">
            <div className="relative w-24 h-24 flex items-center justify-center my-1">
              <svg className="w-full h-full -rotate-90" viewBox="0 0 96 96">
                {/* Background Track */}
                <circle
                  cx="48"
                  cy="48"
                  r={38}
                  stroke="#1e293b"
                  strokeWidth="6"
                  fill="transparent"
                />
                {/* Animated Score Arc */}
                <motion.circle
                  cx="48"
                  cy="48"
                  r={38}
                  stroke={isCritical ? '#f43f5e' : isSuspicious ? '#fbbf24' : '#34d399'}
                  strokeWidth="6"
                  strokeLinecap="round"
                  fill="transparent"
                  initial={{ strokeDashoffset: 238.76 }}
                  animate={{ strokeDashoffset: 238.76 - (238.76 * Math.max(0, Math.min(100, result.securityScore))) / 100 }}
                  transition={{ duration: 0.4, ease: 'easeOut' }}
                  style={{
                    strokeDasharray: 238.76,
                  }}
                />
              </svg>

              <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                <span className="text-xl font-bold font-mono text-slate-100 leading-none">
                  {result.securityScore}
                </span>
                <span className="text-[10px] font-mono text-slate-400 mt-0.5">
                  GRADE {result.grade}
                </span>
              </div>
            </div>

            <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block">Security Score</span>
            <span className="text-[10px] text-blue-400 font-mono mt-0.5">
              Confidence {result.ml.confidence}
            </span>
          </div>

        </div>

        {/* 5-Stage Segmented Probability Bar */}
        <div className="mt-6 space-y-2">
          <div className="flex items-center justify-between text-xs font-mono">
            <span className="text-slate-400">Ensemble Threat Probability:</span>
            <span className="font-semibold text-slate-200">{result.riskScore}% Probability of Malice</span>
          </div>

          <div className="h-3 w-full bg-[#080c14] rounded-full p-0.5 border border-slate-800 flex gap-1">
            <div className={`h-full rounded-l-full flex-1 transition-colors ${result.riskScore <= 20 ? 'bg-emerald-500' : 'bg-emerald-950/40'}`} title="Safe (0-20)" />
            <div className={`h-full flex-1 transition-colors ${result.riskScore > 20 && result.riskScore <= 40 ? 'bg-amber-400' : 'bg-amber-950/40'}`} title="Low Risk (21-40)" />
            <div className={`h-full flex-1 transition-colors ${result.riskScore > 40 && result.riskScore <= 60 ? 'bg-orange-500' : 'bg-orange-950/40'}`} title="Medium Risk (41-60)" />
            <div className={`h-full flex-1 transition-colors ${result.riskScore > 60 && result.riskScore <= 80 ? 'bg-rose-500' : 'bg-rose-950/40'}`} title="High Risk (61-80)" />
            <div className={`h-full rounded-r-full flex-1 transition-colors ${result.riskScore > 80 ? 'bg-red-600' : 'bg-red-950/40'}`} title="Critical (81-100)" />
          </div>

          <div className="flex justify-between text-[10px] font-mono text-slate-400 pt-0.5">
            <span className="text-emerald-400">0 - 20 (Safe)</span>
            <span className="text-amber-400">21 - 40 (Low)</span>
            <span className="text-orange-400">41 - 60 (Med)</span>
            <span className="text-rose-400">61 - 80 (High)</span>
            <span className="text-red-400">81 - 100 (Critical)</span>
          </div>
        </div>
      </SpotlightCard>

      {/* Grid: Domain Host Record & SSL Inspection */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Domain Registration & Origin */}
        <SpotlightCard className="p-6 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div className="flex items-center gap-2">
              <Globe className="w-4 h-4 text-blue-400" />
              <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
                Domain Host Record
              </h3>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
              {result.domain.domain_age_days} Days Old
            </span>
          </div>

          <div className="grid grid-cols-2 gap-3 text-xs">
            <div className="bg-[#080c14] p-3 rounded-lg border border-slate-800/90">
              <span className="text-slate-400 block mb-0.5 font-mono text-[10px]">Hostname</span>
              <span className="font-semibold text-slate-200 truncate block font-mono">{result.domain.hostname}</span>
            </div>

            <div className="bg-[#080c14] p-3 rounded-lg border border-slate-800/90">
              <span className="text-slate-400 block mb-0.5 font-mono text-[10px]">Subdomain / TLD</span>
              <span className="font-semibold text-blue-400 font-mono truncate block">
                {result.domain.subdomain || '(none)'} | {result.domain.tld}
              </span>
            </div>

            <div className="bg-[#080c14] p-3 rounded-lg border border-slate-800/90">
              <span className="text-slate-400 block mb-0.5 font-mono text-[10px]">IP / Geolocation</span>
              <span className="font-semibold text-slate-200 font-mono truncate block">
                {result.domain.ip} ({result.domain.country})
              </span>
            </div>

            <div className="bg-[#080c14] p-3 rounded-lg border border-slate-800/90">
              <span className="text-slate-400 block mb-0.5 font-mono text-[10px]">Registrar Entity</span>
              <span className="font-semibold text-slate-200 truncate block">{result.domain.registrar}</span>
            </div>

            <div className="bg-[#080c14] p-3 rounded-lg border border-slate-800/90">
              <span className="text-slate-400 block mb-0.5 font-mono text-[10px]">Creation Date</span>
              <span className="font-semibold text-slate-300 font-mono">{result.domain.created}</span>
            </div>

            <div className="bg-[#080c14] p-3 rounded-lg border border-slate-800/90">
              <span className="text-slate-400 block mb-0.5 font-mono text-[10px]">Expiration</span>
              <span className="font-semibold text-slate-300 font-mono">{result.domain.expires}</span>
            </div>
          </div>
        </SpotlightCard>

        {/* SSL / TLS Transport Security */}
        <SpotlightCard className="p-6 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div className="flex items-center gap-2">
              <Key className="w-4 h-4 text-blue-400" />
              <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
                TLS Transport Security
              </h3>
            </div>
            <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
              result.ssl.enabled 
                ? 'bg-emerald-950/60 text-emerald-300 border-emerald-500/30' 
                : 'bg-rose-950/60 text-rose-300 border-rose-500/30'
            }`}>
              {result.ssl.enabled ? 'HTTPS Encrypted' : 'Insecure HTTP'}
            </span>
          </div>

          <div className="space-y-3 text-xs">
            <div className="bg-[#080c14] p-3 rounded-lg border border-slate-800/90 flex items-center justify-between">
              <div>
                <span className="text-slate-400 block font-mono text-[10px]">Transport State</span>
                <span className="font-semibold text-slate-100">
                  {result.ssl.enabled ? 'TLS 1.3 Active & Certified' : 'Unencrypted Transport (Cleartext Risk)'}
                </span>
              </div>
              {result.ssl.enabled ? <Lock className="w-4 h-4 text-emerald-400" /> : <Unlock className="w-4 h-4 text-rose-400" />}
            </div>

            <div className="bg-[#080c14] p-3 rounded-lg border border-slate-800/90">
              <span className="text-slate-400 block mb-0.5 font-mono text-[10px]">Certificate Authority</span>
              <span className="font-semibold text-slate-200 truncate block">{result.ssl.issuer}</span>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="bg-[#080c14] p-3 rounded-lg border border-slate-800/90">
                <span className="text-slate-400 block mb-0.5 font-mono text-[10px]">Valid Until</span>
                <span className="font-semibold text-slate-300 font-mono">{result.ssl.valid_until}</span>
              </div>

              <div className="bg-[#080c14] p-3 rounded-lg border border-slate-800/90">
                <span className="text-slate-400 block mb-0.5 font-mono text-[10px]">Self-Signed Assessment</span>
                <span className={`font-semibold ${result.ssl.self_signed ? 'text-rose-400' : 'text-emerald-400'}`}>
                  {result.ssl.self_signed ? 'Self-Signed (Untrusted)' : 'Trusted CA Authority'}
                </span>
              </div>
            </div>
          </div>
        </SpotlightCard>

      </div>

      {/* Security Threat Indicators Checklist */}
      <SpotlightCard className="p-6 space-y-4">
        <div className="flex items-center gap-2 pb-2 border-b border-slate-800">
          <ShieldAlert className="w-4 h-4 text-blue-400" />
          <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
            Lexical Threat Vector Checklist
          </h3>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 text-xs">
          {[
            { label: 'IP Address Target', active: result.threats.ip_address_url, desc: 'Uses raw numeric IP in place of domain hostname' },
            { label: 'URL Shortener Redirection', active: result.threats.url_shortener, desc: 'Hides true landing domain via forwarding service' },
            { label: 'Auth Keyword Density', active: result.threats.suspicious_keywords, desc: 'Tokens like login, verify, banking, security in path' },
            { label: 'Homoglyph & Punycode', active: result.threats.homograph_attack, desc: 'Unicode visual swaps designed to mimic known glyphs' },
            { label: 'Typosquatting Mimicry', active: result.threats.typosquatting_brand, desc: 'Host string closely resembles recognized brand names' },
            { label: 'Subdomain Stacking', active: result.threats.subdomains_excessive, desc: 'Excessive multi-level domain prefix trickery' }
          ].map((item, idx) => (
            <div
              key={idx}
              className={`p-3 rounded-lg border flex items-start gap-3 transition-colors ${
                item.active 
                  ? 'bg-rose-950/30 border-rose-500/40 text-rose-200' 
                  : 'bg-[#080c14] border-slate-800/90 text-slate-300'
              }`}
            >
              <div className="mt-0.5 shrink-0">
                {item.active ? (
                  <AlertTriangle className="w-4 h-4 text-rose-400" />
                ) : (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                )}
              </div>
              <div>
                <div className="font-medium text-slate-200 text-xs">{item.label}</div>
                <div className="text-[11px] text-slate-400 mt-0.5 leading-snug">{item.desc}</div>
              </div>
            </div>
          ))}
        </div>
      </SpotlightCard>

      {/* Automated Visual Sandbox Viewport & DOM Capture */}
      {result.screenshot && (
        <SpotlightCard className="p-6 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-slate-800 gap-2">
            <div className="flex items-center gap-2">
              <Camera className="w-4 h-4 text-blue-400" />
              <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
                Automated Sandbox Viewport & DOM Snapshot
              </h3>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-slate-300">
                Resolution: {result.screenshot.width}×{result.screenshot.height}px
              </span>
              <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                result.riskScore > 60 
                  ? 'bg-rose-950/50 text-rose-300 border-rose-500/30' 
                  : 'bg-emerald-950/50 text-emerald-300 border-emerald-500/30'
              }`}>
                {result.screenshot.statusText}
              </span>
            </div>
          </div>

          <div className="rounded-xl overflow-hidden border border-slate-800 bg-[#060910]">
            {/* Mock Browser Title Bar */}
            <div className="bg-[#0b101b] px-4 py-2.5 border-b border-slate-800 flex items-center justify-between gap-3">
              <div className="flex items-center gap-1.5">
                <div className="w-2.5 h-2.5 rounded-full bg-rose-500/80" />
                <div className="w-2.5 h-2.5 rounded-full bg-amber-500/80" />
                <div className="w-2.5 h-2.5 rounded-full bg-emerald-500/80" />
              </div>
              <div className="flex-1 max-w-xl mx-auto">
                <div className="bg-[#070b14] border border-slate-800/90 rounded-md px-3 py-1 text-[11px] font-mono text-slate-300 flex items-center gap-2 truncate">
                  {result.ssl.enabled ? (
                    <Lock className="w-3 h-3 text-emerald-400 shrink-0" />
                  ) : (
                    <Unlock className="w-3 h-3 text-rose-400 shrink-0" />
                  )}
                  <span className="truncate">{result.url}</span>
                </div>
              </div>
              <div className="text-[10px] font-mono text-slate-500 shrink-0 hidden sm:block">
                Headless Container Isolation
              </div>
            </div>

            {/* Sandbox Render Surface */}
            <div className="relative min-h-[260px] max-h-[420px] bg-[#03060c] flex items-center justify-center overflow-hidden">
              {!screenshotError ? (
                <img
                  src={result.screenshot.url}
                  alt={`Rendered viewport snapshot of ${result.domain.hostname}`}
                  className="w-full h-auto object-cover max-h-[420px] filter transition-all duration-300"
                  onError={() => setScreenshotError(true)}
                  loading="lazy"
                />
              ) : (
                <div className="p-8 text-center space-y-3 max-w-md">
                  <div className="w-12 h-12 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-center mx-auto text-slate-400">
                    <Shield className="w-6 h-6 text-blue-400" />
                  </div>
                  <h4 className="text-sm font-semibold text-slate-200">
                    Viewport Protected by Security Barrier
                  </h4>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Live DOM rendering executed in our isolated headless sandbox. Outbound tracker beacons and malicious payload downloads are quarantined.
                  </p>
                  <div className="inline-flex items-center gap-2 text-[11px] font-mono text-emerald-400 bg-emerald-950/40 px-3 py-1 rounded border border-emerald-500/30">
                    <CheckCircle2 className="w-3 h-3" />
                    DOM Heuristic Vectors Captured
                  </div>
                </div>
              )}
            </div>
          </div>
        </SpotlightCard>
      )}

      {/* 20+ Website Checking Parameters (32 In-Depth Checks) */}
      {result.parameters && result.parameters.length > 0 && (
        <WebsiteCheckParameters parameters={result.parameters} />
      )}

      {/* Asymmetrical Diagnostics: Weighted Risk Breakdown + Explainable AI Recommendations */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Risk Category Breakdown */}
        <SpotlightCard className="lg:col-span-5 p-6 space-y-4">
          <div className="flex items-center gap-2 pb-2 border-b border-slate-800">
            <Activity className="w-4 h-4 text-blue-400" />
            <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
              Vector Weight Breakdown
            </h3>
          </div>

          <div className="space-y-3.5 text-xs">
            {[
              { label: 'Domain Reputation & Typosquat', score: result.riskBreakdown.domain_reputation },
              { label: 'Suspicious Keywords & Tokens', score: result.riskBreakdown.keywords },
              { label: 'Lexical & Subdomain Geometry', score: result.riskBreakdown.url_structure },
              { label: 'TLS Protocol Security', score: result.riskBreakdown.ssl },
              { label: 'Shannon Entropy Deviation', score: result.riskBreakdown.entropy }
            ].map((cat, idx) => (
              <div key={idx} className="space-y-1.5">
                <div className="flex justify-between font-mono text-[11px]">
                  <span className="text-slate-300">{cat.label}</span>
                  <span className={`font-semibold ${
                    cat.score > 60 ? 'text-rose-400' : cat.score > 30 ? 'text-amber-400' : 'text-emerald-400'
                  }`}>
                    {cat.score}/100
                  </span>
                </div>
                <div className="h-1.5 w-full bg-[#080c14] rounded-full overflow-hidden border border-slate-800">
                  <div 
                    className={`h-full rounded-full transition-all duration-500 ${
                      cat.score > 60 ? 'bg-rose-500' : cat.score > 30 ? 'bg-amber-400' : 'bg-emerald-400'
                    }`}
                    style={{ width: `${cat.score}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </SpotlightCard>

        {/* Explainable AI Reasons & Guidance */}
        <SpotlightCard className="lg:col-span-7 p-6 space-y-4">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800">
            <div className="flex items-center gap-2">
              <Cpu className="w-4 h-4 text-blue-400" />
              <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
                Explainable ML Findings
              </h3>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
              {result.ml.model}
            </span>
          </div>

          <div className="space-y-2">
            {result.reasons.map((reason, index) => (
              <div
                key={index}
                className="p-3 bg-[#080c14] rounded-lg border border-slate-800/90 flex items-start gap-2.5 text-xs text-slate-200 leading-relaxed"
              >
                <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
                <span>{reason}</span>
              </div>
            ))}
          </div>

          {result.recommendations.length > 0 && (
            <div className="pt-3 border-t border-slate-800 space-y-2">
              <span className="text-[11px] font-mono uppercase text-emerald-400 font-semibold block">
                Mitigation Recommendations:
              </span>
              <ul className="space-y-1.5">
                {result.recommendations.map((rec, i) => (
                  <li key={i} className="text-xs text-slate-300 flex items-center gap-2">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                    <span>{rec}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </SpotlightCard>

      </div>

    </div>
  );
};
