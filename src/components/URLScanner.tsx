import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  Search, 
  Globe, 
  Cpu, 
  Terminal, 
  Lock, 
  AlertTriangle, 
  ShieldCheck, 
  ShieldAlert, 
  ArrowRight, 
  Sparkles, 
  Binary, 
  Hash, 
  CornerDownLeft,
  X,
  Layers,
  Fingerprint,
  Clipboard,
  Activity
} from 'lucide-react';
import { URLScanResult, User } from '../types';
import { classifyURL } from '../utils/mlClassifier';
import { MagneticButton } from './motion/MagneticButton';
import { SpotlightCard } from './motion/SpotlightCard';
import { CyberDefenseAnimation } from './CyberDefenseAnimation';
import { CyberEarthGlobe } from './CyberEarthGlobe';

interface URLScannerProps {
  onScanComplete: (result: URLScanResult) => void;
  user?: User;
  onOpenLogin?: () => void;
}

interface BenchmarkSample {
  label: string;
  category: string;
  url: string;
  expectedRisk: string;
  badgeColor: string;
  description: string;
}

const BENCHMARK_SAMPLES: BenchmarkSample[] = [
  {
    label: 'Amazon Order Impersonator',
    category: 'Typosquatting',
    url: 'https://amazon-arrived.com/track/order?id=92811',
    expectedRisk: 'High Risk (98%)',
    badgeColor: 'text-rose-400 border-rose-500/30 bg-rose-950/40',
    description: 'Deceptive sub-keyword prefix designed to mimic parcel delivery updates.'
  },
  {
    label: 'PayPal Credential Harvester',
    category: 'Brand Mimicry',
    url: 'https://paypal-login-secure.com/auth/verify',
    expectedRisk: 'Critical (99%)',
    badgeColor: 'text-rose-400 border-rose-500/30 bg-rose-950/40',
    description: 'Stacked auth keywords with hyphens on unauthorized third-party host.'
  },
  {
    label: 'Micr0soft Leetspeak Attack',
    category: 'Homograph',
    url: 'https://micr0soft-login.com/oauth2/login',
    expectedRisk: 'High Risk (94%)',
    badgeColor: 'text-amber-400 border-amber-500/30 bg-amber-950/40',
    description: 'Numeral "0" substitution exploiting visual similarity to the letter "o".'
  },
  {
    label: 'PaypaI IDN Capital Swap',
    category: 'Glyph Swap',
    url: 'https://paypaI.com/myaccount/home',
    expectedRisk: 'Critical (99%)',
    badgeColor: 'text-rose-400 border-rose-500/30 bg-rose-950/40',
    description: 'Uppercase "I" replacing lowercase "l", appearing identical in sans-serif fonts.'
  },
  {
    label: 'Facebook Account Checkpoint',
    category: 'Suspicious Domain',
    url: 'https://faceb00k-security.com/checkpoint/appeal',
    expectedRisk: 'High Risk (91%)',
    badgeColor: 'text-amber-400 border-amber-500/30 bg-amber-950/40',
    description: 'Double zero substitution paired with urgent appeals social engineering.'
  },
  {
    label: 'Official Google Web Portal',
    category: 'Safe Baseline',
    url: 'https://www.google.com',
    expectedRisk: 'Safe (0.2%)',
    badgeColor: 'text-emerald-400 border-emerald-500/30 bg-emerald-950/40',
    description: 'Verified legitimate destination with zero obfuscation markers.'
  }
];

export const URLScanner: React.FC<URLScannerProps> = ({ 
  onScanComplete, 
  user, 
  onOpenLogin 
}) => {
  const [inputUrl, setInputUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanStep, setScanStep] = useState(0);
  const [scanProgress, setScanProgress] = useState(0);
  const [activeCategory, setActiveCategory] = useState<string>('All');

  const SCAN_STAGES = [
    { title: 'Decomposing RFC 3986 Lexical Anatomy', detail: 'Evaluating 32 parameters, token depth, Shannon entropy & special char ratios' },
    { title: 'Screening Homoglyphs & Levenshtein Matrix', detail: 'Cross-checking 27 apex brands, unicode zero-width characters & IDN Punycode' },
    { title: 'Auditing DNS Tenancy & SSL Handshake', detail: 'Verifying TLS cert lifespan, host authority & domain registration age' },
    { title: 'RandomForest Ensemble Execution', detail: 'Aggregating 100 decision trees for risk classification' }
  ];

  // Handle keyboard shortcut (Enter, ⌘ + Enter, or Ctrl + Enter)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Enter') {
        const activeTag = document.activeElement?.tagName;
        if (inputUrl.trim() && (activeTag === 'INPUT' || activeTag === 'BODY')) {
          executeScan(inputUrl);
        }
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [inputUrl]);

  const executeScan = (targetUrl?: string) => {
    const target = (targetUrl || inputUrl).trim();
    if (!target) return;

    try {
      const result = classifyURL(target);
      onScanComplete(result);
    } catch (err) {
      console.error('Classification error:', err);
    }
  };

  const handlePaste = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        setInputUrl(text.trim());
      }
    } catch {
      // Fallback if browser clipboard permission prompt is denied
    }
  };

  // Instant lexical feedback metrics on the typed string
  const getLivePreview = () => {
    const raw = inputUrl.trim();
    if (!raw) return null;

    let host = raw;
    let protocol = 'none';
    try {
      if (raw.startsWith('http://') || raw.startsWith('https://')) {
        const parsed = new URL(raw);
        host = parsed.hostname;
        protocol = parsed.protocol.replace(':', '');
      } else {
        host = raw.split('/')[0];
      }
    } catch {
      host = raw.split('/')[0];
    }

    const length = raw.length;
    const dotCount = (host.match(/\./g) || []).length;
    const hyphenCount = (host.match(/-/g) || []).length;
    const hasIP = /^(?:\d{1,3}\.){3}\d{1,3}/.test(host);

    return { host, protocol, length, dotCount, hyphenCount, hasIP };
  };

  const liveStats = getLivePreview();

  const filteredSamples = activeCategory === 'All' 
    ? BENCHMARK_SAMPLES 
    : BENCHMARK_SAMPLES.filter(s => s.category === activeCategory);

  const categories = ['All', 'Typosquatting', 'Brand Mimicry', 'Homograph', 'Glyph Swap', 'Safe Baseline'];

  return (
    <div className="space-y-10">
      
      {/* Guest Mode Restriction Callout */}
      {(!user || !user.isLoggedIn) && (
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 sm:p-5 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="flex items-start gap-3">
            <div className="p-2 rounded-lg bg-slate-800 text-slate-300 border border-slate-700/80 shrink-0">
              <Lock className="w-4 h-4 text-blue-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-semibold text-slate-200 uppercase tracking-wide">
                  Guest Analyst Session
                </span>
                <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300 border border-slate-700">
                  Read-Only Preview
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-1 leading-relaxed max-w-2xl">
                You can test reference phishing samples or scan URLs in transient mode. Sign in to record persistent audit logs, unlock raw CSV ingestion, and export signed PDF dossiers.
              </p>
            </div>
          </div>

          <MagneticButton
            onClick={onOpenLogin}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium rounded-lg shrink-0 cursor-pointer shadow-sm transition-colors"
          >
            Clerk Sign In
          </MagneticButton>
        </div>
      )}

      {/* Hero Command Center with 3D Cyber Earth Visualization (Requested Design) */}
      <div className="relative rounded-2xl border border-slate-800/80 bg-[#070b13] p-6 sm:p-8 lg:p-10 overflow-hidden shadow-2xl group">
        {/* Animated Cyber Grid Canvas Background Grid Texture */}
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#1e293b15_1px,transparent_1px),linear-gradient(to_bottom,#1e293b15_1px,transparent_1px)] bg-[size:28px_28px] pointer-events-none opacity-60" />

        {/* Ambient Top Glow Beam */}
        <div className="absolute top-0 left-1/4 right-1/4 h-[1px] bg-gradient-to-r from-transparent via-blue-500/50 to-transparent pointer-events-none" />

        {/* Animated 3D Cyber Earth Globe Component */}
        <div className="absolute -right-20 sm:-right-12 lg:right-[-20px] top-1/2 -translate-y-1/2 w-[340px] h-[340px] sm:w-[480px] sm:h-[480px] lg:w-[600px] lg:h-[600px] pointer-events-none select-none z-0">
          <CyberEarthGlobe isScanning={isScanning} />
        </div>

        {/* Foreground Content Stack */}
        <div className="relative z-10 space-y-6 max-w-2xl lg:max-w-3xl">
          {/* Animated Real-time Threat Intelligence Badge */}
          <motion.div 
            initial={{ opacity: 0, y: -6 }}
            animate={{ opacity: 1, y: 0 }}
            className="inline-flex items-center gap-2.5 px-3.5 py-1.5 rounded-full bg-blue-950/60 border border-blue-500/30 text-[11px] font-mono font-semibold text-blue-400 uppercase tracking-widest backdrop-blur-md shadow-[0_0_15px_rgba(59,130,246,0.15)]"
          >
            {/* Animated Heartbeat / ECG Telemetry Wave */}
            <svg className="w-5 h-3 text-cyan-400 stroke-current" viewBox="0 0 24 12" fill="none">
              <motion.path
                d="M0 6h5l2-5 3 10 3-7 2 4 2-2h7"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
                initial={{ pathOffset: 0 }}
                animate={{ pathOffset: [0, 1] }}
                transition={{ repeat: Infinity, duration: 1.8, ease: "linear" }}
              />
            </svg>
            <span>REAL-TIME THREAT INTELLIGENCE</span>
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-400 shadow-[0_0_8px_#10b981]" />
            </span>
          </motion.div>

          {/* Main Title & Subtitle Requested */}
          <div className="space-y-3">
            <h1 className="text-3xl sm:text-4xl lg:text-5xl font-extrabold text-white tracking-tight leading-tight">
              Inspect, Deconstruct &amp; Classify Suspicious URLs
            </h1>
            <p className="text-sm sm:text-base text-slate-300/90 leading-relaxed font-normal">
              Extract 11 multidimensional lexical vectors—evaluating Shannon entropy, token depth, homoglyph substitutions, and credential harvesting patterns via an ensemble Random Forest model.
            </p>
          </div>

          {/* Integrated Inspection Search Bar with Active Laser Scanning Border Glow */}
          <form
            onSubmit={(e) => {
              e.preventDefault();
              executeScan();
            }}
            className="pt-2 space-y-3"
          >
            {/* Animated Gradient Border Shell */}
            <div className="relative rounded-xl p-[1px] bg-gradient-to-r from-blue-500/40 via-cyan-400/30 to-blue-600/40 shadow-xl focus-within:from-blue-500 focus-within:via-cyan-400 focus-within:to-indigo-500 transition-all">
              <div className="relative flex flex-col sm:flex-row items-stretch sm:items-center gap-2 p-1.5 bg-[#080d17]/95 rounded-[11px] backdrop-blur-md">
                <div className="relative flex-1 flex items-center">
                  <div className="absolute left-3.5 text-slate-400">
                    <Search className={`w-4 h-4 transition-colors ${inputUrl ? 'text-blue-400' : 'text-slate-400'}`} />
                  </div>
                  <input
                    id="url-input"
                    type="text"
                    value={inputUrl}
                    onChange={(e) => setInputUrl(e.target.value)}
                    placeholder="Paste suspicious URL here... (e.g. https://amazon-arrived.com/track/order?id=92811)"
                    autoComplete="off"
                    spellCheck="false"
                    className="w-full bg-transparent text-slate-100 pl-10 pr-20 py-3 text-xs sm:text-sm placeholder:text-slate-500 focus:outline-none font-mono"
                  />
                  <div className="absolute right-2 flex items-center gap-1">
                    {inputUrl ? (
                      <button
                        type="button"
                        onClick={() => setInputUrl('')}
                        className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800/80 rounded cursor-pointer transition-colors"
                        title="Clear input (Esc)"
                      >
                        <X className="w-3.5 h-3.5" />
                      </button>
                    ) : (
                      <button
                        type="button"
                        onClick={handlePaste}
                        className="px-2 py-1 text-[11px] font-mono text-slate-400 hover:text-slate-200 hover:bg-slate-800/80 rounded flex items-center gap-1 cursor-pointer transition-colors border border-transparent hover:border-slate-700"
                        title="Paste from clipboard"
                      >
                        <Clipboard className="w-3 h-3" />
                        <span>Paste</span>
                      </button>
                    )}
                  </div>
                </div>

                <MagneticButton
                  id="btn-execute-scan"
                  type="submit"
                  disabled={isScanning || !inputUrl.trim()}
                  className="relative overflow-hidden px-6 py-3 bg-blue-600 hover:bg-blue-500 disabled:opacity-40 disabled:hover:bg-blue-600 text-white font-medium text-xs sm:text-sm rounded-lg transition-colors cursor-pointer shrink-0 shadow-lg shadow-blue-900/30 gap-2 flex items-center justify-center group/btn"
                >
                  {isScanning ? (
                    <>
                      <Cpu className="w-4 h-4 animate-spin text-white" />
                      <span>Analyzing Target...</span>
                    </>
                  ) : (
                    <>
                      <span>Analyze</span>
                      <ArrowRight className="w-4 h-4 text-white group-hover/btn:translate-x-1 transition-transform" />
                    </>
                  )}
                </MagneticButton>
              </div>
            </div>

            <div className="flex items-center justify-between text-[11px] text-slate-400 font-mono px-1">
              <span className="flex items-center gap-1.5">
                <Globe className="w-3 h-3 text-blue-400" />
                Target RFC 3986 URL
              </span>
              <span className="inline-flex items-center gap-1 bg-slate-800/60 px-2 py-0.5 rounded border border-slate-700/60 text-slate-300">
                <CornerDownLeft className="w-3 h-3 text-slate-400" />
                Enter ↵ to scan
              </span>
            </div>

            {/* Live Lexical Vector Decomposition Ribbon */}
            {liveStats && !isScanning && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                className="pt-3 border-t border-slate-800/80 flex flex-wrap items-center gap-2 text-xs font-mono"
              >
                <span className="text-slate-400">Lexical Preview:</span>
                <span className="px-2 py-0.5 rounded bg-slate-800/80 text-slate-200 border border-slate-700">
                  host: {liveStats.host}
                </span>
                <span className="px-2 py-0.5 rounded bg-slate-800/80 text-slate-300 border border-slate-700">
                  protocol: {liveStats.protocol}
                </span>
                <span className="px-2 py-0.5 rounded bg-slate-800/80 text-slate-300 border border-slate-700">
                  length: {liveStats.length}
                </span>
                <span className="px-2 py-0.5 rounded bg-slate-800/80 text-slate-300 border border-slate-700">
                  dots: {liveStats.dotCount}
                </span>
                <span className="px-2 py-0.5 rounded bg-slate-800/80 text-slate-300 border border-slate-700">
                  hyphens: {liveStats.hyphenCount}
                </span>
                {liveStats.hasIP && (
                  <span className="px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800 font-bold">
                    Raw IP Detected
                  </span>
                )}
              </motion.div>
            )}
          </form>

          {/* Tactical Telemetry Metric Bar */}
          <div className="flex flex-wrap items-center gap-3 pt-3 border-t border-slate-800/70 text-[11px] font-mono text-slate-400">
            <div className="flex items-center gap-1.5 bg-slate-900/60 px-2.5 py-1 rounded-lg border border-slate-800 backdrop-blur-xs">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              <span className="text-slate-500">Classifier:</span>
              <span className="text-slate-200">RandomForest (100 Trees)</span>
            </div>
            <div className="flex items-center gap-1.5 bg-slate-900/60 px-2.5 py-1 rounded-lg border border-slate-800 backdrop-blur-xs">
              <span className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-pulse" />
              <span className="text-slate-500">Inference:</span>
              <span className="text-blue-400 font-medium">Client/Server Hybrid</span>
            </div>
            <div className="flex items-center gap-1.5 bg-slate-900/60 px-2.5 py-1 rounded-lg border border-slate-800 backdrop-blur-xs">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
              <span className="text-slate-500">Privacy:</span>
              <span className="text-slate-200">Zero DNS Leak</span>
            </div>
          </div>
        </div>
      </div>

      {/* Real-time Cybersecurity Sentinel Animation & Defense Radar */}
      <CyberDefenseAnimation />

      {/* Benchmark Testing Suite / Phishing Samples */}
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-base sm:text-lg font-semibold text-slate-100 flex items-center gap-2">
              <Fingerprint className="w-4 h-4 text-blue-400" />
              <span>Reference Threat Vectors & Benchmarks</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Select an attack archetype to populate and inspect the feature extractor in real-time.
            </p>
          </div>

          {/* Category Filter Pills */}
          <div className="flex items-center gap-1 overflow-x-auto pb-1 text-xs p-1 bg-slate-900/80 border border-slate-800/80 rounded-xl">
            {categories.map(cat => (
              <button
                key={cat}
                onClick={() => setActiveCategory(cat)}
                className={`relative px-3 py-1.5 rounded-lg transition-colors cursor-pointer whitespace-nowrap text-[11px] font-medium z-10 ${
                  activeCategory === cat
                    ? 'text-slate-100 font-semibold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {activeCategory === cat && (
                  <motion.div
                    layoutId="benchmark-cat-pill"
                    transition={{ type: 'spring', stiffness: 400, damping: 32 }}
                    className="absolute inset-0 bg-slate-800 rounded-lg border border-slate-700/80 shadow-sm -z-10"
                  />
                )}
                <span>{cat}</span>
              </button>
            ))}
          </div>
        </div>

        {/* Asymmetrical Varied Sample Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {filteredSamples.map((sample, idx) => (
            <SpotlightCard
              key={idx}
              id={`sample-card-${idx}`}
              onClick={() => {
                setInputUrl(sample.url);
                executeScan(sample.url);
              }}
              className="p-4 cursor-pointer hover:border-blue-500/40 hover:-translate-y-0.5 transition-all group flex flex-col justify-between"
            >
              <div className="space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[10px] uppercase font-mono font-semibold px-2 py-0.5 rounded border border-slate-700 bg-slate-800 text-slate-300">
                    {sample.category}
                  </span>
                  <span className={`text-[10px] font-mono px-2 py-0.5 rounded border font-semibold ${sample.badgeColor}`}>
                    {sample.expectedRisk}
                  </span>
                </div>

                <div>
                  <h3 className="text-xs font-semibold text-slate-200 group-hover:text-blue-300 transition-colors">
                    {sample.label}
                  </h3>
                  <div className="font-mono text-[11px] text-slate-400 truncate mt-1 bg-[#090d14] px-2 py-1 rounded border border-slate-800 group-hover:border-slate-700 transition-colors">
                    {sample.url}
                  </div>
                </div>

                <p className="text-[11px] text-slate-400 leading-relaxed">
                  {sample.description}
                </p>
              </div>

              <div className="pt-3 mt-3 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono text-slate-400 group-hover:text-blue-400 transition-colors">
                <span>Evaluate with Classifier</span>
                <ArrowRight className="w-3 h-3 group-hover:translate-x-1 transition-transform" />
              </div>
            </SpotlightCard>
          ))}
        </div>
      </div>

      {/* Technical Feature Extraction Architecture */}
      <div className="border border-slate-800/80 bg-slate-900/40 rounded-xl p-6 space-y-6">
        <div className="flex items-center justify-between flex-wrap gap-2 border-b border-slate-800 pb-4">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-blue-400" />
            <h3 className="text-sm font-semibold text-slate-200">
              11-Vector Heuristic Architecture & Lexical Weights
            </h3>
          </div>
          <span className="text-[11px] font-mono text-slate-400">
            Source: <code className="text-blue-300">src/utils/phishingEngine.ts</code>
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
          <div className="bg-[#080c14] p-3.5 rounded-lg border border-slate-800/80 space-y-1">
            <span className="font-mono text-[11px] text-blue-400 uppercase font-semibold">1. Shannon Entropy</span>
            <p className="text-slate-300 leading-relaxed text-[11px]">
              Calculates logarithmic character randomness. DGA domains exhibit entropy &gt; 4.2 bits per char.
            </p>
          </div>

          <div className="bg-[#080c14] p-3.5 rounded-lg border border-slate-800/80 space-y-1">
            <span className="font-mono text-[11px] text-blue-400 uppercase font-semibold">2. Homoglyph Distance</span>
            <p className="text-slate-300 leading-relaxed text-[11px]">
              Computes Levenshtein matrix against 27 top brands (PayPal, Google, Apple, Microsoft, Amazon).
            </p>
          </div>

          <div className="bg-[#080c14] p-3.5 rounded-lg border border-slate-800/80 space-y-1">
            <span className="font-mono text-[11px] text-blue-400 uppercase font-semibold">3. Host Token Delimiters</span>
            <p className="text-slate-300 leading-relaxed text-[11px]">
              Evaluates sub-domain depth, hyphen frequency, dot density, and hexadecimal percent-encoding.
            </p>
          </div>

          <div className="bg-[#080c14] p-3.5 rounded-lg border border-slate-800/80 space-y-1">
            <span className="font-mono text-[11px] text-blue-400 uppercase font-semibold">4. TLD Risk Coefficient</span>
            <p className="text-slate-300 leading-relaxed text-[11px]">
              Reputation scoring across disposable TLDs (.xyz, .top, .tk, .buzz) known for spam dispersion.
            </p>
          </div>
        </div>
      </div>

    </div>
  );
};
