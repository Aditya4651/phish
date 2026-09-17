import React, { useState, useEffect } from 'react';
import { motion } from 'motion/react';
import { 
  Shield, 
  Radio, 
  Activity, 
  Terminal, 
  Cpu, 
  Zap, 
  Lock, 
  CheckCircle2, 
  Scan,
  Crosshair,
  RefreshCw,
  Eye,
  AlertTriangle
} from 'lucide-react';
import { SpotlightCard } from './motion/SpotlightCard';

interface ThreatPing {
  id: string;
  x: number; // percentage in radar
  y: number;
  label: string;
  type: 'phishing' | 'safe' | 'suspicious';
  angle: number; // in degrees
}

const INITIAL_PINGS: ThreatPing[] = [
  { id: 'p1', x: 68, y: 32, label: 'amazon-arrived.com', type: 'phishing', angle: 45 },
  { id: 'p2', x: 28, y: 70, label: 'paypal-login-secure.com', type: 'phishing', angle: 220 },
  { id: 'p3', x: 75, y: 65, label: 'micr0soft-auth.com', type: 'phishing', angle: 135 },
  { id: 'p4', x: 35, y: 35, label: 'google.com (Benign)', type: 'safe', angle: 310 },
  { id: 'p5', x: 50, y: 22, label: 'cdn-token-verify.net', type: 'suspicious', angle: 350 },
];

export const CyberDefenseAnimation: React.FC = () => {
  const [activeStep, setActiveStep] = useState(0);
  const [pulseCount, setPulseCount] = useState(0);
  const [isManualScanning, setIsManualScanning] = useState(false);
  const [selectedPing, setSelectedPing] = useState<ThreatPing | null>(null);

  // Staggered telemetry boot sequence on initial visit
  useEffect(() => {
    const timers = [
      setTimeout(() => setActiveStep(1), 400),
      setTimeout(() => setActiveStep(2), 900),
      setTimeout(() => setActiveStep(3), 1500),
      setTimeout(() => setActiveStep(4), 2100),
    ];
    return () => timers.forEach(clearTimeout);
  }, []);

  const triggerDiagnosticPulse = () => {
    setIsManualScanning(true);
    setPulseCount(prev => prev + 1);
    setTimeout(() => {
      setIsManualScanning(false);
    }, 1400);
  };

  return (
    <SpotlightCard className="p-5 sm:p-6 overflow-hidden relative border-slate-800 bg-[#0c0e15]">
      {/* Subtle Background Architectural Grid */}
      <div 
        className="absolute inset-0 opacity-[0.025] pointer-events-none"
        style={{
          backgroundImage: `
            linear-gradient(to right, #ffffff 1px, transparent 1px),
            linear-gradient(to bottom, #ffffff 1px, transparent 1px)
          `,
          backgroundSize: '24px 24px'
        }}
      />

      {/* Top Banner Status Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800/80 relative z-10">
        <div className="flex items-center gap-2.5">
          <div className="relative flex items-center justify-center">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-ping absolute" />
            <span className="w-2 h-2 rounded-full bg-emerald-400 relative" />
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono font-bold text-slate-200 tracking-wider uppercase">
              DEFENSE SENTINEL HUD • HEURISTIC ACTIVE
            </span>
            <span className="hidden md:inline-block px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800/90 text-slate-300 border border-slate-700/80">
              AUTONOMOUS V2.4
            </span>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="font-mono text-[11px] text-slate-400 flex items-center gap-1.5">
            <Activity className="w-3.5 h-3.5 text-blue-400" />
            <span>THREAT RADAR: 360° SWEEP</span>
          </div>

          <button
            onClick={triggerDiagnosticPulse}
            disabled={isManualScanning}
            className="px-2.5 py-1 rounded-lg bg-slate-800/90 hover:bg-slate-750 border border-slate-700 text-[11px] font-mono text-slate-200 hover:text-white transition-all flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
            title="Send radar diagnostic pulse"
          >
            <RefreshCw className={`w-3 h-3 ${isManualScanning ? 'animate-spin' : ''}`} />
            <span>{isManualScanning ? 'Pulsing...' : 'Diagnostic Ping'}</span>
          </button>
        </div>
      </div>

      {/* Main Cybersecurity Animation Stage */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center pt-4 relative z-10">
        
        {/* Left Column: Cyber Radar HUD Sweep (Animated Canvas/SVG) */}
        <div className="lg:col-span-5 flex flex-col items-center justify-center p-3">
          <div className="relative w-56 h-56 sm:w-64 sm:h-64 rounded-full border border-slate-800 bg-[#090b10] flex items-center justify-center shadow-inner overflow-hidden">
            
            {/* Concentric Radar Rings */}
            <div className="absolute inset-4 rounded-full border border-slate-800/80" />
            <div className="absolute inset-10 rounded-full border border-slate-800/60" />
            <div className="absolute inset-18 rounded-full border border-slate-800/40" />
            <div className="absolute inset-26 rounded-full border border-slate-800/30" />

            {/* Crosshairs */}
            <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
              <div className="w-full h-[1px] bg-slate-800/60" />
              <div className="h-full w-[1px] bg-slate-800/60 absolute" />
            </div>

            {/* Radar Coordinates Markers */}
            <span className="absolute top-1 text-[8px] font-mono text-slate-500">000° N</span>
            <span className="absolute bottom-1 text-[8px] font-mono text-slate-500">180° S</span>
            <span className="absolute right-1 text-[8px] font-mono text-slate-500">090° E</span>
            <span className="absolute left-1 text-[8px] font-mono text-slate-500">270° W</span>

            {/* Continuous Rotating Radar Sweep Beam */}
            <motion.div
              animate={{ rotate: 360 }}
              transition={{ repeat: Infinity, duration: 4.5, ease: 'linear' }}
              className="absolute inset-0 pointer-events-none"
              style={{ transformOrigin: 'center center' }}
            >
              <div 
                className="w-1/2 h-1/2 absolute top-0 right-0 origin-bottom-left"
                style={{
                  background: 'conic-gradient(from 0deg, rgba(59, 130, 246, 0.16) 0deg, transparent 65deg)'
                }}
              />
              <div className="w-1/2 h-[1px] bg-blue-400/60 absolute top-1/2 right-0 origin-left" />
            </motion.div>

            {/* Expanding Shockwave Pulse on Diagnostic Ping */}
            <motion.div
              key={`pulse-${pulseCount}`}
              initial={{ scale: 0.1, opacity: 0.8 }}
              animate={{ scale: 1.15, opacity: 0 }}
              transition={{ duration: 1.2, ease: 'easeOut' }}
              className="absolute inset-0 rounded-full border border-blue-400/50 pointer-events-none"
            />

            {/* Threat Target Pings Blinking on Radar */}
            {INITIAL_PINGS.map((ping) => {
              const isPhish = ping.type === 'phishing';
              const isSuspicious = ping.type === 'suspicious';
              const isSelected = selectedPing?.id === ping.id;

              return (
                <div
                  key={ping.id}
                  onClick={() => setSelectedPing(selectedPing?.id === ping.id ? null : ping)}
                  className="absolute cursor-pointer group"
                  style={{ left: `${ping.x}%`, top: `${ping.y}%`, transform: 'translate(-50%, -50%)' }}
                  title={`${ping.label} (${ping.type.toUpperCase()})`}
                >
                  <motion.div
                    animate={{
                      scale: [1, 1.4, 1],
                      opacity: [0.7, 1, 0.7]
                    }}
                    transition={{
                      repeat: Infinity,
                      duration: 2,
                      delay: (ping.angle / 360) * 4
                    }}
                    className={`w-3 h-3 rounded-full flex items-center justify-center ${
                      isPhish
                        ? 'bg-rose-500/20 border border-rose-500'
                        : isSuspicious
                        ? 'bg-amber-500/20 border border-amber-500'
                        : 'bg-emerald-500/20 border border-emerald-500'
                    }`}
                  >
                    <div
                      className={`w-1.5 h-1.5 rounded-full ${
                        isPhish ? 'bg-rose-400' : isSuspicious ? 'bg-amber-400' : 'bg-emerald-400'
                      }`}
                    />
                  </motion.div>

                  {/* Micro Target Reticle on Selected / Hover */}
                  {isSelected && (
                    <div className="absolute -top-6 left-1/2 -translate-x-1/2 whitespace-nowrap px-1.5 py-0.5 rounded bg-slate-900/95 border border-blue-500/40 text-[9px] font-mono text-blue-300 shadow-lg pointer-events-none">
                      {ping.label.split('.')[0]}
                    </div>
                  )}
                </div>
              );
            })}

            {/* Central Security Core Badge */}
            <div className="relative z-10 w-9 h-9 rounded-full bg-slate-900 border border-blue-400/50 flex items-center justify-center text-blue-400 shadow-[0_0_15px_rgba(59,130,246,0.25)]">
              <Shield className="w-4 h-4 text-blue-400" />
            </div>

          </div>

          <div className="mt-3 flex items-center gap-3 text-[10px] font-mono text-slate-400">
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-rose-500" /> Malicious
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-amber-500" /> Suspicious
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-emerald-500" /> Benign
            </span>
          </div>
        </div>

        {/* Right Column: Tactical Telemetry Terminal & Security Stages */}
        <div className="lg:col-span-7 space-y-3">
          
          <div className="flex items-center justify-between font-mono text-xs text-slate-400 border-b border-slate-800 pb-2">
            <div className="flex items-center gap-2">
              <Terminal className="w-3.5 h-3.5 text-blue-400" />
              <span className="text-slate-200 font-semibold">SECURITY SUBSYSTEM STATUS</span>
            </div>
            <span className="text-emerald-400 text-[11px]">ALL SYSTEMS NOMINAL</span>
          </div>

          {/* Staggered Boot Telemetry Logs */}
          <div className="space-y-2 font-mono text-xs">
            
            {/* Step 1: Lexical Engine */}
            <motion.div
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: activeStep >= 1 ? 1 : 0.25, x: activeStep >= 1 ? 0 : -10 }}
              transition={{ duration: 0.3 }}
              className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800 flex items-center justify-between"
            >
              <div className="flex items-center gap-2.5">
                <CheckCircle2 className={`w-4 h-4 ${activeStep >= 1 ? 'text-emerald-400' : 'text-slate-600'}`} />
                <div>
                  <span className="text-slate-200 font-medium">32 Heuristic Parameters Arming</span>
                  <span className="text-slate-400 block text-[10px]">RFC 3986 • OWASP • Shannon Entropy</span>
                </div>
              </div>
              <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-950/70 text-emerald-300 border border-emerald-800/40">
                READY
              </span>
            </motion.div>

            {/* Step 2: Typosquatting / Punycode Watcher */}
            <motion.div
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: activeStep >= 2 ? 1 : 0.25, x: activeStep >= 2 ? 0 : -10 }}
              transition={{ duration: 0.3 }}
              className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800 flex items-center justify-between"
            >
              <div className="flex items-center gap-2.5">
                <CheckCircle2 className={`w-4 h-4 ${activeStep >= 2 ? 'text-emerald-400' : 'text-slate-600'}`} />
                <div>
                  <span className="text-slate-200 font-medium">Levenshtein Brand Squatting Filter</span>
                  <span className="text-slate-400 block text-[10px]">Homoglyph Swaps • IDN Punycode Scanner</span>
                </div>
              </div>
              <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-950/70 text-emerald-300 border border-emerald-800/40">
                ACTIVE
              </span>
            </motion.div>

            {/* Step 3: Neural Model Inference Engine */}
            <motion.div
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: activeStep >= 3 ? 1 : 0.25, x: activeStep >= 3 ? 0 : -10 }}
              transition={{ duration: 0.3 }}
              className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800 flex items-center justify-between"
            >
              <div className="flex items-center gap-2.5">
                <CheckCircle2 className={`w-4 h-4 ${activeStep >= 3 ? 'text-emerald-400' : 'text-slate-600'}`} />
                <div>
                  <span className="text-slate-200 font-medium">RandomForest Ensemble Model</span>
                  <span className="text-slate-400 block text-[10px]">100 Decision Trees • ~14ms Inference</span>
                </div>
              </div>
              <span className="text-[10px] px-2 py-0.5 rounded bg-blue-950/50 text-blue-300 border border-blue-800/40">
                99.2% CONFIDENCE
              </span>
            </motion.div>

            {/* Step 4: Privacy & Sandboxing */}
            <motion.div
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: activeStep >= 4 ? 1 : 0.25, x: activeStep >= 4 ? 0 : -10 }}
              transition={{ duration: 0.3 }}
              className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800 flex items-center justify-between"
            >
              <div className="flex items-center gap-2.5">
                <CheckCircle2 className={`w-4 h-4 ${activeStep >= 4 ? 'text-emerald-400' : 'text-slate-600'}`} />
                <div>
                  <span className="text-slate-200 font-medium">Memory Isolation & Airgap Sandbox</span>
                  <span className="text-slate-400 block text-[10px]">Zero DNS Exfiltration • Client-Safe Evaluation</span>
                </div>
              </div>
              <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                ENFORCED
              </span>
            </motion.div>

          </div>

          {/* Selected Threat Callout if user clicks a radar node */}
          {selectedPing && (
            <motion.div
              initial={{ opacity: 0, y: 5 }}
              animate={{ opacity: 1, y: 0 }}
              className="p-3 rounded-lg bg-[#11141e] border border-slate-700 text-xs font-mono flex items-center justify-between gap-3"
            >
              <div className="flex items-center gap-2">
                <AlertTriangle className={`w-4 h-4 ${selectedPing.type === 'phishing' ? 'text-rose-400' : 'text-amber-400'}`} />
                <div>
                  <div className="text-slate-200 font-semibold">{selectedPing.label}</div>
                  <div className="text-[10px] text-slate-400">Target Bearing: {selectedPing.angle}° azimuth • Sector Quadrant Alpha</div>
                </div>
              </div>
              <span className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase ${
                selectedPing.type === 'phishing' ? 'bg-rose-950 text-rose-300 border border-rose-800' : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
              }`}>
                {selectedPing.type}
              </span>
            </motion.div>
          )}

        </div>

      </div>
    </SpotlightCard>
  );
};
