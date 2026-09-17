import React, { useState, useMemo } from 'react';
import { 
  CheckCircle2, 
  AlertTriangle, 
  XCircle, 
  Search, 
  SlidersHorizontal, 
  Layers, 
  ChevronDown, 
  ChevronUp, 
  ShieldCheck, 
  ShieldAlert, 
  HelpCircle,
  ExternalLink,
  Filter,
  Check,
  Zap,
  Info
} from 'lucide-react';
import { WebsiteCheckParameter, ParameterCategory, ParameterStatus } from '../types';
import { SpotlightCard } from './motion/SpotlightCard';

interface WebsiteCheckParametersProps {
  parameters?: WebsiteCheckParameter[];
}

export const WebsiteCheckParameters: React.FC<WebsiteCheckParametersProps> = ({ parameters = [] }) => {
  const [selectedCategory, setSelectedCategory] = useState<string>('All');
  const [selectedStatus, setSelectedStatus] = useState<string>('All');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [expandedParamId, setExpandedParamId] = useState<string | null>(null);

  const safeParameters = useMemo(() => {
    return Array.isArray(parameters) ? parameters : [];
  }, [parameters]);

  const categories: Array<{ label: string; value: string; count: number }> = useMemo(() => {
    const counts: Record<string, number> = {};
    safeParameters.forEach(p => {
      counts[p.category] = (counts[p.category] || 0) + 1;
    });

    return [
      { label: 'All Parameters', value: 'All', count: safeParameters.length },
      { label: 'Lexical & URL Anatomy', value: 'Lexical & URL Anatomy', count: counts['Lexical & URL Anatomy'] || 0 },
      { label: 'Evasion & Obfuscation', value: 'Evasion & Obfuscation', count: counts['Evasion & Obfuscation'] || 0 },
      { label: 'Domain & Host Reputation', value: 'Domain & Host Reputation', count: counts['Domain & Host Reputation'] || 0 },
      { label: 'SSL & Transport Security', value: 'SSL & Transport Security', count: counts['SSL & Transport Security'] || 0 },
      { label: 'Content & Social Engineering', value: 'Content & Social Engineering', count: counts['Content & Social Engineering'] || 0 }
    ];
  }, [safeParameters]);

  const statusStats = useMemo(() => {
    const passed = safeParameters.filter(p => p.status === 'Pass').length;
    const warnings = safeParameters.filter(p => p.status === 'Warning').length;
    const failed = safeParameters.filter(p => p.status === 'Fail').length;
    const complianceRate = safeParameters.length > 0 
      ? Math.round(((passed + warnings * 0.5) / safeParameters.length) * 100) 
      : 100;

    return { passed, warnings, failed, complianceRate };
  }, [safeParameters]);

  const filteredParameters = useMemo(() => {
    return safeParameters.filter(param => {
      const matchCategory = selectedCategory === 'All' || param.category === selectedCategory;
      const matchStatus = selectedStatus === 'All' || param.status === selectedStatus;
      const query = searchQuery.trim().toLowerCase();
      const matchSearch = !query || 
        param.name.toLowerCase().includes(query) ||
        param.description.toLowerCase().includes(query) ||
        param.displayValue.toLowerCase().includes(query) ||
        (param.benchmarkStandard && param.benchmarkStandard.toLowerCase().includes(query)) ||
        param.category.toLowerCase().includes(query);

      return matchCategory && matchStatus && matchSearch;
    });
  }, [safeParameters, selectedCategory, selectedStatus, searchQuery]);

  const toggleExpand = (id: string) => {
    setExpandedParamId(current => current === id ? null : id);
  };

  return (
    <SpotlightCard className="p-6 sm:p-8 space-y-6">
      {/* Header & Title Section */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2 mb-1.5">
            <Layers className="w-5 h-5 text-blue-400" />
            <h2 className="text-lg sm:text-xl font-bold text-slate-100 tracking-tight">
              20+ Website Checking Parameters ({parameters.length} In-Depth Checks)
            </h2>
          </div>
          <p className="text-xs text-slate-400 max-w-2xl leading-relaxed">
            Multi-layered inspection engine analyzing RFC 3986 lexical anatomy, host reputation, SSL/TLS cryptographic integrity, homoglyphs, and evasive redirect cloaking.
          </p>
        </div>

        {/* Quick Compliance Pill */}
        <div className="flex items-center gap-3 bg-[#080c14] border border-slate-800 p-2.5 rounded-xl self-start md:self-auto">
          <div className="text-right">
            <div className="text-[10px] font-mono text-slate-400 uppercase">Compliance Health</div>
            <div className={`text-base font-bold font-mono ${
              statusStats.complianceRate >= 80 ? 'text-emerald-400' :
              statusStats.complianceRate >= 50 ? 'text-amber-400' : 'text-rose-400'
            }`}>
              {statusStats.complianceRate}%
            </div>
          </div>
          <div className="w-10 h-10 rounded-lg bg-slate-900 flex items-center justify-center border border-slate-800">
            {statusStats.failed === 0 ? (
              <ShieldCheck className="w-5 h-5 text-emerald-400" />
            ) : (
              <ShieldAlert className="w-5 h-5 text-rose-400" />
            )}
          </div>
        </div>
      </div>

      {/* Summary Metrics Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <button
          onClick={() => setSelectedStatus('All')}
          className={`p-3 rounded-xl border text-left transition-all ${
            selectedStatus === 'All' 
              ? 'bg-slate-800/60 border-slate-600' 
              : 'bg-[#080c14] border-slate-800 hover:border-slate-700'
          }`}
        >
          <span className="text-[10px] font-mono uppercase text-slate-400 block">Total Checks</span>
          <div className="flex items-baseline gap-1.5 mt-0.5">
            <span className="text-xl font-bold font-mono text-slate-100">{parameters.length}</span>
            <span className="text-[11px] text-slate-400">active rules</span>
          </div>
        </button>

        <button
          onClick={() => setSelectedStatus('Pass')}
          className={`p-3 rounded-xl border text-left transition-all ${
            selectedStatus === 'Pass' 
              ? 'bg-emerald-950/40 border-emerald-500/50' 
              : 'bg-[#080c14] border-slate-800 hover:border-emerald-800/40'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-mono uppercase text-emerald-400">Passed</span>
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div className="flex items-baseline gap-1.5 mt-0.5">
            <span className="text-xl font-bold font-mono text-emerald-300">{statusStats.passed}</span>
            <span className="text-[11px] text-slate-400">parameters</span>
          </div>
        </button>

        <button
          onClick={() => setSelectedStatus('Warning')}
          className={`p-3 rounded-xl border text-left transition-all ${
            selectedStatus === 'Warning' 
              ? 'bg-amber-950/40 border-amber-500/50' 
              : 'bg-[#080c14] border-slate-800 hover:border-amber-800/40'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-mono uppercase text-amber-400">Warnings</span>
            <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
          </div>
          <div className="flex items-baseline gap-1.5 mt-0.5">
            <span className="text-xl font-bold font-mono text-amber-300">{statusStats.warnings}</span>
            <span className="text-[11px] text-slate-400">anomalies</span>
          </div>
        </button>

        <button
          onClick={() => setSelectedStatus('Fail')}
          className={`p-3 rounded-xl border text-left transition-all ${
            selectedStatus === 'Fail' 
              ? 'bg-rose-950/40 border-rose-500/50' 
              : 'bg-[#080c14] border-slate-800 hover:border-rose-800/40'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-mono uppercase text-rose-400">Failed / Threat</span>
            <XCircle className="w-3.5 h-3.5 text-rose-400" />
          </div>
          <div className="flex items-baseline gap-1.5 mt-0.5">
            <span className="text-xl font-bold font-mono text-rose-300">{statusStats.failed}</span>
            <span className="text-[11px] text-slate-400">critical</span>
          </div>
        </button>
      </div>

      {/* Category Pills & Search Controls */}
      <div className="space-y-3 pt-2">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          {/* Search box */}
          <div className="relative flex-1 max-w-md">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Filter parameters (e.g. entropy, punycode, port, SSL)..."
              className="w-full pl-9 pr-3 py-2 bg-[#080c14] text-xs text-slate-100 placeholder-slate-500 rounded-lg border border-slate-800 focus:outline-none focus:border-blue-500 transition-colors"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 text-xs"
              >
                Clear
              </button>
            )}
          </div>

          {/* Quick Clear Filter indicator */}
          {(selectedCategory !== 'All' || selectedStatus !== 'All' || searchQuery) && (
            <button
              onClick={() => {
                setSelectedCategory('All');
                setSelectedStatus('All');
                setSearchQuery('');
              }}
              className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1 self-start sm:self-auto cursor-pointer"
            >
              Reset Filters ({filteredParameters.length} of {parameters.length})
            </button>
          )}
        </div>

        {/* Category horizontal scroll pills */}
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 scrollbar-thin">
          {categories.map(cat => (
            <button
              key={cat.value}
              onClick={() => setSelectedCategory(cat.value)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap transition-colors cursor-pointer flex items-center gap-1.5 ${
                selectedCategory === cat.value
                  ? 'bg-blue-600 text-white font-medium shadow-sm'
                  : 'bg-[#080c14] text-slate-400 hover:text-slate-200 border border-slate-800 hover:border-slate-700'
              }`}
            >
              <span>{cat.label}</span>
              <span className={`text-[10px] px-1.5 py-0.2 rounded-full ${
                selectedCategory === cat.value ? 'bg-blue-800 text-blue-100' : 'bg-slate-800 text-slate-400'
              }`}>
                {cat.count}
              </span>
            </button>
          ))}
        </div>
      </div>

      {/* Parameter Cards / Rows */}
      <div className="space-y-2.5 pt-1">
        {filteredParameters.length === 0 ? (
          <div className="p-8 text-center bg-[#080c14] rounded-xl border border-slate-800 text-slate-400 text-xs">
            No website checking parameters match your search query &quot;{searchQuery}&quot;.
          </div>
        ) : (
          filteredParameters.map((param, index) => {
            const isExpanded = expandedParamId === param.id;
            const isPass = param.status === 'Pass';
            const isWarn = param.status === 'Warning';
            const isFail = param.status === 'Fail';

            return (
              <div
                key={param.id}
                className={`rounded-xl border transition-all duration-200 ${
                  isFail 
                    ? 'bg-[#0b080c]/80 border-rose-950/80 hover:border-rose-700/60' 
                    : isWarn 
                    ? 'bg-[#0c0a06]/80 border-amber-950/80 hover:border-amber-700/60' 
                    : 'bg-[#080c14]/80 border-slate-800/90 hover:border-slate-700'
                }`}
              >
                {/* Main Row */}
                <div 
                  onClick={() => toggleExpand(param.id)}
                  className="p-3.5 sm:p-4 cursor-pointer flex flex-col sm:flex-row sm:items-center justify-between gap-3 select-none"
                >
                  <div className="flex items-start gap-3">
                    {/* Status Icon Indicator */}
                    <div className="mt-0.5 shrink-0">
                      {isPass && <CheckCircle2 className="w-4 h-4 text-emerald-400" />}
                      {isWarn && <AlertTriangle className="w-4 h-4 text-amber-400" />}
                      {isFail && <XCircle className="w-4 h-4 text-rose-400" />}
                    </div>

                    <div className="space-y-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-semibold text-slate-100 text-xs sm:text-sm">
                          {index + 1}. {param.name}
                        </span>

                        {/* Benchmark standard pill */}
                        {param.benchmarkStandard && (
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800/90 text-slate-400 border border-slate-700/60">
                            {param.benchmarkStandard}
                          </span>
                        )}

                        {/* Category tag */}
                        <span className="text-[10px] text-slate-400 hidden lg:inline-block">
                          • {param.category}
                        </span>
                      </div>

                      <p className="text-[11px] text-slate-400 leading-snug">
                        {param.description}
                      </p>
                    </div>
                  </div>

                  {/* Right side stats & status badge */}
                  <div className="flex items-center gap-3 self-end sm:self-center shrink-0">
                    {/* Evaluated Value */}
                    <div className="text-right">
                      <span className="text-[10px] font-mono text-slate-500 block uppercase">Inspected Value</span>
                      <span className="text-xs font-mono font-semibold text-slate-200">
                        {param.displayValue}
                      </span>
                    </div>

                    {/* Status Badge */}
                    <div className={`px-2.5 py-1 rounded-md text-[11px] font-semibold font-mono border flex items-center gap-1.5 ${
                      isPass 
                        ? 'bg-emerald-950/60 text-emerald-300 border-emerald-500/40' 
                        : isWarn 
                        ? 'bg-amber-950/60 text-amber-300 border-amber-500/40' 
                        : 'bg-rose-950/60 text-rose-300 border-rose-500/40'
                    }`}>
                      <span>{param.status.toUpperCase()}</span>
                    </div>

                    {/* Expand icon */}
                    <button 
                      aria-label="Toggle forensic detail"
                      className="p-1 rounded text-slate-400 hover:text-slate-200"
                    >
                      {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                {/* Collapsible Forensic Explanatory Drawer */}
                {isExpanded && (
                  <div className="px-4 pb-4 pt-1 border-t border-slate-800/80 bg-[#05080f]/90 space-y-3 rounded-b-xl text-xs">
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2">
                      <div className="bg-[#080c14] p-3 rounded-lg border border-slate-800/90">
                        <span className="text-[10px] font-mono uppercase text-slate-400 block mb-0.5">Threat Severity Level</span>
                        <span className={`font-semibold font-mono ${
                          param.severity === 'Critical' ? 'text-rose-400' :
                          param.severity === 'High' ? 'text-rose-300' :
                          param.severity === 'Medium' ? 'text-amber-400' : 'text-emerald-400'
                        }`}>
                          {param.severity} Priority Vector
                        </span>
                      </div>

                      <div className="bg-[#080c14] p-3 rounded-lg border border-slate-800/90">
                        <span className="text-[10px] font-mono uppercase text-slate-400 block mb-0.5">Risk Contribution</span>
                        <span className={`font-semibold font-mono ${param.riskContribution > 0 ? 'text-rose-400' : 'text-slate-400'}`}>
                          {param.riskContribution > 0 ? `+${param.riskContribution} pts to Risk Score` : '0 pts (Clean)'}
                        </span>
                      </div>

                      <div className="bg-[#080c14] p-3 rounded-lg border border-slate-800/90">
                        <span className="text-[10px] font-mono uppercase text-slate-400 block mb-0.5">Formal Standard</span>
                        <span className="font-semibold font-mono text-slate-300 truncate block">
                          {param.benchmarkStandard || 'Security Best Practice'}
                        </span>
                      </div>
                    </div>

                    <div className="bg-[#080c14] p-3.5 rounded-lg border border-slate-800/90 space-y-1.5">
                      <div className="flex items-center gap-2 text-slate-300 font-semibold text-[11px] font-mono">
                        <Info className="w-3.5 h-3.5 text-blue-400" />
                        <span>FORENSIC TECHNICAL EXPLANATION</span>
                      </div>
                      <p className="text-slate-300 leading-relaxed">
                        {param.forensicDetail}
                      </p>
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </SpotlightCard>
  );
};
