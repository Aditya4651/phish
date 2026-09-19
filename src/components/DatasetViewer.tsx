import React, { useState } from 'react';
import { 
  Database, 
  Search, 
  Download, 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle,
  Binary, 
  Cpu, 
  SlidersHorizontal,
  Table,
  User as UserIcon,
  ExternalLink,
  Lock,
  Sparkles,
  ArrowRight,
  Layers
} from 'lucide-react';
import { SAMPLE_DATASET_CSV } from '../utils/sampleDataset';
import { URLScanResult, User } from '../types';
import { SpotlightCard } from './motion/SpotlightCard';
import { MagneticButton } from './motion/MagneticButton';
import { ScrambleText } from './motion/ScrambleText';
import { MLEvaluationDashboard } from './MLEvaluationDashboard';

interface DatasetViewerProps {
  userScans?: URLScanResult[];
  currentUser?: User;
  onSelectScan?: (scan: URLScanResult) => void;
  onOpenLogin?: () => void;
}

export const DatasetViewer: React.FC<DatasetViewerProps> = ({
  userScans = [],
  currentUser,
  onSelectScan,
  onOpenLogin
}) => {
  const [corpusMode, setCorpusMode] = useState<'ml-model' | 'benchmark' | 'user'>('ml-model');
  const [searchTerm, setSearchTerm] = useState('');
  const [labelFilter, setLabelFilter] = useState<string>('all');

  const isLoggedIn = Boolean(currentUser?.isLoggedIn);

  // Filter benchmark dataset
  const filteredBenchmark = SAMPLE_DATASET_CSV.filter(item => {
    const matchesSearch = item.url.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesLabel = labelFilter === 'all' ? true : item.label.toString() === labelFilter;
    return matchesSearch && matchesLabel;
  });

  // Filter user database scans
  const filteredUserScans = userScans.filter(item => {
    const matchesSearch = item.url.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (item.domain?.hostname && item.domain.hostname.toLowerCase().includes(searchTerm.toLowerCase()));
    const matchesLabel = labelFilter === 'all' ? true : item.label.toLowerCase() === labelFilter.toLowerCase();
    return matchesSearch && matchesLabel;
  });

  const downloadCSV = () => {
    if (corpusMode === 'benchmark') {
      let csvContent = 'data:text/csv;charset=utf-8,url,length,dots,hyphens,is_https,suspicious_words,is_ip,label\n';
      filteredBenchmark.forEach(row => {
        csvContent += `"${row.url}",${row.length},${row.dots},${row.hyphens},${row.is_https},${row.suspicious_words},${row.is_ip},${row.label}\n`;
      });
      const encodedUri = encodeURI(csvContent);
      const link = document.createElement('a');
      link.setAttribute('href', encodedUri);
      link.setAttribute('download', `phishguard_benchmark_corpus_${new Date().toISOString().slice(0, 10)}.csv`);
      document.body.appendChild(link);
      link.click();
      link.remove();
    } else {
      let csvContent = 'data:text/csv;charset=utf-8,id,url,hostname,risk_score,label,scanned_by,timestamp,dots,hyphens,is_https\n';
      filteredUserScans.forEach(row => {
        csvContent += `"${row.id}","${row.url}","${row.domain?.hostname || ''}",${row.riskScore},"${row.label}","${row.scannedBy || currentUser?.username || 'Analyst'}","${row.timestamp}",${row.features?.dots || 1},${row.features?.hyphens || 0},${row.features?.is_https ? 1 : 0}\n`;
      });
      const encodedUri = encodeURI(csvContent);
      const link = document.createElement('a');
      link.setAttribute('href', encodedUri);
      link.setAttribute('download', `phishguard_user_scans_corpus_${currentUser?.username || 'analyst'}_${new Date().toISOString().slice(0, 10)}.csv`);
      document.body.appendChild(link);
      link.click();
      link.remove();
    }
  };

  const userPhishCount = userScans.filter(s => s.label === 'Phishing' || s.riskScore >= 60).length;
  const userSafeCount = userScans.filter(s => s.label === 'Safe' || s.riskScore <= 30).length;
  const userSuspiciousCount = userScans.filter(s => s.label === 'Suspicious' || (s.riskScore > 30 && s.riskScore < 60)).length;

  return (
    <div className="space-y-8">
      
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[11px] font-mono uppercase tracking-wider text-blue-400">
              Machine Learning Corpus &amp; Threat Records
            </span>
            <span className="text-slate-600">•</span>
            <span className="text-[11px] font-mono text-emerald-400 flex items-center gap-1">
              <Database className="w-3 h-3" />
              <span>SQLite Database Storage</span>
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold text-slate-100 tracking-tight flex items-center gap-2.5">
            <Database className="w-6 h-6 text-blue-400" />
            <span>Phishing Feature Matrix &amp; User Corpus</span>
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1">
            Inspect training benchmarks and your authenticated Clerk user scan repository persisted in the database.
          </p>
        </div>

        <div className="flex items-center gap-2.5 flex-wrap">
          {/* Corpus Mode Selector */}
          <div className="flex items-center bg-[#080c14] p-1 rounded-xl border border-slate-800">
            <button
              type="button"
              onClick={() => setCorpusMode('ml-model')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors flex items-center gap-1.5 cursor-pointer ${
                corpusMode === 'ml-model' 
                  ? 'bg-blue-600 text-white shadow-sm' 
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Cpu className="w-3.5 h-3.5" />
              <span>ML Retrained Model (7 Datasets)</span>
            </button>

            <button
              type="button"
              onClick={() => {
                setCorpusMode('user');
                setLabelFilter('all');
              }}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors flex items-center gap-1.5 cursor-pointer ${
                corpusMode === 'user' 
                  ? 'bg-blue-600 text-white shadow-sm' 
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <UserIcon className="w-3.5 h-3.5" />
              <span>User Scanned Links ({userScans.length})</span>
            </button>

            <button
              type="button"
              onClick={() => {
                setCorpusMode('benchmark');
                setLabelFilter('all');
              }}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors flex items-center gap-1.5 cursor-pointer ${
                corpusMode === 'benchmark' 
                  ? 'bg-blue-600 text-white shadow-sm' 
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Database className="w-3.5 h-3.5" />
              <span>Benchmark Matrix ({SAMPLE_DATASET_CSV.length})</span>
            </button>
          </div>

          {corpusMode !== 'ml-model' && (
            <MagneticButton
              id="btn-download-corpus-csv"
              onClick={downloadCSV}
              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-100 text-xs font-semibold rounded-lg border border-slate-700 flex items-center gap-2 cursor-pointer shadow-sm"
            >
              <Download className="w-3.5 h-3.5 text-blue-400" />
              <span>Export {corpusMode === 'user' ? 'User Scans' : 'Benchmark'} CSV</span>
            </MagneticButton>
          )}
        </div>
      </div>

      {/* Primary ML Model Evaluation Dashboard Mode */}
      {corpusMode === 'ml-model' ? (
        <MLEvaluationDashboard />
      ) : (
        <>
          {/* Dataset Statistics Overview */}
          {corpusMode === 'benchmark' ? (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <SpotlightCard className="p-5">
                <div className="text-[11px] font-mono uppercase text-slate-400">Total Samples In Corpus</div>
                <div className="text-3xl font-bold text-slate-100 font-mono mt-2">
                  <ScrambleText text={String(SAMPLE_DATASET_CSV.length)} />
                </div>
                <div className="text-[11px] text-slate-400 mt-1">11-Vector Normalized Records</div>
              </SpotlightCard>

              <SpotlightCard className="p-5 border-rose-500/20">
                <div className="text-[11px] font-mono uppercase text-slate-400">Positive Class (Phishing)</div>
                <div className="text-3xl font-bold text-rose-400 font-mono mt-2">
                  <ScrambleText text={String(SAMPLE_DATASET_CSV.filter(d => d.label === 1).length)} />
                </div>
                <div className="text-[11px] text-rose-400/80 mt-1">Confirmed Attack Targets</div>
              </SpotlightCard>

              <SpotlightCard className="p-5 border-emerald-500/20">
                <div className="text-[11px] font-mono uppercase text-slate-400">Negative Class (Safe)</div>
                <div className="text-3xl font-bold text-emerald-400 font-mono mt-2">
                  <ScrambleText text={String(SAMPLE_DATASET_CSV.filter(d => d.label === 0).length)} />
                </div>
                <div className="text-[11px] text-emerald-400/80 mt-1">Verified Top Rank Domains</div>
              </SpotlightCard>

              <SpotlightCard className="p-5 border-blue-500/20">
                <div className="text-[11px] font-mono uppercase text-slate-400">Test Accuracy Score</div>
                <div className="text-3xl font-bold text-blue-400 font-mono mt-2">
                  <ScrambleText text="98.4%" />
                </div>
                <div className="text-[11px] text-blue-400/80 mt-1">5-Fold Stratified Validation</div>
              </SpotlightCard>
            </div>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <SpotlightCard className="p-5">
                <div className="text-[11px] font-mono uppercase text-slate-400">User Scans In SQLite DB</div>
                <div className="text-3xl font-bold text-slate-100 font-mono mt-2">
                  <ScrambleText text={String(userScans.length)} />
                </div>
                <div className="text-[11px] text-emerald-400 mt-1 flex items-center gap-1">
                  <UserIcon className="w-3 h-3" />
                  <span>@{currentUser?.username || 'Analyst'}</span>
                </div>
              </SpotlightCard>

              <SpotlightCard className="p-5 border-rose-500/20">
                <div className="text-[11px] font-mono uppercase text-slate-400">Phishing Threats Detected</div>
                <div className="text-3xl font-bold text-rose-400 font-mono mt-2">
                  <ScrambleText text={String(userPhishCount)} />
                </div>
                <div className="text-[11px] text-rose-400/80 mt-1">Stored in url_scans table</div>
              </SpotlightCard>

              <SpotlightCard className="p-5 border-amber-500/20">
                <div className="text-[11px] font-mono uppercase text-slate-400">Suspicious Heuristics</div>
                <div className="text-3xl font-bold text-amber-400 font-mono mt-2">
                  <ScrambleText text={String(userSuspiciousCount)} />
                </div>
                <div className="text-[11px] text-amber-400/80 mt-1">Score between 30% and 60%</div>
              </SpotlightCard>

              <SpotlightCard className="p-5 border-emerald-500/20">
                <div className="text-[11px] font-mono uppercase text-slate-400">Verified Benign Records</div>
                <div className="text-3xl font-bold text-emerald-400 font-mono mt-2">
                  <ScrambleText text={String(userSafeCount)} />
                </div>
                <div className="text-[11px] text-emerald-400/80 mt-1">Safe RFC 3986 endpoints</div>
              </SpotlightCard>
            </div>
          )}

      {/* Dataset Table Card */}
      <SpotlightCard className="overflow-hidden">
        
        {/* Table Filter Header */}
        <div className="p-5 border-b border-slate-800 flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Table className="w-4 h-4 text-blue-400" />
            <h3 className="font-semibold text-slate-200 text-sm">
              {corpusMode === 'user' ? 'User Scanned Links Records' : 'Feature Extraction Records'}
            </h3>
            <span className="text-xs bg-slate-800 text-slate-300 font-mono px-2 py-0.5 rounded border border-slate-700">
              {corpusMode === 'user' ? filteredUserScans.length : filteredBenchmark.length} rows
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <div className="relative flex-1 sm:w-64">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
              <input
                id="search-dataset-url"
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder={corpusMode === 'user' ? "Search your scanned URLs..." : "Search corpus URLs..."}
                className="w-full bg-[#080c14] text-xs text-slate-200 pl-8 pr-3 py-2 rounded-lg border border-slate-700 outline-none focus:border-blue-500 font-mono"
              />
            </div>

            {corpusMode === 'benchmark' ? (
              <select
                id="select-dataset-label-filter"
                value={labelFilter}
                onChange={(e) => setLabelFilter(e.target.value)}
                className="bg-[#080c14] text-xs text-slate-200 px-3 py-2 rounded-lg border border-slate-700 outline-none focus:border-blue-500 cursor-pointer font-mono"
              >
                <option value="all">All Labels (0 &amp; 1)</option>
                <option value="1">Phishing (Label: 1)</option>
                <option value="0">Safe Baseline (Label: 0)</option>
              </select>
            ) : (
              <select
                id="select-user-scans-filter"
                value={labelFilter}
                onChange={(e) => setLabelFilter(e.target.value)}
                className="bg-[#080c14] text-xs text-slate-200 px-3 py-2 rounded-lg border border-slate-700 outline-none focus:border-blue-500 cursor-pointer font-mono"
              >
                <option value="all">All Classifications</option>
                <option value="Phishing">Phishing</option>
                <option value="Suspicious">Suspicious</option>
                <option value="Safe">Safe</option>
              </select>
            )}
          </div>
        </div>

        {/* Table Body */}
        {corpusMode === 'benchmark' ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-[#080c14] text-slate-400 font-mono text-[11px] uppercase border-b border-slate-800">
                <tr>
                  <th className="px-5 py-3">Uniform Resource Locator</th>
                  <th className="px-5 py-3">Len</th>
                  <th className="px-5 py-3">Dots</th>
                  <th className="px-5 py-3">Hyphens</th>
                  <th className="px-5 py-3">HTTPS</th>
                  <th className="px-5 py-3">Tokens</th>
                  <th className="px-5 py-3">IP Usage</th>
                  <th className="px-5 py-3">Ground Truth</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {filteredBenchmark.map((item, idx) => (
                  <tr key={idx} className="hover:bg-slate-800/40 transition-colors">
                    <td className="px-5 py-3 font-sans text-xs text-slate-200 max-w-xs truncate" title={item.url}>
                      {item.url}
                    </td>
                    <td className="px-5 py-3 text-slate-300">{item.length}</td>
                    <td className="px-5 py-3 text-slate-300">{item.dots}</td>
                    <td className="px-5 py-3 text-slate-300">{item.hyphens}</td>
                    <td className="px-5 py-3">
                      {item.is_https === 1 ? (
                        <span className="text-emerald-400">1 (Yes)</span>
                      ) : (
                        <span className="text-rose-400">0 (No)</span>
                      )}
                    </td>
                    <td className="px-5 py-3 text-slate-300">{item.suspicious_words}</td>
                    <td className="px-5 py-3">
                      {item.is_ip === 1 ? (
                        <span className="text-rose-400 font-semibold">1 (IP)</span>
                      ) : (
                        <span className="text-slate-500">0</span>
                      )}
                    </td>
                    <td className="px-5 py-3 font-sans">
                      {item.label === 1 ? (
                        <span className="inline-flex items-center gap-1 text-rose-400 bg-rose-950/60 px-2 py-0.5 rounded text-[11px] font-semibold border border-rose-500/30">
                          <ShieldAlert className="w-3 h-3" /> 1 (Phishing)
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded text-[11px] font-semibold border border-emerald-500/30">
                          <ShieldCheck className="w-3 h-3" /> 0 (Safe)
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="overflow-x-auto">
            {filteredUserScans.length > 0 ? (
              <table className="w-full text-left text-xs text-slate-300">
                <thead className="bg-[#080c14] text-slate-400 font-mono text-[11px] uppercase border-b border-slate-800">
                  <tr>
                    <th className="px-5 py-3">Scanned URL</th>
                    <th className="px-5 py-3">Analyst / User</th>
                    <th className="px-5 py-3">Risk Score</th>
                    <th className="px-5 py-3">Classification</th>
                    <th className="px-5 py-3">Len</th>
                    <th className="px-5 py-3">Dots</th>
                    <th className="px-5 py-3">HTTPS</th>
                    <th className="px-5 py-3">Timestamp</th>
                    <th className="px-5 py-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono">
                  {filteredUserScans.map((item) => (
                    <tr key={item.id} className="hover:bg-slate-800/40 transition-colors">
                      <td className="px-5 py-3 font-sans text-xs text-slate-200 max-w-xs truncate" title={item.url}>
                        {item.url}
                      </td>
                      <td className="px-5 py-3">
                        <span className="text-emerald-400 bg-emerald-950/40 border border-emerald-500/30 px-2 py-0.5 rounded text-[11px]">
                          @{item.scannedBy || currentUser?.username || 'Analyst'}
                        </span>
                      </td>
                      <td className="px-5 py-3">
                        <span className={`font-bold ${
                          item.riskScore >= 60 ? 'text-rose-400' : item.riskScore > 30 ? 'text-amber-400' : 'text-emerald-400'
                        }`}>
                          {item.riskScore}%
                        </span>
                      </td>
                      <td className="px-5 py-3 font-sans">
                        {item.label === 'Phishing' ? (
                          <span className="inline-flex items-center gap-1 text-rose-400 bg-rose-950/60 px-2 py-0.5 rounded text-[11px] font-semibold border border-rose-500/30">
                            <ShieldAlert className="w-3 h-3" /> Phishing
                          </span>
                        ) : item.label === 'Suspicious' ? (
                          <span className="inline-flex items-center gap-1 text-amber-400 bg-amber-950/60 px-2 py-0.5 rounded text-[11px] font-semibold border border-amber-500/30">
                            <AlertTriangle className="w-3 h-3" /> Suspicious
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded text-[11px] font-semibold border border-emerald-500/30">
                            <ShieldCheck className="w-3 h-3" /> Safe
                          </span>
                        )}
                      </td>
                      <td className="px-5 py-3 text-slate-300">{item.features?.length || item.url.length}</td>
                      <td className="px-5 py-3 text-slate-300">{item.features?.dots || 1}</td>
                      <td className="px-5 py-3">
                        {item.features?.is_https ? (
                          <span className="text-emerald-400">1 (Yes)</span>
                        ) : (
                          <span className="text-rose-400">0 (No)</span>
                        )}
                      </td>
                      <td className="px-5 py-3 text-slate-400 text-[11px]">
                        {new Date(item.timestamp).toLocaleDateString()}
                      </td>
                      <td className="px-5 py-3 text-right">
                        {onSelectScan && (
                          <button
                            type="button"
                            onClick={() => onSelectScan(item)}
                            className="inline-flex items-center gap-1 px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-[11px] font-sans border border-slate-700 cursor-pointer transition-colors"
                          >
                            <span>Inspect</span>
                            <ArrowRight className="w-3 h-3 text-blue-400" />
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <div className="py-16 px-6 text-center space-y-4">
                <div className="w-12 h-12 rounded-2xl bg-slate-900 border border-slate-800 flex items-center justify-center mx-auto text-blue-400">
                  <Database className="w-6 h-6" />
                </div>
                <div className="space-y-1">
                  <h4 className="text-slate-200 font-semibold text-sm">
                    {isLoggedIn ? 'No User Scans Recorded in Database' : 'Authentication Required for Personal Corpus'}
                  </h4>
                  <p className="text-slate-400 text-xs max-w-md mx-auto">
                    {isLoggedIn 
                      ? 'URLs you evaluate in the Inspector will be automatically indexed here into your private relational database corpus.'
                      : 'Sign in with Clerk to build and query your private intelligence corpus in the SQLite database.'}
                  </p>
                </div>
                {!isLoggedIn && onOpenLogin && (
                  <MagneticButton
                    onClick={onOpenLogin}
                    className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold rounded-lg inline-flex items-center gap-1.5 cursor-pointer shadow-sm"
                  >
                    <Lock className="w-3.5 h-3.5" />
                    <span>Sign In with Clerk</span>
                  </MagneticButton>
                )}
              </div>
            )}
          </div>
        )}
      </SpotlightCard>
      </>
      )}

    </div>
  );
};
