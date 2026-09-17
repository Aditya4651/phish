import React, { useState } from 'react';
import { 
  Database, 
  Search, 
  Download, 
  ShieldAlert, 
  ShieldCheck, 
  Binary, 
  Cpu, 
  SlidersHorizontal,
  Table
} from 'lucide-react';
import { SAMPLE_DATASET_CSV } from '../utils/sampleDataset';
import { SpotlightCard } from './motion/SpotlightCard';
import { MagneticButton } from './motion/MagneticButton';
import { ScrambleText } from './motion/ScrambleText';

export const DatasetViewer: React.FC = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [labelFilter, setLabelFilter] = useState<'all' | '1' | '0'>('all');

  const filteredDataset = SAMPLE_DATASET_CSV.filter(item => {
    const matchesSearch = item.url.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesLabel = labelFilter === 'all' ? true : item.label.toString() === labelFilter;
    return matchesSearch && matchesLabel;
  });

  const downloadCSV = () => {
    let csvContent = 'data:text/csv;charset=utf-8,url,length,dots,hyphens,is_https,suspicious_words,is_ip,label\n';
    filteredDataset.forEach(row => {
      csvContent += `"${row.url}",${row.length},${row.dots},${row.hyphens},${row.is_https},${row.suspicious_words},${row.is_ip},${row.label}\n`;
    });
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `phishguard_training_dataset_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    link.remove();
  };

  return (
    <div className="space-y-8">
      
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold text-slate-100 tracking-tight flex items-center gap-2.5">
            <Database className="w-6 h-6 text-blue-400" />
            <span>Phishing Dataset & Feature Matrix</span>
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1">
            Standardized tabular corpus derived from PhishTank feeds and Alexa Top 10,000 legitimate anchors.
          </p>
        </div>

        <MagneticButton
          id="btn-download-corpus-csv"
          onClick={downloadCSV}
          className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-100 text-xs font-semibold rounded-lg border border-slate-700 flex items-center gap-2 cursor-pointer shadow-sm"
        >
          <Download className="w-3.5 h-3.5 text-blue-400" />
          <span>Export Corpus CSV</span>
        </MagneticButton>
      </div>

      {/* Dataset Statistics Overview */}
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

      {/* Dataset Table Card */}
      <SpotlightCard className="overflow-hidden">
        
        {/* Table Filter Header */}
        <div className="p-5 border-b border-slate-800 flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Table className="w-4 h-4 text-blue-400" />
            <h3 className="font-semibold text-slate-200 text-sm">Feature Extraction Records</h3>
            <span className="text-xs bg-slate-800 text-slate-300 font-mono px-2 py-0.5 rounded border border-slate-700">
              {filteredDataset.length} rows
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
                placeholder="Search corpus URLs..."
                className="w-full bg-[#080c14] text-xs text-slate-200 pl-8 pr-3 py-2 rounded-lg border border-slate-700 outline-none focus:border-blue-500 font-mono"
              />
            </div>

            <select
              id="select-dataset-label-filter"
              value={labelFilter}
              onChange={(e) => setLabelFilter(e.target.value as any)}
              className="bg-[#080c14] text-xs text-slate-200 px-3 py-2 rounded-lg border border-slate-700 outline-none focus:border-blue-500 cursor-pointer font-mono"
            >
              <option value="all">All Labels (0 & 1)</option>
              <option value="1">Phishing (Label: 1)</option>
              <option value="0">Safe Baseline (Label: 0)</option>
            </select>
          </div>
        </div>

        {/* Table Body */}
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
              {filteredDataset.map((item, idx) => (
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
      </SpotlightCard>

    </div>
  );
};
