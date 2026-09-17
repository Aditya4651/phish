import React, { useState, useEffect, useCallback } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip } from 'recharts';
import { 
  ShieldCheck, 
  ShieldAlert, 
  AlertTriangle, 
  Search, 
  Trash2, 
  Eye, 
  FileText, 
  Activity, 
  Lock,
  ArrowUpRight,
  Filter,
  CheckCircle2,
  Clock,
  ExternalLink,
  RefreshCw,
  Database
} from 'lucide-react';
import { URLScanResult, User, UserDashboardStats } from '../types';
import { SpotlightCard } from './motion/SpotlightCard';
import { MagneticButton } from './motion/MagneticButton';
import { ScrambleText } from './motion/ScrambleText';
import { ThreatHeatmap } from './ThreatHeatmap';
import { useAppAuth } from '../context/AuthContext';

interface DashboardProps {
  scanHistory?: URLScanResult[];
  onSelectScan: (scan: URLScanResult) => void;
  onDeleteScan: (id: string) => void;
  user?: User;
  onOpenLogin?: () => void;
}

export const Dashboard: React.FC<DashboardProps> = ({
  scanHistory = [],
  onSelectScan,
  onDeleteScan,
  user: propUser,
  onOpenLogin,
}) => {
  const { user: authUser, isLoggedIn, getAuthToken, openSignIn } = useAppAuth();
  const effectiveUser = authUser?.isLoggedIn ? authUser : (propUser || authUser);
  const isAuthenticated = Boolean(effectiveUser?.isLoggedIn || isLoggedIn);

  const [stats, setStats] = useState<UserDashboardStats | null>(null);
  const [isLoadingStats, setIsLoadingStats] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterCategory, setFilterCategory] = useState<'All' | 'Safe' | 'Suspicious' | 'Phishing'>('All');

  // Fetch live user statistics from relational database
  const fetchDashboardStats = useCallback(async () => {
    if (!isAuthenticated) return;

    try {
      setIsLoadingStats(true);
      const token = await getAuthToken();
      const headers: Record<string, string> = {};
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      } else {
        const legacyToken = localStorage.getItem('auth_token');
        if (legacyToken) headers['Authorization'] = `Bearer ${legacyToken}`;
      }

      const res = await fetch('/api/dashboard/stats', { headers });
      if (res.ok) {
        const data = await res.json();
        setStats(data);
      }
    } catch (err) {
      console.warn('[Dashboard] Error fetching statistics:', err);
    } finally {
      setIsLoadingStats(false);
    }
  }, [isAuthenticated, getAuthToken]);

  useEffect(() => {
    if (isAuthenticated) {
      fetchDashboardStats();
    }
  }, [isAuthenticated, fetchDashboardStats, scanHistory.length]);

  // Fallback to local scans if stats query is in progress
  const totalScans = stats ? stats.totalScans : scanHistory.length;
  const safeCount = stats ? stats.safeUrls : scanHistory.filter(s => s.label === 'Safe').length;
  const suspiciousCount = stats ? stats.suspiciousUrls : scanHistory.filter(s => s.label === 'Suspicious').length;
  const maliciousCount = stats ? stats.maliciousUrls : scanHistory.filter(s => s.label === 'Phishing').length;
  const avgRisk = stats ? stats.avgRiskScore.toFixed(1) : (totalScans > 0
    ? (scanHistory.reduce((acc, curr) => acc + curr.riskScore, 0) / totalScans).toFixed(1)
    : '0.0');

  const latestScan = stats?.latestScan || (scanHistory.length > 0 ? scanHistory[0] : null);

  // Protected Route Guard for Unauthenticated Users
  if (!isAuthenticated) {
    return (
      <div className="max-w-xl mx-auto my-16 bg-slate-900/90 p-8 sm:p-10 rounded-2xl border border-slate-800 text-center space-y-5 shadow-2xl">
        <div className="w-14 h-14 rounded-xl bg-slate-800 border border-slate-700 text-blue-400 flex items-center justify-center mx-auto shadow-inner">
          <Lock className="w-7 h-7" />
        </div>
        <div className="space-y-2">
          <h2 className="text-xl sm:text-2xl font-bold text-slate-100 tracking-tight">
            Restricted Intelligence Console
          </h2>
          <p className="text-xs sm:text-sm text-slate-400 leading-relaxed max-w-md mx-auto">
            This dashboard is private to your analyst credentials. Please authenticate through Clerk to inspect your personal threat telemetry, database scan records, and lexical metrics.
          </p>
        </div>

        <div className="pt-2 flex flex-col sm:flex-row items-center justify-center gap-3">
          <MagneticButton
            onClick={openSignIn || onOpenLogin}
            className="w-full sm:w-auto px-6 py-2.5 bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs rounded-xl shadow-lg transition-colors cursor-pointer flex items-center justify-center gap-2"
          >
            <Lock className="w-3.5 h-3.5" />
            <span>Sign In to Access Dashboard</span>
          </MagneticButton>
        </div>

        <div className="pt-4 border-t border-slate-800/80 flex items-center justify-center gap-2 text-[11px] font-mono text-slate-400">
          <Database className="w-3 h-3 text-emerald-400" />
          <span>Relational Database Persistence Active</span>
        </div>
      </div>
    );
  }

  // Chart Data calculated strictly from user's authenticated database records
  const pieData = [
    { name: 'Phishing', value: maliciousCount, color: '#f43f5e' },
    { name: 'Suspicious', value: suspiciousCount, color: '#f59e0b' },
    { name: 'Safe', value: safeCount, color: '#10b981' },
  ].filter(d => d.value > 0);

  const displayScans = (Array.isArray(stats?.recentScans) && stats.recentScans.length > 0) 
    ? stats.recentScans 
    : (Array.isArray(scanHistory) ? scanHistory : []);

  const barData = displayScans.slice(0, 8).reverse().map((scan) => ({
    name: `#${scan.id.slice(-4)}`,
    riskScore: scan.riskScore,
    url: scan.url.replace(/^https?:\/\//, '').substring(0, 16),
  }));

  const filteredScans = displayScans.filter(scan => {
    const matchesSearch = scan.url.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesCategory = filterCategory === 'All' || scan.label === filterCategory;
    return matchesSearch && matchesCategory;
  });

  return (
    <div className="space-y-8">
      {/* Header Section */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[11px] font-mono uppercase tracking-wider text-blue-400">
              Personal Intelligence Dossier
            </span>
            <span className="text-slate-600">•</span>
            <span className="text-[11px] font-mono text-slate-400">
              Analyst: <strong className="text-slate-200">{effectiveUser.username}</strong>
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold text-slate-100 tracking-tight flex items-center gap-2.5">
            <Activity className="w-6 h-6 text-blue-400" />
            <span>Threat Intelligence Console</span>
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1">
            Live telemetry and detection ratios aggregated from your persistent relational database records.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={fetchDashboardStats}
            disabled={isLoadingStats}
            className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono rounded-lg border border-slate-700 flex items-center gap-2 transition-colors cursor-pointer"
            title="Refresh database statistics"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-blue-400 ${isLoadingStats ? 'animate-spin' : ''}`} />
            <span>Sync Stats</span>
          </button>

          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-emerald-950/40 border border-emerald-800/50 text-[11px] font-mono text-emerald-300">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span>Database Synced</span>
          </div>
        </div>
      </div>

      {/* Primary KPI Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        <SpotlightCard className="p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 font-mono">TOTAL SCANS</span>
            <FileText className="w-4 h-4 text-blue-400" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl sm:text-3xl font-bold text-slate-100 font-mono">
              <ScrambleText text={String(totalScans)} />
            </span>
            <span className="text-[10px] text-slate-400 font-mono">in database</span>
          </div>
        </SpotlightCard>

        <SpotlightCard className="p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 font-mono">SAFE RATIO</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl sm:text-3xl font-bold text-emerald-400 font-mono">
              <ScrambleText text={String(safeCount)} />
            </span>
            <span className="text-[10px] text-slate-400 font-mono">
              ({totalScans > 0 ? Math.round((safeCount / totalScans) * 100) : 0}%)
            </span>
          </div>
        </SpotlightCard>

        <SpotlightCard className="p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 font-mono">SUSPICIOUS</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl sm:text-3xl font-bold text-amber-400 font-mono">
              <ScrambleText text={String(suspiciousCount)} />
            </span>
            <span className="text-[10px] text-slate-400 font-mono">elevated risk</span>
          </div>
        </SpotlightCard>

        <SpotlightCard className="p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 font-mono">MALICIOUS</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl sm:text-3xl font-bold text-rose-400 font-mono">
              <ScrambleText text={String(maliciousCount)} />
            </span>
            <span className="text-[10px] text-rose-400/80 font-mono">phishing hits</span>
          </div>
        </SpotlightCard>

        <SpotlightCard className="p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 font-mono">AVG THREAT</span>
            <Activity className="w-4 h-4 text-purple-400" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl sm:text-3xl font-bold text-slate-100 font-mono">
              {avgRisk}%
            </span>
            <span className="text-[10px] text-slate-400 font-mono">composite score</span>
          </div>
        </SpotlightCard>
      </div>

      {/* Latest Scan Result Card */}
      {latestScan && (
        <SpotlightCard className="p-6 border-blue-500/20 bg-gradient-to-r from-blue-950/20 via-slate-900/60 to-slate-900/40">
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
            <div className="space-y-1 max-w-2xl">
              <div className="flex items-center gap-2">
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-blue-900/40 text-blue-300 border border-blue-700/50">
                  LATEST SCAN RESULT
                </span>
                <span className="text-xs text-slate-400 font-mono flex items-center gap-1">
                  <Clock className="w-3 h-3" />
                  <span>{new Date(latestScan.timestamp).toLocaleString()}</span>
                </span>
              </div>
              <h3 className="text-sm sm:text-base font-semibold text-slate-100 truncate font-mono">
                {latestScan.url}
              </h3>
              <p className="text-xs text-slate-400">
                Classified as <strong className={latestScan.label === 'Phishing' ? 'text-rose-400' : latestScan.label === 'Suspicious' ? 'text-amber-400' : 'text-emerald-400'}>{latestScan.label}</strong> with Security Grade <span className="font-mono font-bold text-slate-200">{latestScan.grade}</span> ({latestScan.riskScore}% risk).
              </p>
            </div>

            <div className="flex items-center gap-3">
              <button
                onClick={() => onSelectScan(latestScan)}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold rounded-lg flex items-center gap-2 transition-colors cursor-pointer shadow-md"
              >
                <Eye className="w-3.5 h-3.5" />
                <span>Inspect Full Dossier</span>
              </button>
            </div>
          </div>
        </SpotlightCard>
      )}

      {/* Analytics Visualizers */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <SpotlightCard className="p-6">
          <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-4">
            <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-blue-400" />
              <span>Threat Category Distribution</span>
            </h3>
            <span className="text-[11px] font-mono text-slate-400">Personal History</span>
          </div>

          <div className="h-64 flex items-center justify-center">
            {pieData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={65}
                    outerRadius={95}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {pieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0c101c',
                      borderColor: '#1e293b',
                      borderRadius: '8px',
                      fontSize: '12px',
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="text-center text-xs text-slate-400 space-y-1">
                <FileText className="w-8 h-8 mx-auto text-slate-400" />
                <p>No scans recorded yet. Execute a URL inspection to populate intelligence charts.</p>
              </div>
            )}
          </div>

          <div className="flex justify-center gap-6 mt-4 text-xs font-mono">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
              <span className="text-slate-300">Safe ({safeCount})</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-amber-500" />
              <span className="text-slate-300">Suspicious ({suspiciousCount})</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-rose-500" />
              <span className="text-slate-300">Phishing ({maliciousCount})</span>
            </div>
          </div>
        </SpotlightCard>

        <SpotlightCard className="p-6">
          <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-4">
            <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <Activity className="w-4 h-4 text-purple-400" />
              <span>Recent Scan Risk Trends</span>
            </h3>
            <span className="text-[11px] font-mono text-slate-400">Chronological</span>
          </div>

          <div className="h-64 flex items-center justify-center">
            {barData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={barData} margin={{ top: 10, right: 10, left: -20, bottom: 25 }}>
                  <XAxis dataKey="name" stroke="#64748b" fontSize={11} />
                  <YAxis stroke="#64748b" fontSize={11} domain={[0, 100]} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0c101c',
                      borderColor: '#1e293b',
                      borderRadius: '8px',
                      fontSize: '12px',
                    }}
                  />
                  <Bar dataKey="riskScore" fill="#3b82f6" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="text-center text-xs text-slate-400 space-y-1">
                <Activity className="w-8 h-8 mx-auto text-slate-400" />
                <p>Run your first scan to generate risk trend charts.</p>
              </div>
            )}
          </div>
        </SpotlightCard>
      </div>

      {/* Heatmap Section */}
      <ThreatHeatmap scans={displayScans} scanHistory={displayScans} />

      {/* Recent Scans Table with Search & Filter */}
      <SpotlightCard className="p-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div>
            <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <Clock className="w-4 h-4 text-blue-400" />
              <span>Recent Scans Activity</span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Live audit records stored permanently in the relational database.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search scans..."
                className="pl-8 pr-3 py-1.5 bg-[#080c14] text-xs text-slate-200 rounded-lg border border-slate-700 outline-none focus:border-blue-500 font-mono w-44"
              />
            </div>

            <div className="flex items-center gap-1 bg-[#080c14] p-1 rounded-lg border border-slate-700 text-xs">
              {(['All', 'Safe', 'Suspicious', 'Phishing'] as const).map((cat) => (
                <button
                  key={cat}
                  onClick={() => setFilterCategory(cat)}
                  className={`px-2 py-1 rounded text-[11px] font-medium transition-colors cursor-pointer ${
                    filterCategory === cat
                      ? 'bg-blue-600 text-white font-semibold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {cat}
                </button>
              ))}
            </div>
          </div>
        </div>

        <div className="mt-4 overflow-x-auto">
          {filteredScans.length === 0 ? (
            <div className="text-center py-12 text-slate-400 text-xs font-mono space-y-2">
              <FileText className="w-8 h-8 mx-auto text-slate-400" />
              <p>No matching scan records found in your database.</p>
            </div>
          ) : (
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px] tracking-wider">
                  <th className="py-3 px-3">Target URL</th>
                  <th className="py-3 px-3">Result</th>
                  <th className="py-3 px-3">Risk Score</th>
                  <th className="py-3 px-3">Grade</th>
                  <th className="py-3 px-3">Timestamp</th>
                  <th className="py-3 px-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredScans.slice(0, 10).map((scan) => (
                  <tr key={scan.id} className="hover:bg-slate-800/30 transition-colors group">
                    <td className="py-3 px-3 font-semibold text-slate-200 max-w-xs truncate">
                      {scan.url}
                    </td>
                    <td className="py-3 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                        scan.label === 'Safe' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' :
                        scan.label === 'Suspicious' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                        'bg-rose-950 text-rose-300 border border-rose-800'
                      }`}>
                        {scan.label}
                      </span>
                    </td>
                    <td className="py-3 px-3 font-bold text-slate-200">
                      {scan.riskScore}/100
                    </td>
                    <td className="py-3 px-3 font-bold text-blue-400">
                      {scan.grade}
                    </td>
                    <td className="py-3 px-3 text-slate-400 text-[11px]">
                      {new Date(scan.timestamp).toLocaleString()}
                    </td>
                    <td className="py-3 px-3 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => onSelectScan(scan)}
                          className="p-1.5 hover:bg-slate-700 text-slate-300 hover:text-white rounded-md transition-colors cursor-pointer"
                          title="View Scan Details"
                        >
                          <Eye className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => onDeleteScan(scan.id)}
                          className="p-1.5 hover:bg-rose-950 text-slate-400 hover:text-rose-400 rounded-md transition-colors cursor-pointer"
                          title="Delete Scan Record"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </SpotlightCard>
    </div>
  );
};
