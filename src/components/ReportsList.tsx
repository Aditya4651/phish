import React, { useState, useEffect, useCallback } from 'react';
import { 
  FileText, 
  Download, 
  Search, 
  ShieldCheck, 
  ShieldAlert, 
  AlertTriangle, 
  Eye, 
  Calendar, 
  Lock, 
  Layers, 
  Check,
  ChevronLeft,
  ChevronRight,
  ArrowUpDown,
  Filter,
  Trash2,
  RefreshCw,
  Clock,
  Database
} from 'lucide-react';
import { URLScanResult, User } from '../types';
import { SpotlightCard } from './motion/SpotlightCard';
import { MagneticButton } from './motion/MagneticButton';
import { useAppAuth } from '../context/AuthContext';

interface ReportsListProps {
  scanHistory?: URLScanResult[];
  onSelectScan: (scan: URLScanResult) => void;
  onDeleteScan?: (id: string) => void;
  user?: User;
  onOpenLogin?: () => void;
}

export const ReportsList: React.FC<ReportsListProps> = ({ 
  scanHistory: localScans = [], 
  onSelectScan, 
  onDeleteScan,
  user: propUser, 
  onOpenLogin 
}) => {
  const { user: authUser, isLoggedIn, getAuthToken, openSignIn } = useAppAuth();
  const effectiveUser = authUser?.isLoggedIn ? authUser : (propUser || authUser);
  const isAuthenticated = Boolean(effectiveUser?.isLoggedIn || isLoggedIn);

  const [dbScans, setDbScans] = useState<URLScanResult[]>([]);
  const [totalCount, setTotalCount] = useState(0);
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [pageSize] = useState(15);
  const [isLoading, setIsLoading] = useState(false);

  const [searchTerm, setSearchTerm] = useState('');
  const [filterResult, setFilterResult] = useState<'All' | 'Safe' | 'Suspicious' | 'Phishing'>('All');
  const [sortOrder, setSortOrder] = useState<'desc' | 'asc'>('desc');

  // Query authenticated scan history from relational SQLite database
  const fetchScans = useCallback(async (pageToLoad: number = 1) => {
    if (!isAuthenticated) return;

    try {
      setIsLoading(true);
      const token = await getAuthToken();
      const headers: Record<string, string> = {};
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      } else {
        const legacyToken = localStorage.getItem('auth_token');
        if (legacyToken) headers['Authorization'] = `Bearer ${legacyToken}`;
      }

      const params = new URLSearchParams({
        page: String(pageToLoad),
        limit: String(pageSize),
        search: searchTerm.trim(),
        result: filterResult,
        sort: sortOrder,
      });

      const res = await fetch(`/api/scans?${params.toString()}`, { headers });
      if (res.ok) {
        const data = await res.json();
        if (data && Array.isArray(data.scans)) {
          setDbScans(data.scans);
          setTotalCount(data.total);
          setCurrentPage(data.page);
          setTotalPages(data.totalPages);
        } else if (Array.isArray(data)) {
          setDbScans(data);
          setTotalCount(data.length);
          setCurrentPage(1);
          setTotalPages(1);
        }
      }
    } catch (err) {
      console.warn('[ReportsList] Error fetching scans from database:', err);
    } finally {
      setIsLoading(false);
    }
  }, [isAuthenticated, getAuthToken, searchTerm, filterResult, sortOrder, pageSize]);

  useEffect(() => {
    if (isAuthenticated) {
      fetchScans(currentPage);
    }
  }, [isAuthenticated, fetchScans, currentPage]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setCurrentPage(1);
    fetchScans(1);
  };

  const handleFilterChange = (result: 'All' | 'Safe' | 'Suspicious' | 'Phishing') => {
    setFilterResult(result);
    setCurrentPage(1);
  };

  const handleToggleSort = () => {
    setSortOrder(prev => prev === 'desc' ? 'asc' : 'desc');
    setCurrentPage(1);
  };

  const handleDeleteItem = async (scanId: string) => {
    // Optimistic UI update
    setDbScans(prev => prev.filter(s => s.id !== scanId));
    setTotalCount(prev => Math.max(0, prev - 1));

    if (onDeleteScan) {
      onDeleteScan(scanId);
    }

    try {
      const token = await getAuthToken();
      const headers: Record<string, string> = {};
      if (token) headers['Authorization'] = `Bearer ${token}`;

      await fetch(`/api/scans/${scanId}`, {
        method: 'DELETE',
        headers,
      });
    } catch (err) {
      console.warn('Error deleting scan:', err);
    }
  };

  const exportAllCSV = () => {
    const activeList = (Array.isArray(dbScans) && dbScans.length > 0) ? dbScans : (Array.isArray(localScans) ? localScans : []);
    if (activeList.length === 0) {
      alert('No scan records available to export.');
      return;
    }
    let csvContent = 'data:text/csv;charset=utf-8,ID,URL,Status,RiskScore,Classification,Timestamp,Threats\n';
    activeList.forEach(s => {
      const threatsSummary = Object.entries(s.threats || {})
        .filter(([, v]) => Boolean(v))
        .map(([k]) => k)
        .join('; ');
      csvContent += `"${s.id}","${s.url}","Completed",${s.riskScore},"${s.label}","${s.timestamp}","${threatsSummary}"\n`;
    });
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `phishing_audit_dossiers_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    link.remove();
  };

  // Protected Route: Unauthenticated Users Locked
  if (!isAuthenticated) {
    return (
      <div className="max-w-xl mx-auto my-16 bg-slate-900/90 p-8 sm:p-10 rounded-2xl border border-slate-800 text-center space-y-5 shadow-2xl">
        <div className="w-14 h-14 rounded-xl bg-slate-800 border border-slate-700 text-blue-400 flex items-center justify-center mx-auto shadow-inner">
          <Lock className="w-7 h-7" />
        </div>
        <div className="space-y-2">
          <h2 className="text-xl sm:text-2xl font-bold text-slate-100 tracking-tight">
            Protected Intelligence Dossiers
          </h2>
          <p className="text-xs sm:text-sm text-slate-400 leading-relaxed max-w-md mx-auto">
            Scan dossiers and persistent audit trails are confidential to the authenticated analyst. Please log in with your Clerk credentials to inspect your personal scanning history.
          </p>
        </div>

        <div className="pt-2 flex flex-col sm:flex-row items-center justify-center gap-3">
          <MagneticButton
            onClick={openSignIn || onOpenLogin}
            className="w-full sm:w-auto px-6 py-2.5 bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs rounded-xl shadow-lg transition-colors cursor-pointer flex items-center justify-center gap-2"
          >
            <Lock className="w-3.5 h-3.5" />
            <span>Sign In to Access Scan History</span>
          </MagneticButton>
        </div>

        <div className="pt-4 border-t border-slate-800/80 flex items-center justify-center gap-2 text-[11px] font-mono text-slate-400">
          <Database className="w-3 h-3 text-emerald-400" />
          <span>Relational SQLite Storage Guard</span>
        </div>
      </div>
    );
  }

  const displayedList = dbScans.length > 0 ? dbScans : localScans;

  return (
    <div className="space-y-8">
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[11px] font-mono uppercase tracking-wider text-blue-400">
              Audit Logs & Provenance
            </span>
            <span className="text-slate-600">•</span>
            <span className="text-[11px] font-mono text-slate-400">
              Analyst: <strong className="text-slate-200">{effectiveUser.username}</strong>
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold text-slate-100 tracking-tight flex items-center gap-2.5">
            <FileText className="w-6 h-6 text-blue-400" />
            <span>Scan Dossiers & Audit History</span>
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1">
            Standardized forensic reports stored in the relational database for auditing and SOC compliance.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => fetchScans(currentPage)}
            disabled={isLoading}
            className="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold rounded-lg border border-slate-700 flex items-center gap-2 transition-colors cursor-pointer"
            title="Refresh scan records"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-blue-400 ${isLoading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>

          <button
            onClick={exportAllCSV}
            className="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg border border-slate-700 flex items-center gap-2 transition-colors cursor-pointer"
          >
            <Download className="w-3.5 h-3.5 text-blue-400" />
            <span>Export CSV</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Ribbon */}
      <SpotlightCard className="p-4 sm:p-5">
        <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-4">
          <form onSubmit={handleSearchSubmit} className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search by URL domain, keyword, or classification..."
              className="w-full bg-[#080c14] text-slate-200 text-xs pl-9 pr-24 py-2.5 rounded-lg border border-slate-700 outline-none focus:border-blue-500 font-mono"
            />
            <button
              type="submit"
              className="absolute right-1.5 top-1.5 bottom-1.5 px-3 bg-blue-600 hover:bg-blue-500 text-white text-[11px] font-semibold rounded-md transition-colors cursor-pointer"
            >
              Filter
            </button>
          </form>

          <div className="flex flex-wrap items-center gap-2">
            <div className="flex items-center gap-1 bg-[#080c14] p-1 rounded-lg border border-slate-700 text-xs">
              {(['All', 'Safe', 'Suspicious', 'Phishing'] as const).map((cat) => (
                <button
                  key={cat}
                  onClick={() => handleFilterChange(cat)}
                  className={`px-3 py-1.5 rounded-md text-[11px] font-medium transition-colors cursor-pointer ${
                    filterResult === cat
                      ? 'bg-blue-600 text-white font-semibold shadow-sm'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {cat}
                </button>
              ))}
            </div>

            <button
              onClick={handleToggleSort}
              className="px-3 py-2 bg-[#080c14] hover:bg-slate-800 text-slate-300 border border-slate-700 text-xs font-mono rounded-lg flex items-center gap-1.5 transition-colors cursor-pointer"
              title="Toggle sort order by date"
            >
              <ArrowUpDown className="w-3.5 h-3.5 text-blue-400" />
              <span>{sortOrder === 'desc' ? 'Newest First' : 'Oldest First'}</span>
            </button>
          </div>
        </div>
      </SpotlightCard>

      {/* Main Records List */}
      {isLoading ? (
        <div className="p-16 text-center text-xs font-mono text-slate-400 space-y-3">
          <RefreshCw className="w-6 h-6 animate-spin mx-auto text-blue-400" />
          <p>Querying relational database dossiers...</p>
        </div>
      ) : displayedList.length === 0 ? (
        <div className="p-16 text-center text-slate-400 border border-slate-800 rounded-xl bg-slate-900/40 space-y-3">
          <FileText className="w-10 h-10 mx-auto text-slate-400" />
          <h3 className="text-base font-semibold text-slate-200">No Dossiers Match Filters</h3>
          <p className="text-xs max-w-sm mx-auto leading-relaxed">
            There are no scan records matching your query in the database. Scan a target URL from the Inspector to create a permanent dossier.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {displayedList.map((scan) => {
            const threatCount = Object.values(scan.threats || {}).filter(Boolean).length;
            const isPhish = scan.label === 'Phishing';
            const isSusp = scan.label === 'Suspicious';

            return (
              <SpotlightCard
                key={scan.id}
                className="p-4 sm:p-5 border-slate-800/80 hover:border-slate-700 transition-all group"
              >
                <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
                  <div className="flex items-start gap-4 flex-1 min-w-0">
                    <div className={`p-2.5 rounded-xl shrink-0 ${
                      isPhish ? 'bg-rose-950/80 border border-rose-500/40 text-rose-400' :
                      isSusp ? 'bg-amber-950/80 border border-amber-500/40 text-amber-400' :
                      'bg-emerald-950/80 border border-emerald-500/40 text-emerald-400'
                    }`}>
                      {isPhish ? <ShieldAlert className="w-5 h-5" /> : isSusp ? <AlertTriangle className="w-5 h-5" /> : <ShieldCheck className="w-5 h-5" />}
                    </div>

                    <div className="space-y-1.5 min-w-0 flex-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider ${
                          isPhish ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                          isSusp ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                          'bg-emerald-950 text-emerald-300 border border-emerald-800'
                        }`}>
                          {scan.label}
                        </span>

                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-blue-950 text-blue-300 border border-blue-800">
                          Grade {scan.grade}
                        </span>

                        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300 border border-slate-700">
                          Status: Completed
                        </span>

                        <span className="text-[11px] text-slate-400 font-mono flex items-center gap-1">
                          <Clock className="w-3 h-3" />
                          <span>{new Date(scan.timestamp).toLocaleString()}</span>
                        </span>
                      </div>

                      <h3 className="text-sm sm:text-base font-semibold text-slate-100 truncate font-mono">
                        {scan.url}
                      </h3>

                      <div className="flex items-center gap-4 text-xs font-mono text-slate-400 flex-wrap">
                        <span>Risk Score: <strong className={isPhish ? 'text-rose-400' : isSusp ? 'text-amber-400' : 'text-emerald-400'}>{scan.riskScore}/100</strong></span>
                        <span>•</span>
                        <span>Threat Indicators: <strong className="text-slate-200">{threatCount} triggered</strong></span>
                        <span>•</span>
                        <span>Domain: <strong className="text-slate-300">{scan.domain?.hostname || 'Resolved'}</strong></span>
                        <span>•</span>
                        <span className="text-emerald-400">ID #{scan.id}</span>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0 self-end lg:self-center">
                    <button
                      onClick={() => onSelectScan(scan)}
                      className="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg flex items-center gap-2 border border-slate-700 transition-colors cursor-pointer"
                    >
                      <Eye className="w-3.5 h-3.5 text-blue-400" />
                      <span>View Dossier</span>
                    </button>

                    <button
                      onClick={() => handleDeleteItem(scan.id)}
                      className="p-2 bg-slate-850 hover:bg-rose-950/60 text-slate-400 hover:text-rose-400 rounded-lg border border-slate-800 hover:border-rose-800 transition-colors cursor-pointer"
                      title="Delete dossier"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              </SpotlightCard>
            );
          })}
        </div>
      )}

      {/* Pagination Footer */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between border-t border-slate-800 pt-4 text-xs font-mono text-slate-400">
          <div>
            Showing page <strong className="text-slate-200">{currentPage}</strong> of <strong className="text-slate-200">{totalPages}</strong> ({totalCount} total dossiers)
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}
              disabled={currentPage === 1}
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg border border-slate-700 disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-1 cursor-pointer"
            >
              <ChevronLeft className="w-3.5 h-3.5" />
              <span>Previous</span>
            </button>

            <button
              onClick={() => setCurrentPage(prev => Math.min(totalPages, prev + 1))}
              disabled={currentPage === totalPages}
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg border border-slate-700 disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-1 cursor-pointer"
            >
              <span>Next</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
