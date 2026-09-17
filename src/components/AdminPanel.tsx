import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  Users, 
  FileText, 
  Database, 
  Activity, 
  Server, 
  Trash2, 
  Plus, 
  Search, 
  CheckCircle2, 
  AlertTriangle, 
  Lock, 
  RefreshCw, 
  Cpu,
  Copy,
  Check,
  Calendar,
  Eye,
  Download,
  ExternalLink,
  Shield,
  X,
  UserCheck,
  Globe,
  Filter
} from 'lucide-react';
import { AuditLog, ThreatDbEntry, User, UserRole, AdminUserRecord, URLScanResult } from '../types';
import { SpotlightCard } from './motion/SpotlightCard';
import { MagneticButton } from './motion/MagneticButton';
import { ScrambleText } from './motion/ScrambleText';

interface AdminPanelProps {
  currentUser?: User;
  onOpenLogin?: () => void;
  getAuthToken?: () => Promise<string | null>;
}

export const AdminPanel: React.FC<AdminPanelProps> = ({ currentUser, onOpenLogin, getAuthToken }) => {
  const [activeTab, setActiveTab] = useState<'users' | 'health' | 'logs' | 'threats'>('users');

  // Verify that the accessing user is truly an administrator
  const isAdmin = Boolean(
    currentUser?.isLoggedIn && (
      (currentUser.role || '').toLowerCase() === 'admin' ||
      currentUser.username?.toLowerCase() === 'admin'
    )
  );
  
  // Real Database & System Telemetry Metrics
  const [stats, setStats] = useState({
    totalUsers: 1,
    totalScans: 0,
    safeScans: 0,
    suspiciousScans: 0,
    maliciousScans: 0,
    threatsInDb: 0,
    activeSessions: 1,
    avgScanTimeMs: 138,
    accuracyRate: '99.4%',
    databaseEngine: 'SQLite Relational (LibSQL)',
  });

  // User Directory State (populated from SQLite Database)
  const [users, setUsers] = useState<AdminUserRecord[]>([]);
  const [isLoadingUsers, setIsLoadingUsers] = useState(true);
  const [userSearchTerm, setUserSearchTerm] = useState('');
  const [roleFilter, setRoleFilter] = useState<string>('all');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // User Inspection Dossier Modal State
  const [inspectingUser, setInspectingUser] = useState<AdminUserRecord | null>(null);
  const [inspectingUserScans, setInspectingUserScans] = useState<URLScanResult[]>([]);
  const [isLoadingScans, setIsLoadingScans] = useState(false);

  // User Deletion State
  const [userToDelete, setUserToDelete] = useState<AdminUserRecord | null>(null);
  const [isDeletingUser, setIsDeletingUser] = useState(false);

  // Action status banner
  const [adminNotification, setAdminNotification] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  // Audit Logs & Threat Intelligence
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [threats, setThreats] = useState<ThreatDbEntry[]>([]);
  const [newPattern, setNewPattern] = useState('');
  const [newThreatType, setNewThreatType] = useState<ThreatDbEntry['threatType']>('Phishing');

  // Build authenticated bearer headers for admin API requests
  const getAuthHeaders = async (includeJson = false): Promise<Record<string, string>> => {
    const headers: Record<string, string> = {};
    if (includeJson) {
      headers['Content-Type'] = 'application/json';
    }
    if (getAuthToken) {
      try {
        const token = await getAuthToken();
        if (token) {
          headers['Authorization'] = `Bearer ${token}`;
        }
      } catch (err) {
        console.warn('Error obtaining auth token for admin request:', err);
      }
    }
    return headers;
  };

  // Load telemetry, users, logs, and threats from backend
  const fetchAllAdminData = async () => {
    if (!isAdmin) {
      setIsLoadingUsers(false);
      return;
    }
    setIsLoadingUsers(true);
    try {
      const headers = await getAuthHeaders();
      const [statsRes, usersRes, logsRes, threatsRes] = await Promise.all([
        fetch('/api/admin/stats', { headers }),
        fetch('/api/admin/users', { headers }),
        fetch('/api/admin/logs', { headers }),
        fetch('/api/admin/threats', { headers }),
      ]);

      if (statsRes.ok) {
        const statsData = await statsRes.json();
        setStats(prev => ({ ...prev, ...statsData }));
      }

      if (usersRes.ok) {
        const usersData = await usersRes.json();
        if (Array.isArray(usersData)) {
          setUsers(usersData);
        }
      }

      if (logsRes.ok) {
        const logsData = await logsRes.json();
        if (Array.isArray(logsData)) setAuditLogs(logsData);
      }

      if (threatsRes.ok) {
        const threatsData = await threatsRes.json();
        if (Array.isArray(threatsData)) setThreats(threatsData);
      }
    } catch (err) {
      console.error('Failed to load admin data:', err);
    } finally {
      setIsLoadingUsers(false);
    }
  };

  useEffect(() => {
    if (isAdmin) {
      fetchAllAdminData();
    }
  }, [isAdmin]);

  // Copy helper
  const handleCopy = (text: string, idKey: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(idKey);
    setTimeout(() => {
      setCopiedId(null);
    }, 2000);
  };

  // Inspect User Scans Dossier
  const handleInspectUser = async (userRecord: AdminUserRecord) => {
    setInspectingUser(userRecord);
    setIsLoadingScans(true);
    try {
      const headers = await getAuthHeaders();
      const res = await fetch(`/api/admin/users/${userRecord.id}/scans`, { headers });
      if (res.ok) {
        const data = await res.json();
        setInspectingUserScans(Array.isArray(data.scans) ? data.scans : []);
      } else {
        setInspectingUserScans([]);
      }
    } catch (err) {
      console.error('Failed to fetch scans for user:', err);
      setInspectingUserScans([]);
    } finally {
      setIsLoadingScans(false);
    }
  };

  // Change User Role in SQLite Database
  const handleRoleChange = async (userId: number, newRole: string) => {
    try {
      const headers = await getAuthHeaders(true);
      const res = await fetch(`/api/admin/users/${userId}/role`, {
        method: 'PATCH',
        headers,
        body: JSON.stringify({ role: newRole }),
      });

      if (res.ok) {
        setUsers(prev => prev.map(u => u.id === userId ? { ...u, role: newRole } : u));
        setAdminNotification({
          type: 'success',
          message: `Role for User #${userId} successfully updated to "${newRole.toUpperCase()}".`,
        });
      } else {
        throw new Error('Failed to update role in database.');
      }
    } catch (err: any) {
      setAdminNotification({
        type: 'error',
        message: err?.message || 'Error updating user role.',
      });
    }
    setTimeout(() => setAdminNotification(null), 4000);
  };

  // Delete User in SQLite Database
  const confirmDeleteUser = async () => {
    if (!userToDelete) return;
    setIsDeletingUser(true);
    try {
      const headers = await getAuthHeaders();
      const res = await fetch(`/api/admin/users/${userToDelete.id}`, {
        method: 'DELETE',
        headers,
      });

      if (res.ok) {
        setUsers(prev => prev.filter(u => u.id !== userToDelete.id));
        setAdminNotification({
          type: 'success',
          message: `User record #${userToDelete.id} (@${userToDelete.username || 'user'}) and associated scans permanently removed.`,
        });
        setUserToDelete(null);
      } else {
        throw new Error('Deletion failed on server.');
      }
    } catch (err: any) {
      setAdminNotification({
        type: 'error',
        message: err?.message || 'Failed to delete user.',
      });
    } finally {
      setIsDeletingUser(false);
      setTimeout(() => setAdminNotification(null), 4000);
    }
  };

  // Threat Intel Pattern creation
  const handleAddThreat = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newPattern.trim()) return;

    const entry: ThreatDbEntry = {
      id: 'th-' + Math.random().toString(36).substring(2, 7),
      urlPattern: newPattern.trim().toLowerCase(),
      threatType: newThreatType,
      addedBy: currentUser?.username || 'Admin',
      addedAt: new Date().toISOString().split('T')[0],
      status: 'Active',
    };

    setThreats([entry, ...threats]);
    setNewPattern('');

    const headers = await getAuthHeaders(true);
    fetch('/api/admin/threats', {
      method: 'POST',
      headers,
      body: JSON.stringify({ urlPattern: entry.urlPattern, threatType: entry.threatType, addedBy: 'Admin' }),
    }).catch(() => {});
  };

  const handleDeleteThreat = async (id: string) => {
    setThreats(threats.filter(t => t.id !== id));
    const headers = await getAuthHeaders();
    fetch(`/api/admin/threats/${id}`, { method: 'DELETE', headers }).catch(() => {});
  };

  // Export User Directory as JSON
  const handleExportUsersJSON = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(users, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `phishguard_users_export_${new Date().toISOString().split('T')[0]}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  // Export User Directory as CSV
  const handleExportUsersCSV = () => {
    const headers = ['DB_ID', 'CLERK_USER_ID', 'USERNAME', 'FIRST_NAME', 'LAST_NAME', 'EMAIL', 'ROLE', 'DATE_OF_BIRTH', 'TOTAL_SCANS', 'HIGH_RISK_SCANS', 'CREATED_AT', 'LAST_ACTIVE_AT'];
    const rows = users.map(u => [
      u.id,
      `"${u.clerk_user_id || ''}"`,
      `"${u.username || ''}"`,
      `"${u.first_name || ''}"`,
      `"${u.last_name || ''}"`,
      `"${u.email || ''}"`,
      `"${u.role || 'analyst'}"`,
      `"${u.date_of_birth || ''}"`,
      u.total_scans,
      u.high_risk_scans,
      `"${u.created_at}"`,
      `"${u.last_active_at}"`,
    ]);
    const csvContent = "data:text/csv;charset=utf-8," + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `phishguard_users_registry_${new Date().toISOString().split('T')[0]}.csv`);
    document.body.appendChild(link);
    link.click();
    link.remove();
  };

  // Filtered users
  const filteredUsers = users.filter(user => {
    const matchesSearch = 
      !userSearchTerm.trim() ||
      String(user.id).includes(userSearchTerm.trim()) ||
      user.clerk_user_id.toLowerCase().includes(userSearchTerm.toLowerCase()) ||
      (user.username && user.username.toLowerCase().includes(userSearchTerm.toLowerCase())) ||
      (user.email && user.email.toLowerCase().includes(userSearchTerm.toLowerCase())) ||
      (user.first_name && user.first_name.toLowerCase().includes(userSearchTerm.toLowerCase())) ||
      (user.last_name && user.last_name.toLowerCase().includes(userSearchTerm.toLowerCase())) ||
      (user.date_of_birth && user.date_of_birth.includes(userSearchTerm.trim()));

    const matchesRole = 
      roleFilter === 'all' || 
      (user.role || 'analyst').toLowerCase() === roleFilter.toLowerCase();

    return matchesSearch && matchesRole;
  });

  if (!isAdmin) {
    return (
      <div className="bg-[#0b0e17] p-8 sm:p-10 rounded-2xl border border-rose-500/30 text-center space-y-5 max-w-md mx-auto my-14 shadow-2xl">
        <div className="w-14 h-14 rounded-2xl bg-rose-950/70 border border-rose-500/40 text-rose-400 flex items-center justify-center mx-auto shadow-inner">
          <Lock className="w-7 h-7" />
        </div>
        <div className="space-y-2">
          <h2 className="text-xl font-bold text-slate-100 tracking-tight">
            Administrator Access Restricted
          </h2>
          <p className="text-xs text-slate-400 leading-relaxed">
            The Administrative Security Console is only accessible to verified administrator logins (e.g. role: <span className="text-slate-200 font-mono font-medium">Administrator</span>). Unauthorized users cannot view user IDs, directory data, or forensic telemetry.
          </p>
        </div>
        {onOpenLogin && (
          <div className="pt-2">
            <MagneticButton
              onClick={onOpenLogin}
              className="w-full px-4 py-2.5 bg-rose-600 hover:bg-rose-500 text-white font-medium text-xs rounded-lg cursor-pointer shadow-sm transition-colors flex items-center justify-center gap-1.5"
            >
              <Lock className="w-3.5 h-3.5" />
              <span>Admin Sign In</span>
            </MagneticButton>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto space-y-8 pb-12">
      
      {/* Header & Section Navigation */}
      <div className="border-b border-slate-800 pb-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-slate-900 border border-slate-700/60 p-1.5 flex items-center justify-center shrink-0 shadow-md shadow-indigo-950/40">
              <img src="/logo-emblem.png" alt="PhishGuard" className="w-full h-full object-contain" referrerPolicy="no-referrer" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-2xl sm:text-3xl font-bold text-slate-100 tracking-tight">
                  Admin Command Console
                </h1>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-indigo-950/80 text-indigo-300 border border-indigo-700/60 uppercase">
                  RBAC Active
                </span>
              </div>
              <p className="text-xs sm:text-sm text-slate-400 mt-0.5">
                Inspect registered users, IDs, credentials, Date of Birth (DOB), scan dossiers, and system health.
              </p>
            </div>
          </div>
        </div>

        {/* Tab Switcher */}
        <div className="flex items-center gap-1 bg-slate-900 p-1 rounded-lg border border-slate-800">
          {[
            { id: 'users', label: 'User Directory', icon: Users },
            { id: 'health', label: 'Telemetry & DB', icon: Activity },
            { id: 'logs', label: 'Audit Trail', icon: FileText },
            { id: 'threats', label: 'Threat Signatures', icon: Database },
          ].map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                id={`admin-tab-${tab.id}`}
                onClick={() => setActiveTab(tab.id as any)}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold transition-colors cursor-pointer ${
                  activeTab === tab.id 
                    ? 'bg-indigo-600/90 text-white shadow-sm' 
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Notification Banner */}
      {adminNotification && (
        <div className={`p-4 rounded-xl border flex items-center justify-between text-xs font-mono transition-all ${
          adminNotification.type === 'success'
            ? 'bg-emerald-950/40 border-emerald-800/60 text-emerald-300'
            : 'bg-rose-950/40 border-rose-800/60 text-rose-300'
        }`}>
          <div className="flex items-center gap-2">
            {adminNotification.type === 'success' ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            ) : (
              <AlertTriangle className="w-4 h-4 text-rose-400" />
            )}
            <span>{adminNotification.message}</span>
          </div>
          <button
            onClick={() => setAdminNotification(null)}
            className="p-1 hover:bg-white/10 rounded cursor-pointer"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Quick Metrics Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <SpotlightCard className="p-4 bg-slate-900/40 border-slate-800">
          <div className="text-[10px] font-mono uppercase text-slate-400">Total Registered Users</div>
          <div className="text-2xl sm:text-3xl font-bold text-slate-100 font-mono mt-1">
            <ScrambleText text={String(stats.totalUsers)} />
          </div>
          <div className="text-[11px] text-blue-400 mt-1 flex items-center gap-1">
            <Users className="w-3 h-3" />
            <span>SQLite Database Users</span>
          </div>
        </SpotlightCard>

        <SpotlightCard className="p-4 bg-slate-900/40 border-slate-800">
          <div className="text-[10px] font-mono uppercase text-slate-400">Total Scans Executed</div>
          <div className="text-2xl sm:text-3xl font-bold text-indigo-400 font-mono mt-1">
            <ScrambleText text={String(stats.totalScans)} />
          </div>
          <div className="text-[11px] text-indigo-400/80 mt-1 flex items-center gap-1">
            <Cpu className="w-3 h-3" />
            <span>Relational Forensics</span>
          </div>
        </SpotlightCard>

        <SpotlightCard className="p-4 bg-slate-900/40 border-slate-800">
          <div className="text-[10px] font-mono uppercase text-slate-400">Threats Neutralized</div>
          <div className="text-2xl sm:text-3xl font-bold text-rose-400 font-mono mt-1">
            <ScrambleText text={String(stats.maliciousScans)} />
          </div>
          <div className="text-[11px] text-rose-400/80 mt-1 flex items-center gap-1">
            <ShieldAlert className="w-3 h-3" />
            <span>Phishing Vectors</span>
          </div>
        </SpotlightCard>

        <SpotlightCard className="p-4 bg-slate-900/40 border-slate-800">
          <div className="text-[10px] font-mono uppercase text-slate-400">Database Engine</div>
          <div className="text-base sm:text-lg font-bold text-emerald-400 font-mono mt-2 truncate">
            SQLite (LibSQL)
          </div>
          <div className="text-[11px] text-emerald-400/80 mt-1 flex items-center gap-1">
            <Database className="w-3 h-3" />
            <span>Foreign Key Integrity</span>
          </div>
        </SpotlightCard>
      </div>

      {/* ========================================================= */}
      {/* TAB 1: USER DIRECTORY & RBAC MATRIX                       */}
      {/* ========================================================= */}
      {activeTab === 'users' && (
        <SpotlightCard className="overflow-hidden border border-slate-800">
          {/* Controls Bar: Search, Filters, Refresh, Export */}
          <div className="p-5 border-b border-slate-800 bg-[#07090e]/70 space-y-4">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div>
                <h3 className="font-bold text-slate-100 text-sm sm:text-base flex items-center gap-2">
                  <Users className="w-4 h-4 text-blue-400" />
                  <span>User Directory & Forensic Information Matrix</span>
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  View User IDs, Clerk IDs, usernames, real names, Date of Birth (DOB), roles, and scan histories.
                </p>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  onClick={fetchAllAdminData}
                  disabled={isLoadingUsers}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono font-medium rounded-lg transition-colors flex items-center gap-1.5 border border-slate-700 cursor-pointer disabled:opacity-50"
                  title="Reload users from database"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${isLoadingUsers ? 'animate-spin' : ''}`} />
                  <span>Refresh</span>
                </button>

                <button
                  type="button"
                  onClick={handleExportUsersJSON}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono font-medium rounded-lg transition-colors flex items-center gap-1.5 border border-slate-700 cursor-pointer"
                  title="Export entire user database to JSON"
                >
                  <Download className="w-3.5 h-3.5 text-blue-400" />
                  <span>Export JSON</span>
                </button>

                <button
                  type="button"
                  onClick={handleExportUsersCSV}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono font-medium rounded-lg transition-colors flex items-center gap-1.5 border border-slate-700 cursor-pointer"
                  title="Export user database to CSV spreadsheet"
                >
                  <Download className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Export CSV</span>
                </button>
              </div>
            </div>

            {/* Search Input & Role Filter Row */}
            <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3 pt-1">
              <div className="relative flex-1">
                <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={userSearchTerm}
                  onChange={(e) => setUserSearchTerm(e.target.value)}
                  placeholder="Search by User ID, Clerk ID, Name, Username, Email, or DOB..."
                  className="w-full bg-[#080c14] text-xs text-slate-200 pl-9 pr-3.5 py-2.5 rounded-lg border border-slate-700 outline-none focus:border-blue-500 font-mono"
                />
                {userSearchTerm && (
                  <button
                    onClick={() => setUserSearchTerm('')}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200"
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>

              {/* Role filter dropdown */}
              <div className="flex items-center gap-2">
                <span className="text-xs text-slate-400 font-mono whitespace-nowrap flex items-center gap-1">
                  <Filter className="w-3.5 h-3.5" />
                  <span>Role:</span>
                </span>
                <select
                  value={roleFilter}
                  onChange={(e) => setRoleFilter(e.target.value)}
                  className="bg-[#080c14] text-xs font-mono text-slate-200 px-3 py-2.5 rounded-lg border border-slate-700 outline-none cursor-pointer"
                >
                  <option value="all">All Roles ({users.length})</option>
                  <option value="admin">Administrators</option>
                  <option value="analyst">Security Analysts</option>
                  <option value="user">Standard Users</option>
                </select>
              </div>
            </div>
          </div>

          {/* Users Table */}
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-[#070a12] text-slate-400 font-mono text-[11px] uppercase border-b border-slate-800">
                <tr>
                  <th className="px-4 py-3.5 whitespace-nowrap">User ID & Identifiers</th>
                  <th className="px-4 py-3.5 whitespace-nowrap">User Name & Avatar</th>
                  <th className="px-4 py-3.5 whitespace-nowrap">Username</th>
                  <th className="px-4 py-3.5 whitespace-nowrap">Date of Birth (DOB)</th>
                  <th className="px-4 py-3.5 whitespace-nowrap">Email Address</th>
                  <th className="px-4 py-3.5 whitespace-nowrap">Role Designation</th>
                  <th className="px-4 py-3.5 whitespace-nowrap text-center">Activity & Scans</th>
                  <th className="px-4 py-3.5 whitespace-nowrap text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {isLoadingUsers ? (
                  <tr>
                    <td colSpan={8} className="px-4 py-12 text-center text-slate-400 font-sans">
                      <div className="flex flex-col items-center justify-center gap-2">
                        <RefreshCw className="w-6 h-6 animate-spin text-blue-400" />
                        <span className="text-xs font-mono">Querying relational user registry...</span>
                      </div>
                    </td>
                  </tr>
                ) : filteredUsers.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="px-4 py-12 text-center text-slate-400 font-sans">
                      <div className="flex flex-col items-center justify-center gap-2">
                        <Users className="w-8 h-8 text-slate-600" />
                        <span className="text-sm text-slate-300 font-semibold">No users matching search filters</span>
                        <span className="text-xs text-slate-500">Try adjusting your search query or reset the role filter.</span>
                      </div>
                    </td>
                  </tr>
                ) : (
                  filteredUsers.map((u) => {
                    const fullName = [u.first_name, u.last_name].filter(Boolean).join(' ');
                    const isAdmin = (u.role || '').toLowerCase() === 'admin';

                    return (
                      <tr key={u.id} className="hover:bg-slate-800/40 transition-colors">
                        
                        {/* 1. USER ID & CLERK IDENTIFIERS */}
                        <td className="px-4 py-3.5">
                          <div className="space-y-1">
                            <div className="flex items-center gap-1.5">
                              <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-blue-950/70 border border-blue-700/60 text-blue-300">
                                ID #{u.id}
                              </span>
                              {isAdmin && (
                                <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-indigo-950/80 border border-indigo-700 text-indigo-300">
                                  ADMIN
                                </span>
                              )}
                            </div>
                            
                            <div className="flex items-center gap-1 text-[10px] text-slate-400">
                              <span className="font-mono text-slate-400 truncate max-w-[120px]" title={u.clerk_user_id}>
                                {u.clerk_user_id}
                              </span>
                              <button
                                type="button"
                                onClick={() => handleCopy(u.clerk_user_id, `clerk-${u.id}`)}
                                className="p-0.5 hover:text-white transition-colors cursor-pointer"
                                title="Copy Clerk User ID"
                              >
                                {copiedId === `clerk-${u.id}` ? (
                                  <Check className="w-3 h-3 text-emerald-400" />
                                ) : (
                                  <Copy className="w-3 h-3 text-slate-500 hover:text-slate-300" />
                                )}
                              </button>
                            </div>
                          </div>
                        </td>

                        {/* 2. USER NAME & AVATAR */}
                        <td className="px-4 py-3.5">
                          <div className="flex items-center gap-2.5">
                            <div className="w-8 h-8 rounded-lg overflow-hidden bg-slate-800 border border-slate-700 shrink-0 flex items-center justify-center">
                              {u.profile_image_url ? (
                                <img
                                  src={u.profile_image_url}
                                  alt={fullName || 'Avatar'}
                                  className="w-full h-full object-cover"
                                  referrerPolicy="no-referrer"
                                  onError={(e) => {
                                    // Fallback to initial
                                    (e.target as HTMLElement).style.display = 'none';
                                  }}
                                />
                              ) : (
                                <span className="text-xs font-bold text-slate-300 uppercase">
                                  {(u.first_name?.charAt(0) || u.username?.charAt(0) || 'U')}
                                </span>
                              )}
                            </div>
                            <div>
                              <div className="font-semibold text-slate-100 text-xs">
                                {fullName || <span className="text-slate-400 italic">Not provided</span>}
                              </div>
                              <div className="text-[10px] text-slate-400">
                                Joined {u.created_at ? u.created_at.split('T')[0] : 'Recently'}
                              </div>
                            </div>
                          </div>
                        </td>

                        {/* 3. USERNAME */}
                        <td className="px-4 py-3.5 font-semibold text-blue-300">
                          {u.username ? (
                            <span>@{u.username}</span>
                          ) : (
                            <span className="text-slate-400 font-normal italic">—</span>
                          )}
                        </td>

                        {/* 4. DATE OF BIRTH (DOB) */}
                        <td className="px-4 py-3.5">
                          {u.date_of_birth ? (
                            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900/90 border border-slate-700/80 text-slate-200 text-xs w-fit">
                              <Calendar className="w-3.5 h-3.5 text-blue-400 shrink-0" />
                              <span className="font-semibold">{u.date_of_birth}</span>
                            </div>
                          ) : (
                            <span className="text-slate-400 text-[11px] italic">Not provided</span>
                          )}
                        </td>

                        {/* 5. EMAIL ADDRESS */}
                        <td className="px-4 py-3.5 text-slate-300">
                          {u.email ? (
                            <span className="truncate max-w-[180px] inline-block" title={u.email}>
                              {u.email}
                            </span>
                          ) : (
                            <span className="text-slate-400 italic">No email</span>
                          )}
                        </td>

                        {/* 6. ROLE DESIGNATION (Inline Selector) */}
                        <td className="px-4 py-3.5">
                          <select
                            value={(u.role || 'analyst').toLowerCase()}
                            onChange={(e) => handleRoleChange(u.id, e.target.value)}
                            className={`text-xs font-mono px-2.5 py-1 rounded-md border outline-none cursor-pointer transition-colors ${
                              (u.role || '').toLowerCase() === 'admin'
                                ? 'bg-indigo-950/80 text-indigo-300 border-indigo-700/80'
                                : (u.role || '').toLowerCase() === 'user'
                                ? 'bg-slate-900 text-slate-300 border-slate-700'
                                : 'bg-blue-950/80 text-blue-300 border-blue-700/80'
                            }`}
                          >
                            <option value="admin">Admin</option>
                            <option value="analyst">Analyst</option>
                            <option value="user">User</option>
                          </select>
                        </td>

                        {/* 7. SCANS & USAGE STATS */}
                        <td className="px-4 py-3.5 text-center">
                          <div className="inline-flex items-center gap-2">
                            <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-slate-900 border border-slate-800 text-slate-200" title="Total Scans">
                              {u.total_scans} scans
                            </span>
                            {u.high_risk_scans > 0 && (
                              <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-rose-950/70 border border-rose-800 text-rose-300" title="High Risk / Phishing Detections">
                                {u.high_risk_scans} threats
                              </span>
                            )}
                          </div>
                        </td>

                        {/* 8. ACTIONS */}
                        <td className="px-4 py-3.5 text-right">
                          <div className="flex items-center justify-end gap-1.5">
                            <button
                              type="button"
                              onClick={() => handleInspectUser(u)}
                              className="px-2 py-1 bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 border border-blue-500/30 rounded text-xs transition-colors flex items-center gap-1 cursor-pointer"
                              title="Inspect full user dossier and scan logs"
                            >
                              <Eye className="w-3 h-3" />
                              <span className="hidden sm:inline">Inspect</span>
                            </button>

                            <button
                              type="button"
                              onClick={() => setUserToDelete(u)}
                              className="p-1 text-slate-400 hover:text-rose-400 hover:bg-rose-950/40 rounded transition-colors cursor-pointer"
                              title="Delete user and associated records"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </td>

                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          {/* Table Footer Summary */}
          <div className="p-4 border-t border-slate-800 bg-[#07090e] flex flex-col sm:flex-row items-center justify-between text-xs text-slate-400 font-mono gap-2">
            <div>
              Showing {filteredUsers.length} of {users.length} registered database accounts
            </div>
            <div className="flex items-center gap-4 text-[11px]">
              <span className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-indigo-400" />
                <span>Admin ({users.filter(u => (u.role || '').toLowerCase() === 'admin').length})</span>
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-blue-400" />
                <span>Analysts ({users.filter(u => (u.role || '').toLowerCase() === 'analyst').length})</span>
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-slate-400" />
                <span>Users ({users.filter(u => (u.role || '').toLowerCase() === 'user').length})</span>
              </span>
            </div>
          </div>
        </SpotlightCard>
      )}

      {/* ========================================================= */}
      {/* TAB 2: SYSTEM TELEMETRY & DATABASE HEALTH                 */}
      {/* ========================================================= */}
      {activeTab === 'health' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <SpotlightCard className="p-5">
              <div className="text-[11px] font-mono uppercase text-slate-400">Total Registered Users</div>
              <div className="text-3xl font-bold text-slate-100 font-mono mt-2">
                <ScrambleText text={String(stats.totalUsers)} />
              </div>
              <div className="text-[11px] text-blue-400 mt-1">RBAC Multi-Tenant Matrix</div>
            </SpotlightCard>

            <SpotlightCard className="p-5 border-blue-500/20">
              <div className="text-[11px] font-mono uppercase text-slate-400">Model Accuracy Rate</div>
              <div className="text-3xl font-bold text-blue-400 font-mono mt-2">
                <ScrambleText text={stats.accuracyRate} />
              </div>
              <div className="text-[11px] text-blue-400/80 mt-1">Ensemble Random Forest</div>
            </SpotlightCard>

            <SpotlightCard className="p-5 border-emerald-500/20">
              <div className="text-[11px] font-mono uppercase text-slate-400">Average Inference Latency</div>
              <div className="text-3xl font-bold text-emerald-400 font-mono mt-2">
                <ScrambleText text={`${stats.avgScanTimeMs}ms`} />
              </div>
              <div className="text-[11px] text-emerald-400/80 mt-1">Zero-DNS Leaking Engine</div>
            </SpotlightCard>

            <SpotlightCard className="p-5 border-amber-500/20">
              <div className="text-[11px] font-mono uppercase text-slate-400">Threat DB Heuristic Rules</div>
              <div className="text-3xl font-bold text-amber-400 font-mono mt-2">
                <ScrambleText text={String(threats.length)} />
              </div>
              <div className="text-[11px] text-amber-400/80 mt-1">Active Whitelist/Blacklist</div>
            </SpotlightCard>
          </div>

          <SpotlightCard className="p-6 space-y-4">
            <div className="flex items-center gap-2 pb-2 border-b border-slate-800">
              <Server className="w-4 h-4 text-blue-400" />
              <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
                Core System Architecture & Microservice State
              </h3>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs font-mono">
              <div className="bg-[#080c14] p-4 rounded-lg border border-slate-800/90 space-y-1">
                <span className="text-slate-400 text-[11px]">Relational Persistence Layer</span>
                <div className="text-emerald-400 font-semibold text-xs">SQLite (LibSQL Engine)</div>
                <div className="text-slate-500 text-[10px]">Foreign keys enabled • Scans tied to users</div>
              </div>

              <div className="bg-[#080c14] p-4 rounded-lg border border-slate-800/90 space-y-1">
                <span className="text-slate-400 text-[11px]">Authentication Gateway</span>
                <div className="text-blue-300 font-semibold text-xs">Clerk Cloud SSO + JWT Tokens</div>
                <div className="text-slate-500 text-[10px]">Zero-tamper user identity sync</div>
              </div>

              <div className="bg-[#080c14] p-4 rounded-lg border border-slate-800/90 space-y-1">
                <span className="text-slate-400 text-[11px]">Express REST Gateway</span>
                <div className="text-slate-200 font-semibold text-xs">Port 3000 Ingress Routing</div>
                <div className="text-slate-500 text-[10px]">Strict CORS & Security Headers Active</div>
              </div>
            </div>
          </SpotlightCard>
        </div>
      )}

      {/* ========================================================= */}
      {/* TAB 3: AUDIT TRAIL LOGS                                   */}
      {/* ========================================================= */}
      {activeTab === 'logs' && (
        <SpotlightCard className="overflow-hidden border border-slate-800">
          <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-[#07090e]/70">
            <div className="flex items-center gap-2">
              <FileText className="w-4 h-4 text-blue-400" />
              <h3 className="font-semibold text-slate-200 text-sm">Security Event Audit Trail</h3>
            </div>
            <span className="text-xs text-slate-400 font-mono">{auditLogs.length} events logged</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-[#080c14] text-slate-400 font-mono text-[11px] uppercase border-b border-slate-800">
                <tr>
                  <th className="px-5 py-3">Timestamp</th>
                  <th className="px-5 py-3">Subject</th>
                  <th className="px-5 py-3">Event Type</th>
                  <th className="px-5 py-3">Details</th>
                  <th className="px-5 py-3">Origin IP</th>
                  <th className="px-5 py-3">Severity</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {auditLogs.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="p-8 text-center text-slate-500">
                      No security audit events recorded yet.
                    </td>
                  </tr>
                ) : (
                  auditLogs.map((log) => (
                    <tr key={log.id} className="hover:bg-slate-800/40">
                      <td className="px-5 py-3 text-slate-400">{log.timestamp.substring(0, 19).replace('T', ' ')}</td>
                      <td className="px-5 py-3 font-semibold text-slate-200">{log.username}</td>
                      <td className="px-5 py-3 text-blue-300">{log.eventType}</td>
                      <td className="px-5 py-3 text-slate-300 font-sans text-xs">{log.details}</td>
                      <td className="px-5 py-3 text-slate-400">{log.ipAddress}</td>
                      <td className="px-5 py-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                          log.severity === 'CRITICAL' ? 'bg-rose-950/70 text-rose-300 border border-rose-500/40' :
                          log.severity === 'WARN' ? 'bg-amber-950/70 text-amber-300 border border-amber-500/40' :
                          'bg-slate-800 text-slate-300 border border-slate-700'
                        }`}>
                          {log.severity}
                        </span>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </SpotlightCard>
      )}

      {/* ========================================================= */}
      {/* TAB 4: THREAT INTELLIGENCE PATTERNS                       */}
      {/* ========================================================= */}
      {activeTab === 'threats' && (
        <div className="space-y-6">
          
          <SpotlightCard className="p-6 space-y-4 border border-slate-800">
            <div className="flex items-center gap-2 pb-2 border-b border-slate-800">
              <Plus className="w-4 h-4 text-blue-400" />
              <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
                Create Threat Pattern Rule (Blacklist / Whitelist)
              </h3>
            </div>

            <form onSubmit={handleAddThreat} className="flex flex-col sm:flex-row gap-3">
              <input
                type="text"
                value={newPattern}
                onChange={(e) => setNewPattern(e.target.value)}
                placeholder="Target pattern e.g. amazon-arrived.com or verify-auth-login"
                required
                className="flex-1 bg-[#080c14] text-xs font-mono text-slate-100 px-3.5 py-2.5 rounded-lg border border-slate-700 outline-none focus:border-blue-500"
              />

              <select
                value={newThreatType}
                onChange={(e) => setNewThreatType(e.target.value as any)}
                className="bg-[#080c14] text-xs font-mono text-slate-200 px-3 py-2.5 rounded-lg border border-slate-700 outline-none cursor-pointer"
              >
                <option value="Phishing">Phishing</option>
                <option value="Typosquatting">Typosquatting</option>
                <option value="Malware">Malware</option>
                <option value="Whitelist">Whitelist</option>
              </select>

              <MagneticButton
                type="submit"
                className="px-5 py-2.5 bg-blue-600 hover:bg-blue-500 text-white font-medium text-xs rounded-lg cursor-pointer flex items-center justify-center gap-1.5 shadow-sm transition-colors"
              >
                <Plus className="w-3.5 h-3.5 text-white" />
                <span>Add Threat Rule</span>
              </MagneticButton>
            </form>
          </SpotlightCard>

          <SpotlightCard className="overflow-hidden border border-slate-800">
            <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-[#07090e]/70">
              <div className="flex items-center gap-2">
                <Database className="w-4 h-4 text-blue-400" />
                <h3 className="font-semibold text-slate-200 text-sm">Threat Intelligence Pattern Database</h3>
              </div>
              <span className="text-xs text-slate-400 font-mono">{threats.length} rules active</span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs text-slate-300">
                <thead className="bg-[#080c14] text-slate-400 font-mono text-[11px] uppercase border-b border-slate-800">
                  <tr>
                    <th className="px-5 py-3">Pattern Match</th>
                    <th className="px-5 py-3">Threat Type</th>
                    <th className="px-5 py-3">Enrolled By</th>
                    <th className="px-5 py-3">Enrolled Date</th>
                    <th className="px-5 py-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono">
                  {threats.map((t) => (
                    <tr key={t.id} className="hover:bg-slate-800/40">
                      <td className="px-5 py-3.5 font-semibold text-slate-200">{t.urlPattern}</td>
                      <td className="px-5 py-3.5">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                          t.threatType === 'Whitelist' 
                            ? 'bg-emerald-950/60 text-emerald-300 border border-emerald-800/60' 
                            : 'bg-rose-950/60 text-rose-300 border border-rose-500/30'
                        }`}>
                          {t.threatType}
                        </span>
                      </td>
                      <td className="px-5 py-3.5 text-slate-400">{t.addedBy}</td>
                      <td className="px-5 py-3.5 text-slate-400">{t.addedAt}</td>
                      <td className="px-5 py-3.5 text-right">
                        <button
                          onClick={() => handleDeleteThreat(t.id)}
                          className="p-1.5 text-slate-400 hover:text-rose-400 hover:bg-rose-950/30 rounded transition-colors cursor-pointer"
                          title="Delete Threat Rule"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </SpotlightCard>

        </div>
      )}

      {/* ========================================================= */}
      {/* MODAL 1: INSPECT USER DOSSIER & SCAN HISTORY             */}
      {/* ========================================================= */}
      {inspectingUser && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn">
          <div className="bg-[#090d16] border border-slate-700/80 rounded-2xl max-w-2xl w-full max-h-[90vh] overflow-y-auto shadow-2xl flex flex-col">
            
            {/* Modal Header */}
            <div className="p-5 border-b border-slate-800 flex items-center justify-between sticky top-0 bg-[#090d16]/95 backdrop-blur-md z-10">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-blue-600/10 border border-blue-500/30 flex items-center justify-center text-blue-400">
                  <UserCheck className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="font-bold text-slate-100 text-base flex items-center gap-2">
                    <span>Analyst Dossier #{inspectingUser.id}</span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-blue-950 text-blue-300 border border-blue-800">
                      {(inspectingUser.role || 'analyst').toUpperCase()}
                    </span>
                  </h3>
                  <p className="text-xs text-slate-400 font-mono">
                    Clerk ID: {inspectingUser.clerk_user_id}
                  </p>
                </div>
              </div>

              <button
                type="button"
                onClick={() => setInspectingUser(null)}
                className="p-2 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Content */}
            <div className="p-6 space-y-6">
              
              {/* Primary Identity Card */}
              <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col sm:flex-row items-start sm:items-center gap-4">
                <div className="w-16 h-16 rounded-2xl overflow-hidden bg-slate-800 border-2 border-blue-500/30 shrink-0 flex items-center justify-center">
                  {inspectingUser.profile_image_url ? (
                    <img
                      src={inspectingUser.profile_image_url}
                      alt="Avatar"
                      className="w-full h-full object-cover"
                      referrerPolicy="no-referrer"
                    />
                  ) : (
                    <span className="text-xl font-bold text-slate-300 uppercase">
                      {(inspectingUser.first_name?.charAt(0) || inspectingUser.username?.charAt(0) || 'U')}
                    </span>
                  )}
                </div>

                <div className="space-y-1 flex-1">
                  <div className="text-lg font-bold text-slate-100">
                    {[inspectingUser.first_name, inspectingUser.last_name].filter(Boolean).join(' ') || 'Unnamed Analyst'}
                  </div>
                  <div className="text-xs text-blue-400 font-mono">
                    @{inspectingUser.username || 'unknown_username'}
                  </div>
                  <div className="text-xs text-slate-400 font-mono">
                    {inspectingUser.email || 'No email associated'}
                  </div>
                </div>

                <div className="text-left sm:text-right space-y-1 font-mono text-xs">
                  <div className="text-slate-400 text-[10px]">DATE OF BIRTH</div>
                  <div className="text-slate-200 font-semibold flex items-center sm:justify-end gap-1">
                    <Calendar className="w-3.5 h-3.5 text-blue-400" />
                    <span>{inspectingUser.date_of_birth || 'Not specified'}</span>
                  </div>
                </div>
              </div>

              {/* Forensic Details Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
                <div className="p-3 rounded-lg bg-slate-900/40 border border-slate-800">
                  <div className="text-[10px] text-slate-400">DATABASE ID</div>
                  <div className="text-sm font-bold text-slate-100 mt-0.5">#{inspectingUser.id}</div>
                </div>

                <div className="p-3 rounded-lg bg-slate-900/40 border border-slate-800">
                  <div className="text-[10px] text-slate-400">TOTAL SCANS</div>
                  <div className="text-sm font-bold text-blue-400 mt-0.5">{inspectingUser.total_scans}</div>
                </div>

                <div className="p-3 rounded-lg bg-slate-900/40 border border-slate-800">
                  <div className="text-[10px] text-slate-400">HIGH RISK SCANS</div>
                  <div className="text-sm font-bold text-rose-400 mt-0.5">{inspectingUser.high_risk_scans}</div>
                </div>

                <div className="p-3 rounded-lg bg-slate-900/40 border border-slate-800">
                  <div className="text-[10px] text-slate-400">SAFE RATIO</div>
                  <div className="text-sm font-bold text-emerald-400 mt-0.5">{inspectingUser.safe_scans}</div>
                </div>
              </div>

              {/* Scanned URLs List by this User */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-bold text-slate-200 uppercase font-mono tracking-wider flex items-center gap-1.5">
                    <Globe className="w-3.5 h-3.5 text-blue-400" />
                    <span>Scanned URLs History ({inspectingUserScans.length})</span>
                  </h4>
                </div>

                {isLoadingScans ? (
                  <div className="p-8 text-center text-slate-400 font-mono text-xs flex items-center justify-center gap-2">
                    <RefreshCw className="w-4 h-4 animate-spin text-blue-400" />
                    <span>Loading forensic scan logs from database...</span>
                  </div>
                ) : inspectingUserScans.length === 0 ? (
                  <div className="p-6 rounded-xl bg-slate-900/30 border border-dashed border-slate-800 text-center text-slate-400 text-xs font-mono">
                    This user has not executed any URL forensic scans yet.
                  </div>
                ) : (
                  <div className="max-h-60 overflow-y-auto rounded-xl border border-slate-800 divide-y divide-slate-800 bg-[#07090e]">
                    {inspectingUserScans.map((scan) => (
                      <div key={scan.id} className="p-3 flex items-center justify-between gap-3 text-xs">
                        <div className="min-w-0 flex-1">
                          <div className="font-mono text-slate-200 truncate" title={scan.url}>
                            {scan.url}
                          </div>
                          <div className="text-[10px] font-mono text-slate-400 mt-0.5">
                            {scan.timestamp ? scan.timestamp.substring(0, 19).replace('T', ' ') : ''}
                          </div>
                        </div>

                        <div className="flex items-center gap-2 shrink-0">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                            scan.riskScore > 60
                              ? 'bg-rose-950/80 text-rose-300 border border-rose-800'
                              : scan.riskScore > 40
                              ? 'bg-amber-950/80 text-amber-300 border border-amber-800'
                              : 'bg-emerald-950/80 text-emerald-300 border border-emerald-800'
                          }`}>
                            {scan.riskScore}% {scan.label || 'Scanned'}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-slate-800 bg-[#07090e] flex items-center justify-between sticky bottom-0">
              <div className="text-[11px] font-mono text-slate-400">
                Synchronized with SQLite Relational DB
              </div>
              <button
                type="button"
                onClick={() => setInspectingUser(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium text-xs rounded-lg transition-colors cursor-pointer"
              >
                Close Dossier
              </button>
            </div>

          </div>
        </div>
      )}

      {/* ========================================================= */}
      {/* MODAL 2: CONFIRM DELETE USER                              */}
      {/* ========================================================= */}
      {userToDelete && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn">
          <div className="bg-[#0c101c] border border-rose-500/40 rounded-2xl max-w-md w-full p-6 shadow-2xl space-y-4">
            <div className="w-12 h-12 rounded-xl bg-rose-950/80 border border-rose-500/40 text-rose-400 flex items-center justify-center mx-auto">
              <AlertTriangle className="w-6 h-6" />
            </div>

            <div className="text-center space-y-1">
              <h3 className="text-base font-bold text-slate-100">Expunge User Record #{userToDelete.id}?</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                This will permanently delete the database record for <strong className="text-slate-200">@{userToDelete.username || userToDelete.email}</strong> and cascade-delete all associated scan histories. This action cannot be reversed.
              </p>
            </div>

            <div className="flex items-center gap-3 pt-2">
              <button
                type="button"
                onClick={() => setUserToDelete(null)}
                className="flex-1 px-4 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium text-xs rounded-lg transition-colors cursor-pointer"
              >
                Cancel
              </button>

              <button
                type="button"
                disabled={isDeletingUser}
                onClick={confirmDeleteUser}
                className="flex-1 px-4 py-2.5 bg-rose-600 hover:bg-rose-500 text-white font-medium text-xs rounded-lg transition-colors cursor-pointer flex items-center justify-center gap-1.5 shadow-sm disabled:opacity-50"
              >
                {isDeletingUser ? (
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <Trash2 className="w-3.5 h-3.5" />
                )}
                <span>Confirm Delete</span>
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
};
