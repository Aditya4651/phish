import React, { useState, useEffect } from 'react';
import { AnimatePresence } from 'motion/react';
import { Navbar } from './components/Navbar';
import { URLScanner } from './components/URLScanner';
import { ScanResultCard } from './components/ScanResultCard';
import { Dashboard } from './components/Dashboard';
import { ReportsList } from './components/ReportsList';
import { UserProfileView } from './components/UserProfileView';
import { AdminPanel } from './components/AdminPanel';
import { DatasetViewer } from './components/DatasetViewer';
import { ClerkAuthModal } from './components/ClerkAuthModal';
import { PageTransition } from './components/motion/PageTransition';
import { ToastContainer, ToastMessage } from './components/ToastNotification';
import { URLScanResult, User } from './types';
import { Lock, ShieldAlert, Database } from 'lucide-react';
import { MagneticButton } from './components/motion/MagneticButton';
import { useAppAuth } from './context/AuthContext';

export default function App() {
  const { 
    user: authUser, 
    dbUser, 
    isLoggedIn, 
    isLoaded, 
    isClerkConfigured, 
    getAuthToken, 
    isAuthModalOpen,
    openSignIn, 
    openSignUp, 
    closeAuthModal,
    signOut 
  } = useAppAuth();

  const [activeTab, setActiveTab] = useState('scanner');
  const [scanHistory, setScanHistory] = useState<URLScanResult[]>([]);
  const [currentScan, setCurrentScan] = useState<URLScanResult | null>(null);
  const [isLoginModalOpen, setIsLoginModalOpen] = useState(false);
  const [toasts, setToasts] = useState<ToastMessage[]>([]);

  // Effective unified user object
  const currentUser: User = authUser || {
    id: 'usr-guest',
    username: 'Guest Analyst',
    email: 'guest@cybersec.org',
    role: 'Guest',
    isLoggedIn: false,
    accountStatus: 'Active',
    verificationStatus: false,
    createdAt: new Date().toISOString().split('T')[0],
  };

  const addToast = (title: string, description?: string, type: 'success' | 'warning' | 'info' = 'success') => {
    const id = Math.random().toString(36).substring(2, 9);
    setToasts(prev => [...prev, { id, title, description, type }]);
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id));
    }, 4200);
  };

  const removeToast = (id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  };

  // Determine if the current user has verified administrator privileges
  const isAdmin = Boolean(
    isLoggedIn && (
      (currentUser.role || '').toLowerCase() === 'admin' ||
      (dbUser?.role || '').toLowerCase() === 'admin' ||
      currentUser.username?.toLowerCase() === 'admin'
    )
  );

  // Security guard: If user is not an authenticated admin and attempts to open 'admin', redirect to 'scanner'
  useEffect(() => {
    if (activeTab === 'admin' && !isAdmin && isLoaded) {
      setActiveTab('scanner');
    }
  }, [activeTab, isAdmin, isLoaded]);

  // Fetch scan history from SQLite database for authenticated user
  const fetchUserScans = async () => {
    if (!isLoggedIn) {
      setScanHistory([]);
      return;
    }

    try {
      const token = await getAuthToken();
      const headers: Record<string, string> = {};
      if (token) headers['Authorization'] = `Bearer ${token}`;

      const res = await fetch('/api/scans', { headers });
      if (res.ok) {
        const data = await res.json();
        if (data && Array.isArray(data.scans)) {
          setScanHistory(data.scans);
        } else if (Array.isArray(data)) {
          setScanHistory(data);
        }
      }
    } catch (err) {
      console.warn('[App] Error loading scans:', err);
    }
  };

  useEffect(() => {
    fetchUserScans();
  }, [isLoggedIn]);

  const handleScanComplete = async (result: URLScanResult) => {
    setCurrentScan(result);
    setScanHistory(prev => [result, ...prev]);

    const isPhish = result.riskScore > 60;
    addToast(
      isPhish ? 'Phishing Threat Vector Detected' : 'Scan Evaluation Finished',
      `${result.domain.hostname} classified as ${result.riskLevel} (${result.riskScore}% Risk)`,
      isPhish ? 'warning' : 'success'
    );

    // If authenticated, persist to relational SQLite database
    if (isLoggedIn) {
      try {
        const token = await getAuthToken();
        const headers: Record<string, string> = {
          'Content-Type': 'application/json',
        };
        if (token) headers['Authorization'] = `Bearer ${token}`;

        const res = await fetch('/api/scan', {
          method: 'POST',
          headers,
          body: JSON.stringify({
            url: result.url,
            scannedBy: currentUser.username || 'Analyst',
          }),
        });

        if (res.ok) {
          const saved = await res.json();
          // Update record with server generated ID if provided
          if (saved && saved.id) {
            setCurrentScan(saved);
            setScanHistory(prev => prev.map(s => s.id === result.id ? saved : s));
          }
        }
      } catch (err) {
        console.warn('Scan persistence error:', err);
      }
    }
  };

  const handleDeleteScan = async (id: string) => {
    setScanHistory(prev => prev.filter(item => item.id !== id));
    if (currentScan?.id === id) {
      setCurrentScan(null);
    }
    addToast('Audit Record Purged', 'Scan removed from intelligence repository', 'info');

    if (isLoggedIn) {
      try {
        const token = await getAuthToken();
        const headers: Record<string, string> = {};
        if (token) headers['Authorization'] = `Bearer ${token}`;

        await fetch(`/api/scans/${id}`, {
          method: 'DELETE',
          headers,
        });
      } catch (err) {
        console.warn('Error deleting scan:', err);
      }
    }
  };

  const handleSelectScanFromDashboard = (scan: URLScanResult) => {
    setCurrentScan(scan);
    setActiveTab('scanner');
  };

  const handleRegenerateApiKey = async () => {
    const token = await getAuthToken();
    const res = await fetch('/api/user/api-key', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify({ username: currentUser.username }),
    });
    const data = await res.json();
    return data.apiKey;
  };

  const handleOpenAuth = () => {
    setIsLoginModalOpen(true);
  };

  return (
    <div className="min-h-screen bg-[#090a0f] text-slate-100 flex flex-col font-sans selection:bg-blue-600 selection:text-white">
      {/* Top Navbar */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={(tab) => {
          setActiveTab(tab);
          if (tab !== 'scanner') {
            setCurrentScan(null);
          }
        }}
        user={currentUser}
        onOpenLogin={handleOpenAuth}
        onLogout={signOut}
      />

      {/* Main Analysis Stage */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 sm:py-10">
        <AnimatePresence mode="wait">
          {activeTab === 'scanner' && (
            <PageTransition key="scanner-tab">
              {currentScan ? (
                <ScanResultCard
                  result={currentScan}
                  onScanNew={() => setCurrentScan(null)}
                />
              ) : (
                <URLScanner
                  onScanComplete={handleScanComplete}
                  user={currentUser}
                  onOpenLogin={handleOpenAuth}
                />
              )}
            </PageTransition>
          )}

          {activeTab === 'dashboard' && (
            <PageTransition key="dashboard">
              <Dashboard
                scanHistory={scanHistory}
                onSelectScan={handleSelectScanFromDashboard}
                onDeleteScan={handleDeleteScan}
                user={currentUser}
                onOpenLogin={handleOpenAuth}
              />
            </PageTransition>
          )}

          {activeTab === 'reports' && (
            <PageTransition key="reports">
              <ReportsList
                scanHistory={scanHistory}
                onSelectScan={handleSelectScanFromDashboard}
                onDeleteScan={handleDeleteScan}
                user={currentUser}
                onOpenLogin={handleOpenAuth}
              />
            </PageTransition>
          )}

          {activeTab === 'profile' && (
            <PageTransition key="profile">
              <UserProfileView
                user={currentUser}
                onRegenerateApiKey={handleRegenerateApiKey}
                onLogout={signOut}
                onOpenLogin={handleOpenAuth}
              />
            </PageTransition>
          )}

          {activeTab === 'admin' && (
            <PageTransition key="admin">
              <AdminPanel 
                currentUser={currentUser}
                onOpenLogin={handleOpenAuth}
                getAuthToken={getAuthToken}
              />
            </PageTransition>
          )}

          {activeTab === 'dataset' && (
            <PageTransition key="dataset">
              <DatasetViewer 
                userScans={scanHistory}
                currentUser={currentUser}
                onSelectScan={handleSelectScanFromDashboard}
                onOpenLogin={handleOpenAuth}
              />
            </PageTransition>
          )}
        </AnimatePresence>
      </main>

      {/* Editorial Systemic Footer */}
      <footer className="border-t border-slate-800/80 bg-[#06080e] py-6 text-xs text-slate-400">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2 font-mono">
            <img src="/logo-emblem.png" alt="PhishGuard" className="w-4 h-4 object-contain" referrerPolicy="no-referrer" />
            <span className="text-slate-300 font-semibold">PHISH<span className="text-cyan-400">GUARD</span>.ai</span>
            <span className="text-slate-600">•</span>
            <span className="text-slate-400">RFC 3986 Lexical Audit Standard</span>
            <span className="text-slate-600">•</span>
            <span className="text-emerald-400/90 flex items-center gap-1">
              <Database className="w-3 h-3" />
              <span>Relational Database Sync</span>
            </span>
          </div>

          <div className="text-slate-400 font-mono text-[11px]">
            Clerk Authentication • SQLite Persistence • Scikit-Learn RF Model
          </div>
        </div>
      </footer>

      {/* Clerk Authentication Setup & Access Modal */}
      <ClerkAuthModal
        isOpen={isLoginModalOpen || isAuthModalOpen}
        onClose={() => {
          setIsLoginModalOpen(false);
          closeAuthModal();
        }}
      />

      {/* Floating Micro-Interaction Toast Notifications */}
      <ToastContainer toasts={toasts} onDismiss={removeToast} />
    </div>
  );
}
