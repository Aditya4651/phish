import React, { useState, useEffect } from 'react';
import { 
  X, 
  Key,
  ExternalLink,
  ShieldCheck,
  AlertCircle,
  UserCheck,
  Shield,
  Lock,
  UserPlus,
  LogIn
} from 'lucide-react';
import { SignIn, SignUp } from '@clerk/clerk-react';
import { useAppAuth } from '../context/AuthContext';

interface ClerkAuthModalProps {
  isOpen: boolean;
  onClose: () => void;
  initialMode?: 'signin' | 'signup';
}

export const ClerkAuthModal: React.FC<ClerkAuthModalProps> = ({ 
  isOpen, 
  onClose,
  initialMode = 'signin' 
}) => {
  const { 
    clerkKeyStatus,
    saveCustomClerkKey,
    loginWithCredentials,
    registerAccount,
    isLoggedIn 
  } = useAppAuth();

  const [activeTab, setActiveTab] = useState<'quick' | 'credentials' | 'register' | 'clerk'>('quick');
  const [authMode, setAuthMode] = useState<'signin' | 'signup'>(initialMode);
  const [customKeyInput, setCustomKeyInput] = useState('');
  const [usernameInput, setUsernameInput] = useState('');
  const [passwordInput, setPasswordInput] = useState('');
  const [emailInput, setEmailInput] = useState('');
  const [firstNameInput, setFirstNameInput] = useState('');
  const [lastNameInput, setLastNameInput] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  useEffect(() => {
    setAuthMode(initialMode);
    setErrorMessage(null);
  }, [initialMode, isOpen]);

  // Close modal when sign-in or registration succeeds
  useEffect(() => {
    if (isLoggedIn && isOpen) {
      onClose();
    }
  }, [isLoggedIn, isOpen, onClose]);

  if (!isOpen) return null;

  const handleQuickLogin = async (role: 'analyst' | 'admin') => {
    setIsSubmitting(true);
    setErrorMessage(null);
    try {
      const res = await loginWithCredentials(role, role);
      if (!res.success) {
        setErrorMessage(res.error || 'Failed to sign in');
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'Error during sign-in');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleCredentialsSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!usernameInput.trim()) {
      setErrorMessage('Username or email is required.');
      return;
    }
    setIsSubmitting(true);
    setErrorMessage(null);
    try {
      const res = await loginWithCredentials(usernameInput.trim(), passwordInput);
      if (!res.success) {
        setErrorMessage(res.error || 'Invalid credentials.');
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'Error signing in.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleRegisterSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!usernameInput.trim() || !emailInput.trim()) {
      setErrorMessage('Username and email are required.');
      return;
    }
    setIsSubmitting(true);
    setErrorMessage(null);
    try {
      const res = await registerAccount({
        username: usernameInput.trim(),
        email: emailInput.trim(),
        password: passwordInput,
        firstName: firstNameInput.trim(),
        lastName: lastNameInput.trim(),
      });
      if (!res.success) {
        setErrorMessage(res.error || 'Registration failed.');
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'Error creating account.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleSaveKey = (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = customKeyInput.trim();
    if (!trimmed.startsWith('pk_test_') && !trimmed.startsWith('pk_live_')) {
      setErrorMessage('Key must be a valid Clerk Publishable Key starting with pk_test_ or pk_live_');
      return;
    }
    saveCustomClerkKey(trimmed);
  };

  return (
    <div 
      className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 bg-black/80 backdrop-blur-md overflow-y-auto"
      onClick={onClose}
    >
      <div 
        className="relative w-full max-w-md bg-[#0b101d] border border-slate-800/90 rounded-2xl shadow-2xl p-6 sm:p-7 overflow-hidden text-slate-100 my-8"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Subtle Top Gradient Line */}
        <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-blue-600 via-indigo-500 to-cyan-400" />

        {/* Close Button */}
        <button
          onClick={onClose}
          className="absolute top-4 right-4 p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800/80 transition-colors cursor-pointer"
          title="Close dialog"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Brand Header */}
        <div className="flex items-center gap-3.5 mb-5">
          <div className="w-11 h-11 rounded-xl bg-slate-900 border border-slate-700/80 p-2 flex items-center justify-center shrink-0 shadow-md">
            <img src="/logo-emblem.png" alt="PhishGuard" className="w-full h-full object-contain" referrerPolicy="no-referrer" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-white tracking-tight">
              {clerkKeyStatus === 'live' 
                ? (authMode === 'signin' ? 'Sign In' : 'Create Account')
                : 'Security Analyst Authentication'}
            </h2>
            <p className="text-xs text-slate-400">
              {clerkKeyStatus === 'live'
                ? 'Secured with Clerk authentication & SQLite database persistence.'
                : 'Sign in to persist your scans to Intelligence and Audit Dossiers.'}
            </p>
          </div>
        </div>

        {/* Live Clerk Provider View */}
        {clerkKeyStatus === 'live' ? (
          <div className="space-y-4">
            <div className="flex justify-center rounded-xl overflow-hidden">
              {authMode === 'signin' ? (
                <SignIn routing="virtual" />
              ) : (
                <SignUp routing="virtual" />
              )}
            </div>
            <div className="text-center pt-2">
              <button
                type="button"
                onClick={() => setAuthMode(authMode === 'signin' ? 'signup' : 'signin')}
                className="text-xs text-blue-400 hover:text-blue-300 font-medium cursor-pointer"
              >
                {authMode === 'signin' 
                  ? "Don't have an account? Sign up" 
                  : 'Already have an account? Sign in'}
              </button>
            </div>
          </div>
        ) : (
          /* Direct Database & Analyst Auth View */
          <div className="space-y-4">
            {/* Navigation Tabs */}
            <div className="flex items-center gap-1 p-1 bg-slate-900/90 rounded-xl border border-slate-800 text-xs">
              <button
                type="button"
                onClick={() => { setActiveTab('quick'); setErrorMessage(null); }}
                className={`flex-1 py-1.5 px-2 rounded-lg font-medium transition-colors cursor-pointer text-center ${
                  activeTab === 'quick' ? 'bg-blue-600 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Quick Access
              </button>
              <button
                type="button"
                onClick={() => { setActiveTab('credentials'); setErrorMessage(null); }}
                className={`flex-1 py-1.5 px-2 rounded-lg font-medium transition-colors cursor-pointer text-center ${
                  activeTab === 'credentials' ? 'bg-blue-600 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Sign In
              </button>
              <button
                type="button"
                onClick={() => { setActiveTab('register'); setErrorMessage(null); }}
                className={`flex-1 py-1.5 px-2 rounded-lg font-medium transition-colors cursor-pointer text-center ${
                  activeTab === 'register' ? 'bg-blue-600 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Register
              </button>
              <button
                type="button"
                onClick={() => { setActiveTab('clerk'); setErrorMessage(null); }}
                className={`py-1.5 px-2 rounded-lg font-medium transition-colors cursor-pointer text-center ${
                  activeTab === 'clerk' ? 'bg-slate-700 text-white' : 'text-slate-400 hover:text-slate-200'
                }`}
                title="Configure Clerk"
              >
                <Key className="w-3.5 h-3.5 inline" />
              </button>
            </div>

            {errorMessage && (
              <div className="p-3 rounded-xl bg-red-950/60 border border-red-800/70 text-xs text-red-200 flex items-start gap-2">
                <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                <span>{errorMessage}</span>
              </div>
            )}

            {/* TAB 1: Quick Analyst Access */}
            {activeTab === 'quick' && (
              <div className="space-y-3 pt-1">
                <p className="text-xs text-slate-300 leading-relaxed">
                  Select a pre-configured role to immediately access and persist saved scans to your SQLite database:
                </p>

                <div className="grid grid-cols-1 gap-2.5">
                  <button
                    type="button"
                    onClick={() => handleQuickLogin('analyst')}
                    disabled={isSubmitting}
                    className="p-3.5 rounded-xl bg-slate-900/90 hover:bg-slate-800/90 border border-blue-900/40 hover:border-blue-500/60 transition-all text-left flex items-center justify-between group cursor-pointer"
                  >
                    <div className="flex items-center gap-3">
                      <div className="w-9 h-9 rounded-lg bg-blue-950/80 border border-blue-800/60 flex items-center justify-center text-blue-400 group-hover:scale-105 transition-transform">
                        <UserCheck className="w-4 h-4" />
                      </div>
                      <div>
                        <div className="text-xs font-semibold text-slate-100 flex items-center gap-1.5">
                          <span>Security Analyst</span>
                          <span className="px-1.5 py-0.2 bg-blue-500/20 text-blue-400 text-[10px] font-mono rounded">Default</span>
                        </div>
                        <div className="text-[11px] text-slate-400 font-mono">analyst@cybersec.org</div>
                      </div>
                    </div>
                    <span className="text-xs text-blue-400 group-hover:translate-x-0.5 transition-transform">Enter →</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => handleQuickLogin('admin')}
                    disabled={isSubmitting}
                    className="p-3.5 rounded-xl bg-slate-900/90 hover:bg-slate-800/90 border border-slate-800 hover:border-indigo-500/60 transition-all text-left flex items-center justify-between group cursor-pointer"
                  >
                    <div className="flex items-center gap-3">
                      <div className="w-9 h-9 rounded-lg bg-indigo-950/80 border border-indigo-800/60 flex items-center justify-center text-indigo-400 group-hover:scale-105 transition-transform">
                        <Shield className="w-4 h-4" />
                      </div>
                      <div>
                        <div className="text-xs font-semibold text-slate-100 flex items-center gap-1.5">
                          <span>SecOps Administrator</span>
                          <span className="px-1.5 py-0.2 bg-indigo-500/20 text-indigo-400 text-[10px] font-mono rounded">Admin</span>
                        </div>
                        <div className="text-[11px] text-slate-400 font-mono">admin@phishguard.ai</div>
                      </div>
                    </div>
                    <span className="text-xs text-indigo-400 group-hover:translate-x-0.5 transition-transform">Enter →</span>
                  </button>
                </div>
              </div>
            )}

            {/* TAB 2: Standard Sign In */}
            {activeTab === 'credentials' && (
              <form onSubmit={handleCredentialsSubmit} className="space-y-3 pt-1">
                <div>
                  <label className="block text-[11px] font-mono text-slate-300 mb-1.5">Username or Email</label>
                  <input
                    type="text"
                    value={usernameInput}
                    onChange={(e) => setUsernameInput(e.target.value)}
                    placeholder="e.g. analyst or user@org.com"
                    required
                    className="w-full px-3.5 py-2.5 rounded-xl bg-[#060a14] border border-slate-700/80 text-slate-100 text-xs focus:outline-none focus:border-blue-500 placeholder:text-slate-600 transition-colors"
                  />
                </div>

                <div>
                  <label className="block text-[11px] font-mono text-slate-300 mb-1.5">Password</label>
                  <input
                    type="password"
                    value={passwordInput}
                    onChange={(e) => setPasswordInput(e.target.value)}
                    placeholder="••••••••"
                    className="w-full px-3.5 py-2.5 rounded-xl bg-[#060a14] border border-slate-700/80 text-slate-100 text-xs focus:outline-none focus:border-blue-500 placeholder:text-slate-600 transition-colors"
                  />
                </div>

                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="w-full py-2.5 bg-blue-600 hover:bg-blue-500 text-white font-semibold rounded-xl text-xs flex items-center justify-center gap-2 shadow-md transition-colors cursor-pointer"
                >
                  <LogIn className="w-3.5 h-3.5" />
                  <span>{isSubmitting ? 'Authenticating...' : 'Sign In to Database'}</span>
                </button>
              </form>
            )}

            {/* TAB 3: Register Analyst Account */}
            {activeTab === 'register' && (
              <form onSubmit={handleRegisterSubmit} className="space-y-3 pt-1">
                <div className="grid grid-cols-2 gap-2.5">
                  <div>
                    <label className="block text-[11px] font-mono text-slate-300 mb-1">First Name</label>
                    <input
                      type="text"
                      value={firstNameInput}
                      onChange={(e) => setFirstNameInput(e.target.value)}
                      placeholder="Alex"
                      className="w-full px-3 py-2 rounded-xl bg-[#060a14] border border-slate-700/80 text-slate-100 text-xs focus:outline-none focus:border-blue-500"
                    />
                  </div>
                  <div>
                    <label className="block text-[11px] font-mono text-slate-300 mb-1">Last Name</label>
                    <input
                      type="text"
                      value={lastNameInput}
                      onChange={(e) => setLastNameInput(e.target.value)}
                      placeholder="Reed"
                      className="w-full px-3 py-2 rounded-xl bg-[#060a14] border border-slate-700/80 text-slate-100 text-xs focus:outline-none focus:border-blue-500"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-[11px] font-mono text-slate-300 mb-1">Username</label>
                  <input
                    type="text"
                    value={usernameInput}
                    onChange={(e) => setUsernameInput(e.target.value)}
                    placeholder="analyst_handle"
                    required
                    className="w-full px-3 py-2 rounded-xl bg-[#060a14] border border-slate-700/80 text-slate-100 text-xs focus:outline-none focus:border-blue-500 font-mono"
                  />
                </div>

                <div>
                  <label className="block text-[11px] font-mono text-slate-300 mb-1">Work Email</label>
                  <input
                    type="email"
                    value={emailInput}
                    onChange={(e) => setEmailInput(e.target.value)}
                    placeholder="analyst@domain.com"
                    required
                    className="w-full px-3 py-2 rounded-xl bg-[#060a14] border border-slate-700/80 text-slate-100 text-xs focus:outline-none focus:border-blue-500"
                  />
                </div>

                <div>
                  <label className="block text-[11px] font-mono text-slate-300 mb-1">Password</label>
                  <input
                    type="password"
                    value={passwordInput}
                    onChange={(e) => setPasswordInput(e.target.value)}
                    placeholder="Create a password"
                    className="w-full px-3 py-2 rounded-xl bg-[#060a14] border border-slate-700/80 text-slate-100 text-xs focus:outline-none focus:border-blue-500"
                  />
                </div>

                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="w-full py-2.5 bg-blue-600 hover:bg-blue-500 text-white font-semibold rounded-xl text-xs flex items-center justify-center gap-2 shadow-md transition-colors cursor-pointer"
                >
                  <UserPlus className="w-3.5 h-3.5" />
                  <span>{isSubmitting ? 'Registering...' : 'Create Analyst Account'}</span>
                </button>
              </form>
            )}

            {/* TAB 4: Optional Clerk Configuration */}
            {activeTab === 'clerk' && (
              <form onSubmit={handleSaveKey} className="space-y-3 pt-1">
                <div className="p-3 rounded-xl bg-blue-950/30 border border-blue-900/50 text-xs text-slate-300 space-y-1.5">
                  <div className="flex items-center gap-2 text-blue-400 font-medium">
                    <ShieldCheck className="w-4 h-4" />
                    <span>Optional Clerk OAuth</span>
                  </div>
                  <p className="text-slate-400 leading-relaxed text-[11px]">
                    To connect an external Clerk cloud project for Social/Google OAuth, paste your Publishable Key:
                  </p>
                </div>

                <div>
                  <label className="block text-[11px] font-mono text-slate-300 mb-1.5">Clerk Publishable Key</label>
                  <input
                    type="text"
                    value={customKeyInput}
                    onChange={(e) => {
                      setCustomKeyInput(e.target.value);
                      setErrorMessage(null);
                    }}
                    placeholder="pk_test_... or pk_live_..."
                    className="w-full px-3.5 py-2.5 rounded-xl bg-[#060a14] border border-slate-700/80 text-slate-100 text-xs font-mono focus:outline-none focus:border-blue-500"
                  />
                </div>

                <button
                  type="submit"
                  className="w-full py-2.5 bg-slate-800 hover:bg-slate-700 text-white font-semibold rounded-xl text-xs transition-colors cursor-pointer"
                >
                  Save & Reload
                </button>
              </form>
            )}
          </div>
        )}

        {/* Modal Footer */}
        <div className="mt-5 pt-3 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-400">
          <span className="flex items-center gap-1.5 font-mono">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            <span>SQLite Database Active</span>
          </span>
          <button
            type="button"
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 cursor-pointer transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};

