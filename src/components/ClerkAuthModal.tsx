import React, { useState, useEffect } from 'react';
import { 
  X, 
  Key,
  ExternalLink,
  ShieldCheck,
  AlertCircle
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
    isLoggedIn 
  } = useAppAuth();

  const [authMode, setAuthMode] = useState<'signin' | 'signup'>(initialMode);
  const [customKeyInput, setCustomKeyInput] = useState('');
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
                : 'Clerk Authentication Setup'}
            </h2>
            <p className="text-xs text-slate-400">
              {clerkKeyStatus === 'live'
                ? 'Secured with Clerk authentication & SQLite database persistence.'
                : 'Configure Clerk to enable verified multi-user authentication.'}
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
          /* Clerk Key Setup View */
          <div className="space-y-4">
            <div className="p-4 rounded-xl bg-blue-950/30 border border-blue-900/50 text-xs text-slate-300 space-y-2">
              <div className="flex items-center gap-2 text-blue-400 font-medium">
                <ShieldCheck className="w-4 h-4" />
                <span>Clerk Session Security</span>
              </div>
              <p className="text-slate-400 leading-relaxed">
                PhishGuard strictly uses Clerk for user authentication, password management, session verification, and Google OAuth.
              </p>
              <p className="text-slate-400 leading-relaxed">
                To sign in and sync scans with your profile, provide your Clerk Publishable Key below or declare <code className="text-cyan-300 font-mono">VITE_CLERK_PUBLISHABLE_KEY</code> in <code className="text-cyan-300 font-mono">.env</code>.
              </p>
            </div>

            {errorMessage && (
              <div className="p-3 rounded-xl bg-red-950/60 border border-red-800/70 text-xs text-red-200 flex items-start gap-2">
                <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                <span>{errorMessage}</span>
              </div>
            )}

            <form onSubmit={handleSaveKey} className="space-y-3">
              <div>
                <label className="block text-[11px] font-mono text-slate-300 mb-1.5">
                  Clerk Publishable Key
                </label>
                <div className="relative">
                  <Key className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
                  <input
                    type="text"
                    value={customKeyInput}
                    onChange={(e) => {
                      setCustomKeyInput(e.target.value);
                      setErrorMessage(null);
                    }}
                    placeholder="pk_test_... or pk_live_..."
                    className="w-full pl-9 pr-3.5 py-2.5 rounded-xl bg-[#060a14] border border-slate-700/80 text-slate-100 text-xs font-mono focus:outline-none focus:border-blue-500 placeholder:text-slate-600 transition-colors"
                    required
                  />
                </div>
              </div>

              <button
                type="submit"
                className="w-full py-2.5 bg-blue-600 hover:bg-blue-500 text-white font-semibold rounded-xl text-xs flex items-center justify-center gap-2 shadow-md transition-colors cursor-pointer"
              >
                <span>Activate Clerk Authentication</span>
              </button>
            </form>

            <div className="pt-2 text-center">
              <a
                href="https://dashboard.clerk.com"
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1.5 text-xs text-blue-400 hover:text-blue-300 transition-colors"
              >
                <span>Open Clerk Dashboard</span>
                <ExternalLink className="w-3.5 h-3.5" />
              </a>
            </div>
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
