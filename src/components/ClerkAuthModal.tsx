import React, { useState, useEffect } from 'react';
import { 
  X, 
  ShieldCheck, 
  ExternalLink, 
  AlertCircle,
  Loader2,
  Lock,
  User as UserIcon,
  KeyRound,
  Mail,
  ArrowRight
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
    loginWithCredentials,
    registerAccount,
    clerkKeyStatus,
    isLoggedIn 
  } = useAppAuth();

  const [authMode, setAuthMode] = useState<'signin' | 'signup'>(initialMode);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [activeProvider, setActiveProvider] = useState<'credentials' | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Normal login form state
  const [usernameOrEmail, setUsernameOrEmail] = useState('');
  const [password, setPassword] = useState('');
  const [regEmail, setRegEmail] = useState('');
  const [regUsername, setRegUsername] = useState('');
  const [regFirstName, setRegFirstName] = useState('');
  const [regLastName, setRegLastName] = useState('');

  useEffect(() => {
    setAuthMode(initialMode);
    setErrorMessage(null);
    setIsSubmitting(false);
    setActiveProvider(null);
  }, [initialMode, isOpen]);

  // Close modal when sign-in or registration succeeds
  useEffect(() => {
    if (isLoggedIn && isOpen) {
      onClose();
    }
  }, [isLoggedIn, isOpen, onClose]);

  if (!isOpen) return null;

  const isInIframe = typeof window !== 'undefined' && window.self !== window.top;

  const handleNormalSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);
    setIsSubmitting(true);
    setActiveProvider('credentials');

    try {
      if (authMode === 'signin') {
        if (!usernameOrEmail.trim()) {
          setErrorMessage('Please enter your username or email.');
          setIsSubmitting(false);
          setActiveProvider(null);
          return;
        }
        const res = await loginWithCredentials(usernameOrEmail.trim(), password);
        if (!res.success) {
          setErrorMessage(res.error || 'Invalid credentials.');
          setIsSubmitting(false);
          setActiveProvider(null);
        }
      } else {
        if (!regUsername.trim() || !regEmail.trim()) {
          setErrorMessage('Please fill in username and email.');
          setIsSubmitting(false);
          setActiveProvider(null);
          return;
        }
        const res = await registerAccount({
          username: regUsername.trim(),
          email: regEmail.trim(),
          password: password || 'analyst-pass',
          firstName: regFirstName.trim() || 'SecOps',
          lastName: regLastName.trim() || 'Analyst',
        });
        if (!res.success) {
          setErrorMessage(res.error || 'Failed to create account.');
          setIsSubmitting(false);
          setActiveProvider(null);
        }
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'Authentication error.');
      setIsSubmitting(false);
      setActiveProvider(null);
    }
  };

  return (
    <div 
      id="clerk-auth-modal-backdrop"
      className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 bg-black/85 backdrop-blur-md overflow-y-auto"
      onClick={onClose}
    >
      <div 
        id="clerk-auth-modal-card"
        className="relative w-full max-w-md bg-[#090d18] border border-slate-800/90 rounded-2xl shadow-2xl p-6 sm:p-8 overflow-hidden text-slate-100 my-8"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Ambient Top Glow */}
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-48 h-1 bg-gradient-to-r from-transparent via-blue-500 to-transparent" />

        {/* Close Button */}
        <button
          id="clerk-modal-close-btn"
          onClick={onClose}
          aria-label="Close authentication modal"
          className="absolute top-4 right-4 p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800/60 transition-colors"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Header Branding */}
        <div className="text-center mb-6">
          <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-blue-500/10 border border-blue-500/20 mb-3 text-blue-400 shadow-inner">
            <ShieldCheck className="w-6 h-6" />
          </div>
          <h2 className="text-xl font-bold tracking-tight text-white flex items-center justify-center gap-2">
            PhishGuard Access
          </h2>
          <p className="text-xs text-slate-400 mt-1.5 leading-relaxed max-w-xs mx-auto">
            {authMode === 'signin' 
              ? 'Sign in to access forensics dossiers, threat telemetry, and Cloud SQL persistence.'
              : 'Create your analyst account with OAuth or standard credentials.'}
          </p>
        </div>

        {/* Error Alert */}
        {errorMessage && (
          <div className="mb-5 p-3.5 bg-red-950/40 border border-red-800/60 rounded-xl flex items-start gap-2.5 text-xs text-red-200">
            <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
            <div className="flex-1 leading-snug">{errorMessage}</div>
          </div>
        )}

        {/* Signup Form if in signup mode */}
        {authMode === 'signup' && (
          <form onSubmit={handleNormalSubmit} className="space-y-3 mb-4">
            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="block text-[10px] font-mono uppercase text-slate-400 mb-1">
                  First Name
                </label>
                <input
                  id="normal-reg-firstname"
                  type="text"
                  value={regFirstName}
                  onChange={(e) => setRegFirstName(e.target.value)}
                  placeholder="SecOps"
                  className="w-full px-3 py-2 bg-slate-900/80 border border-slate-700/80 focus:border-blue-500 rounded-xl text-xs text-slate-100 placeholder-slate-500 outline-none transition-all font-mono"
                />
              </div>
              <div>
                <label className="block text-[10px] font-mono uppercase text-slate-400 mb-1">
                  Last Name
                </label>
                <input
                  id="normal-reg-lastname"
                  type="text"
                  value={regLastName}
                  onChange={(e) => setRegLastName(e.target.value)}
                  placeholder="Analyst"
                  className="w-full px-3 py-2 bg-slate-900/80 border border-slate-700/80 focus:border-blue-500 rounded-xl text-xs text-slate-100 placeholder-slate-500 outline-none transition-all font-mono"
                />
              </div>
            </div>
            <div>
              <label className="block text-[11px] font-mono uppercase text-slate-400 mb-1">
                Username
              </label>
              <div className="relative">
                <UserIcon className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                <input
                  id="normal-reg-username"
                  type="text"
                  required
                  value={regUsername}
                  onChange={(e) => setRegUsername(e.target.value)}
                  placeholder="analyst123"
                  className="w-full pl-9 pr-3 py-2.5 bg-slate-900/80 border border-slate-700/80 focus:border-blue-500 rounded-xl text-sm text-slate-100 placeholder-slate-500 outline-none transition-all font-mono"
                />
              </div>
            </div>
            <div>
              <label className="block text-[11px] font-mono uppercase text-slate-400 mb-1">
                Email
              </label>
              <div className="relative">
                <Mail className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                <input
                  id="normal-reg-email"
                  type="email"
                  required
                  value={regEmail}
                  onChange={(e) => setRegEmail(e.target.value)}
                  placeholder="analyst@domain.com"
                  className="w-full pl-9 pr-3 py-2.5 bg-slate-900/80 border border-slate-700/80 focus:border-blue-500 rounded-xl text-sm text-slate-100 placeholder-slate-500 outline-none transition-all font-mono"
                />
              </div>
            </div>
            <div>
              <label className="block text-[11px] font-mono uppercase text-slate-400 mb-1">
                Password
              </label>
              <div className="relative">
                <KeyRound className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                <input
                  id="normal-reg-password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Create a password"
                  className="w-full pl-9 pr-3 py-2.5 bg-slate-900/80 border border-slate-700/80 focus:border-blue-500 rounded-xl text-sm text-slate-100 placeholder-slate-500 outline-none transition-all font-mono"
                />
              </div>
            </div>

            <button
              id="normal-reg-submit-btn"
              type="submit"
              disabled={isSubmitting}
              className="w-full mt-2 py-2.5 px-4 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white font-medium text-sm rounded-xl shadow-md transition-all flex items-center justify-center gap-2 disabled:opacity-60"
            >
              {isSubmitting && activeProvider === 'credentials' ? (
                <Loader2 className="w-4 h-4 animate-spin text-white" />
              ) : (
                <>
                  <span>Create Account</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>
        )}

        {/* Embedded Native Clerk Component (Displays Clerk Social Buttons) */}
        {clerkKeyStatus === 'live' && (
          <div className="mt-5 pt-5 border-t border-slate-800/80">
            <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 mb-3 px-1">
              <span>Clerk Official Provider Widget:</span>
              <span className="text-emerald-400 flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                Live OAuth
              </span>
            </div>

            <div className="rounded-xl overflow-hidden clerk-container flex justify-center">
              {authMode === 'signin' ? (
                <SignIn 
                  routing="virtual"
                  appearance={{
                    layout: {
                      socialButtonsPlacement: 'top',
                      socialButtonsVariant: 'blockButton',
                    },
                    elements: {
                      dividerRow: 'hidden',
                      form: 'hidden',
                      formButtonPrimary: 'hidden',
                      footerAction: 'hidden',
                      header: 'hidden',
                      card: 'bg-transparent border-0 shadow-none p-0 w-full',
                      socialButtonsBlockButton: 'w-full bg-[#0c1220] hover:bg-[#11192b] border border-slate-700/80 hover:border-blue-500/60 text-slate-100 font-medium py-3 px-4 rounded-xl transition-all shadow-sm flex items-center justify-center gap-3 my-1',
                      socialButtonsBlockButtonText: 'text-sm font-semibold text-slate-100',
                    }
                  }}
                />
              ) : (
                <SignUp 
                  routing="virtual"
                  appearance={{
                    layout: {
                      socialButtonsPlacement: 'top',
                      socialButtonsVariant: 'blockButton',
                    },
                    elements: {
                      dividerRow: 'hidden',
                      form: 'hidden',
                      formButtonPrimary: 'hidden',
                      footerAction: 'hidden',
                      header: 'hidden',
                      card: 'bg-transparent border-0 shadow-none p-0 w-full',
                      socialButtonsBlockButton: 'w-full bg-[#0c1220] hover:bg-[#11192b] border border-slate-700/80 hover:border-blue-500/60 text-slate-100 font-medium py-3 px-4 rounded-xl transition-all shadow-sm flex items-center justify-center gap-3 my-1',
                      socialButtonsBlockButtonText: 'text-sm font-semibold text-slate-100',
                    }
                  }}
                />
              )}
            </div>
          </div>
        )}

        {/* Footer Security Notice & Iframe Notice */}
        <div className="mt-6 pt-4 border-t border-slate-800/80 text-center space-y-2">
          <div className="flex items-center justify-center gap-1.5 text-[11px] text-slate-400 font-mono">
            <Lock className="w-3 h-3 text-emerald-400" />
            <span>End-to-End Verified via Clerk & SQLite Persistence</span>
          </div>

          {isInIframe && (
            <div className="text-[11px] text-slate-400">
              Browser blocking third-party cookies in the preview frame?{' '}
              <a 
                href={typeof window !== 'undefined' ? window.location.href : '#'} 
                target="_blank" 
                rel="noopener noreferrer"
                className="text-blue-400 hover:text-blue-300 inline-flex items-center gap-1 underline underline-offset-2 ml-1"
              >
                Open in new tab <ExternalLink className="w-2.5 h-2.5 inline" />
              </a>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
