import React, { useState, useEffect } from 'react';
import { 
  X, 
  Lock, 
  CheckCircle2, 
  AlertTriangle,
  Sparkles,
  ArrowRight,
  Shield,
  Eye,
  EyeOff,
  Settings,
  ChevronDown,
  ChevronUp,
  Loader2,
  Check
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
    loginWithCredentials, 
    loginWithGoogle,
    registerAccount,
    saveCustomClerkKey 
  } = useAppAuth();

  // Mode: 'signin' | 'signup'
  const [authMode, setAuthMode] = useState<'signin' | 'signup'>(initialMode);
  const [showPassword, setShowPassword] = useState(false);
  const [showClerkSettings, setShowClerkSettings] = useState(false);

  // Form inputs
  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [email, setEmail] = useState('');
  const [username, setUsername] = useState('');
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  const [customKeyInput, setCustomKeyInput] = useState('');

  // Status indicators
  const [isLoading, setIsLoading] = useState(false);
  const [loadingAction, setLoadingAction] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  useEffect(() => {
    setAuthMode(initialMode);
    setErrorMessage(null);
    setSuccessMessage(null);
    setShowClerkSettings(false);
  }, [initialMode, isOpen]);

  if (!isOpen) return null;

  // 1. Google One-Tap / SSO Handler
  const handleGoogleAuth = async () => {
    setIsLoading(true);
    setLoadingAction('google');
    setErrorMessage(null);
    try {
      const result = await loginWithGoogle();
      if (result.success) {
        setSuccessMessage('Successfully authenticated with Google.');
        setTimeout(() => onClose(), 600);
      } else {
        setErrorMessage(result.error || 'Google authentication failed.');
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'Error signing in with Google.');
    } finally {
      setIsLoading(false);
      setLoadingAction(null);
    }
  };

  // 2. Username/Email & Password Login
  const handleCredentialsLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!identifier.trim() || !password) {
      setErrorMessage('Please enter your username/email and password.');
      return;
    }

    setIsLoading(true);
    setLoadingAction('credentials');
    setErrorMessage(null);
    try {
      const result = await loginWithCredentials(identifier.trim(), password);
      if (result.success) {
        setSuccessMessage('Authentication successful! Loading dashboard...');
        setTimeout(() => onClose(), 600);
      } else {
        setErrorMessage(result.error || 'Invalid username or password.');
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'Error during sign in.');
    } finally {
      setIsLoading(false);
      setLoadingAction(null);
    }
  };

  // 4. Registration Handler
  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !email.trim() || !password) {
      setErrorMessage('Username, email, and password are required.');
      return;
    }

    setIsLoading(true);
    setLoadingAction('register');
    setErrorMessage(null);
    try {
      const result = await registerAccount({
        username: username.trim(),
        email: email.trim(),
        password,
        firstName: firstName.trim(),
        lastName: lastName.trim(),
      });
      if (result.success) {
        setSuccessMessage('Account created successfully! Signed in.');
        setTimeout(() => onClose(), 600);
      } else {
        setErrorMessage(result.error || 'Registration failed.');
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'Error creating account.');
    } finally {
      setIsLoading(false);
      setLoadingAction(null);
    }
  };

  // 5. Custom Clerk Key (if developer wishes to hook an external Clerk instance)
  const handleSaveCustomKey = (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = customKeyInput.trim();
    if (!trimmed.startsWith('pk_test_') && !trimmed.startsWith('pk_live_')) {
      setErrorMessage('Key must start with pk_test_ or pk_live_');
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
              {authMode === 'signin' ? 'Sign in to PhishGuard' : 'Create Analyst Account'}
            </h2>
            <p className="text-xs text-slate-400">
              {authMode === 'signin' 
                ? 'Welcome back! Choose your preferred authentication method.'
                : 'Register a new security profile to save audits and reports.'}
            </p>
          </div>
        </div>

        {/* Feedback Alerts */}
        {errorMessage && (
          <div className="mb-4 p-3 rounded-xl bg-red-950/60 border border-red-800/70 text-xs text-red-200 flex items-start gap-2">
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
            <span className="flex-1">{errorMessage}</span>
          </div>
        )}
        {successMessage && (
          <div className="mb-4 p-3 rounded-xl bg-emerald-950/60 border border-emerald-800/70 text-xs text-emerald-200 flex items-start gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
            <span className="flex-1">{successMessage}</span>
          </div>
        )}

        {/* Live Clerk Provider View (Only active if genuine live key is present) */}
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
          /* High-Performance Direct & SSO Portal */
          <div className="space-y-4">
            {authMode === 'signin' ? (
              <>
                {/* 1. Continue with Google Button */}
                <button
                  type="button"
                  onClick={handleGoogleAuth}
                  disabled={isLoading}
                  className="w-full py-2.5 px-4 bg-slate-900 hover:bg-slate-800 border border-slate-700/80 hover:border-slate-600 text-white font-medium rounded-xl text-xs flex items-center justify-center gap-3 transition-all cursor-pointer shadow-sm disabled:opacity-50"
                >
                  {isLoading && loadingAction === 'google' ? (
                    <Loader2 className="w-4 h-4 animate-spin text-blue-400" />
                  ) : (
                    <>
                      <svg className="w-4 h-4 shrink-0" viewBox="0 0 24 24">
                        <path
                          fill="#4285F4"
                          d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                        />
                        <path
                          fill="#34A853"
                          d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                        />
                        <path
                          fill="#FBBC05"
                          d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
                        />
                        <path
                          fill="#EA4335"
                          d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
                        />
                      </svg>
                      <span>Continue with Google</span>
                    </>
                  )}
                </button>

                {/* Divider */}
                <div className="flex items-center gap-3 my-3">
                  <div className="flex-1 h-[1px] bg-slate-800" />
                  <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                    or sign in with credentials
                  </span>
                  <div className="flex-1 h-[1px] bg-slate-800" />
                </div>

                {/* Credentials Form */}
                <form onSubmit={handleCredentialsLogin} className="space-y-3.5">
                  <div>
                    <label className="block text-[11px] font-mono text-slate-300 mb-1">
                      Username or Email
                    </label>
                    <input
                      type="text"
                      value={identifier}
                      onChange={(e) => setIdentifier(e.target.value)}
                      placeholder="Enter your username or email"
                      className="w-full px-3.5 py-2.5 rounded-xl bg-[#060a14] border border-slate-700/80 text-slate-100 text-xs focus:outline-none focus:border-blue-500 placeholder:text-slate-600 transition-colors"
                      required
                    />
                  </div>

                  <div>
                    <div className="flex items-center justify-between mb-1">
                      <label className="text-[11px] font-mono text-slate-300">
                        Password
                      </label>
                      <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        className="text-[11px] text-slate-400 hover:text-slate-200 flex items-center gap-1 cursor-pointer"
                      >
                        {showPassword ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                        <span>{showPassword ? 'Hide' : 'Show'}</span>
                      </button>
                    </div>
                    <input
                      type={showPassword ? 'text' : 'password'}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="Enter your password"
                      className="w-full px-3.5 py-2.5 rounded-xl bg-[#060a14] border border-slate-700/80 text-slate-100 text-xs focus:outline-none focus:border-blue-500 placeholder:text-slate-600 transition-colors"
                      required
                    />
                  </div>

                  <button
                    type="submit"
                    disabled={isLoading}
                    className="w-full py-2.5 bg-blue-600 hover:bg-blue-500 text-white font-semibold rounded-xl text-xs flex items-center justify-center gap-2 shadow-md transition-colors cursor-pointer disabled:opacity-50"
                  >
                    {isLoading && loadingAction === 'credentials' ? (
                      <Loader2 className="w-4 h-4 animate-spin text-white" />
                    ) : (
                      <>
                        <Lock className="w-3.5 h-3.5" />
                        <span>Sign In</span>
                      </>
                    )}
                  </button>
                </form>

                {/* Switch to Sign Up */}
                <div className="text-center pt-2">
                  <button
                    type="button"
                    onClick={() => { setAuthMode('signup'); setErrorMessage(null); }}
                    className="text-xs text-slate-400 hover:text-white cursor-pointer transition-colors"
                  >
                    Don't have an account? <span className="text-blue-400 hover:underline">Sign up</span>
                  </button>
                </div>
              </>
            ) : (
              /* Sign Up / Registration View */
              <form onSubmit={handleRegister} className="space-y-3 pt-1">
                <div className="grid grid-cols-2 gap-2.5">
                  <div>
                    <label className="block text-[11px] font-mono text-slate-300 mb-1">
                      First Name
                    </label>
                    <input
                      type="text"
                      value={firstName}
                      onChange={(e) => setFirstName(e.target.value)}
                      placeholder="Alex"
                      className="w-full px-3 py-2 rounded-xl bg-[#060a14] border border-slate-700/80 text-slate-100 text-xs focus:outline-none focus:border-blue-500"
                    />
                  </div>
                  <div>
                    <label className="block text-[11px] font-mono text-slate-300 mb-1">
                      Last Name
                    </label>
                    <input
                      type="text"
                      value={lastName}
                      onChange={(e) => setLastName(e.target.value)}
                      placeholder="Mercer"
                      className="w-full px-3 py-2 rounded-xl bg-[#060a14] border border-slate-700/80 text-slate-100 text-xs focus:outline-none focus:border-blue-500"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-[11px] font-mono text-slate-300 mb-1">
                    Username
                  </label>
                  <input
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="analyst_alex"
                    className="w-full px-3 py-2 rounded-xl bg-[#060a14] border border-slate-700/80 text-slate-100 text-xs focus:outline-none focus:border-blue-500"
                    required
                  />
                </div>

                <div>
                  <label className="block text-[11px] font-mono text-slate-300 mb-1">
                    Email Address
                  </label>
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="alex@security-firm.com"
                    className="w-full px-3 py-2 rounded-xl bg-[#060a14] border border-slate-700/80 text-slate-100 text-xs focus:outline-none focus:border-blue-500"
                    required
                  />
                </div>

                <div>
                  <label className="block text-[11px] font-mono text-slate-300 mb-1">
                    Password
                  </label>
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••"
                    className="w-full px-3 py-2 rounded-xl bg-[#060a14] border border-slate-700/80 text-slate-100 text-xs focus:outline-none focus:border-blue-500"
                    required
                  />
                </div>

                <button
                  type="submit"
                  disabled={isLoading}
                  className="w-full py-2.5 bg-blue-600 hover:bg-blue-500 text-white font-semibold rounded-xl text-xs flex items-center justify-center gap-2 shadow-md transition-colors cursor-pointer disabled:opacity-50 mt-1"
                >
                  {isLoading && loadingAction === 'register' ? (
                    <Loader2 className="w-4 h-4 animate-spin text-white" />
                  ) : (
                    <>
                      <span>Create Account & Sign In</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </>
                  )}
                </button>

                {/* Switch to Sign In */}
                <div className="text-center pt-2">
                  <button
                    type="button"
                    onClick={() => { setAuthMode('signin'); setErrorMessage(null); }}
                    className="text-xs text-slate-400 hover:text-white cursor-pointer transition-colors"
                  >
                    Already have an account? <span className="text-blue-400 hover:underline">Sign in</span>
                  </button>
                </div>
              </form>
            )}

            {/* Optional Collapsible Clerk Configuration (for developers who have their own Clerk keys) */}
            <div className="pt-2 border-t border-slate-800/60">
              <button
                type="button"
                onClick={() => setShowClerkSettings(!showClerkSettings)}
                className="w-full flex items-center justify-between text-[11px] text-slate-400 hover:text-slate-300 cursor-pointer py-1"
              >
                <div className="flex items-center gap-1.5">
                  <Settings className="w-3 h-3 text-slate-400" />
                  <span>Custom Clerk Cloud Key (Optional)</span>
                </div>
                {showClerkSettings ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
              </button>

              {showClerkSettings && (
                <form onSubmit={handleSaveCustomKey} className="mt-2 space-y-2 p-2.5 rounded-xl bg-slate-900/60 border border-slate-800 text-xs">
                  <p className="text-[11px] text-slate-400">
                    If you have your own Clerk dashboard instance, paste your publishable key (<code className="text-cyan-300">pk_test_...</code>) below:
                  </p>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={customKeyInput}
                      onChange={(e) => setCustomKeyInput(e.target.value)}
                      placeholder="pk_test_..."
                      className="flex-1 px-2.5 py-1.5 rounded-lg bg-black/40 border border-slate-700 text-slate-200 text-xs font-mono focus:outline-none focus:border-blue-500"
                    />
                    <button
                      type="submit"
                      className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-white font-medium rounded-lg text-xs cursor-pointer"
                    >
                      Save
                    </button>
                  </div>
                </form>
              )}
            </div>
          </div>
        )}

        {/* Modal Footer */}
        <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-400">
          <span className="flex items-center gap-1.5 font-mono">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            <span>SQLite Database Active</span>
          </span>
          <button
            type="button"
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 cursor-pointer transition-colors"
          >
            Dismiss
          </button>
        </div>
      </div>
    </div>
  );
};
