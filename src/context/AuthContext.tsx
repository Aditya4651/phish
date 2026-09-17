import React, { createContext, useContext, useState, useEffect, ReactNode, useCallback } from 'react';
import { ClerkProvider, useUser, useAuth, useClerk } from '@clerk/clerk-react';
import { User, UserDashboardStats } from '../types';

const RAW_CLERK_KEY = 
  (typeof window !== 'undefined' && localStorage.getItem('phishguard_clerk_pub_key')) ||
  import.meta.env.VITE_CLERK_PUBLISHABLE_KEY || 
  import.meta.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY || 
  '';

export function isLiveClerkKey(key?: string | null): boolean {
  if (!key || typeof key !== 'string') return false;
  const trimmed = key.trim();
  if (!trimmed.startsWith('pk_test_') && !trimmed.startsWith('pk_live_')) return false;
  // Check for the known dead/deleted dummy test key that returns 404 from Clerk
  if (trimmed === 'pk_test_aW50ZW50LWhlcm1pdC0yNzUyLmNsZXJrLmFjY291bnRzLmRldiQ') return false;
  try {
    const raw = trimmed.replace(/^pk_(test|live)_/, '');
    const decoded = atob(raw.replace(/\$/g, ''));
    if (decoded.includes('intent-hermit-2752')) return false;
  } catch {
    if (trimmed.includes('aW50ZW50LWhlcm1pdC0yNzUy')) return false;
  }
  return true;
}

export type ClerkKeyStatus = 'live' | 'invalid_dummy' | 'missing';

export function getClerkKeyStatus(key?: string | null): ClerkKeyStatus {
  if (!key || !key.trim()) return 'missing';
  if (isLiveClerkKey(key)) return 'live';
  return 'invalid_dummy';
}

export interface AuthContextType {
  user: User;
  dbUser?: User;
  isLoggedIn: boolean;
  isLoaded: boolean;
  isClerkConfigured: boolean;
  clerkKeyStatus: ClerkKeyStatus;
  userStats: UserDashboardStats | null;
  getAuthToken: () => Promise<string | null>;
  refreshUserProfile: () => Promise<void>;
  updateUserProfile: (data: {
    firstName?: string;
    lastName?: string;
    username?: string;
    dateOfBirth?: string;
    profileImageUrl?: string;
  }) => Promise<{ success: boolean; error?: string }>;
  loginWithCredentials: (username: string, password: string) => Promise<{ success: boolean; error?: string }>;
  loginWithGoogle: (email?: string, name?: string) => Promise<{ success: boolean; error?: string }>;
  registerAccount: (data: {
    username: string;
    email: string;
    password: string;
    firstName?: string;
    lastName?: string;
  }) => Promise<{ success: boolean; error?: string }>;
  saveCustomClerkKey: (key: string) => void;
  isAuthModalOpen: boolean;
  openSignIn: () => void;
  openSignUp: () => void;
  closeAuthModal: () => void;
  signOut: () => Promise<void>;
}

const defaultGuestUser: User = {
  id: 'usr-guest',
  username: 'Guest Analyst',
  email: 'guest@cybersec.org',
  role: 'Guest',
  isLoggedIn: false,
  accountStatus: 'Active',
  verificationStatus: false,
  createdAt: new Date().toISOString().split('T')[0],
  lastActive: new Date().toISOString(),
};

const AuthContext = createContext<AuthContextType>({
  user: defaultGuestUser,
  dbUser: defaultGuestUser,
  isLoggedIn: false,
  isLoaded: true,
  isClerkConfigured: false,
  clerkKeyStatus: 'missing',
  userStats: null,
  getAuthToken: async () => null,
  refreshUserProfile: async () => {},
  updateUserProfile: async () => ({ success: false, error: 'Not configured' }),
  loginWithCredentials: async () => ({ success: false, error: 'Not configured' }),
  loginWithGoogle: async () => ({ success: false, error: 'Not configured' }),
  registerAccount: async () => ({ success: false, error: 'Not configured' }),
  saveCustomClerkKey: () => {},
  isAuthModalOpen: false,
  openSignIn: () => {},
  openSignUp: () => {},
  closeAuthModal: () => {},
  signOut: async () => {},
});

export const useAppAuth = () => useContext(AuthContext);

/**
 * Direct Authentication Bridge (Active when Clerk is not configured or for direct analyst login)
 */
const DirectAuthBridge: React.FC<{
  children: ReactNode;
  clerkKeyStatus: ClerkKeyStatus;
  isModalOpen: boolean;
  setIsModalOpen: (open: boolean) => void;
}> = ({ children, clerkKeyStatus, isModalOpen, setIsModalOpen }) => {
  const [user, setUser] = useState<User>(defaultGuestUser);
  const [dbUser, setDbUser] = useState<User>(defaultGuestUser);
  const [userStats, setUserStats] = useState<UserDashboardStats | null>(null);
  const [isLoaded, setIsLoaded] = useState(false);

  // Helper to fetch session token from localStorage
  const getAuthToken = useCallback(async (): Promise<string | null> => {
    return localStorage.getItem('phishguard_auth_token');
  }, []);

  // Sync current user profile from server
  const syncWithDatabase = useCallback(async () => {
    const token = localStorage.getItem('phishguard_auth_token');
    if (!token) {
      setUser(defaultGuestUser);
      setDbUser(defaultGuestUser);
      setUserStats(null);
      setIsLoaded(true);
      return;
    }

    try {
      const res = await fetch('/api/auth/me', {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (res.ok) {
        const data = await res.json();
        const serverUser = data.user;
        const stats = data.stats;

        const effectiveEmail = (serverUser.email || '').toLowerCase();
        const isAdmin = 
          (serverUser.role || '').toLowerCase() === 'admin' ||
          serverUser.username === 'admin';

        const unifiedUser: User = {
          id: String(serverUser.id),
          username: serverUser.username || 'Analyst',
          firstName: serverUser.first_name || '',
          lastName: serverUser.last_name || '',
          email: serverUser.email || '',
          dateOfBirth: serverUser.date_of_birth || '',
          profileImage: serverUser.profile_image_url || (isAdmin ? 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?auto=format&fit=crop&q=80&w=250' : undefined),
          role: isAdmin ? 'Admin' : 'Free User',
          isLoggedIn: true,
          accountStatus: 'Active',
          verificationStatus: true,
          createdAt: serverUser.created_at ? serverUser.created_at.split('T')[0] : new Date().toISOString().split('T')[0],
          lastLogin: serverUser.last_active_at || new Date().toISOString(),
          lastActive: serverUser.last_active_at || new Date().toISOString(),
        };

        setUser(unifiedUser);
        setDbUser(unifiedUser);

        if (stats) {
          setUserStats(stats);
        }
      } else {
        localStorage.removeItem('phishguard_auth_token');
        setUser(defaultGuestUser);
        setDbUser(defaultGuestUser);
      }
    } catch (err) {
      console.warn('[Direct Auth Sync] Error syncing user:', err);
    } finally {
      setIsLoaded(true);
    }
  }, []);

  useEffect(() => {
    syncWithDatabase();
  }, [syncWithDatabase]);

  const loginWithCredentials = async (username: string, password: string): Promise<{ success: boolean; error?: string }> => {
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });

      const data = await res.json();
      if (!res.ok) {
        return { success: false, error: data.error || 'Authentication failed' };
      }

      localStorage.setItem('phishguard_auth_token', data.token);
      await syncWithDatabase();
      setIsModalOpen(false);
      return { success: true };
    } catch (err: any) {
      return { success: false, error: err.message || 'Network error during login.' };
    }
  };

  const loginWithGoogle = async (email?: string, name?: string): Promise<{ success: boolean; error?: string }> => {
    try {
      const res = await fetch('/api/auth/google/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: email || 'analyst@phishguard.security',
          name: name || 'Security Analyst',
          googleId: 'g-analyst-sso',
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        return { success: false, error: data.error || 'Google login failed' };
      }

      localStorage.setItem('phishguard_auth_token', data.token);
      await syncWithDatabase();
      setIsModalOpen(false);
      return { success: true };
    } catch (err: any) {
      return { success: false, error: err.message || 'Network error during Google login.' };
    }
  };

  const registerAccount = async (payload: {
    username: string;
    email: string;
    password: string;
    firstName?: string;
    lastName?: string;
  }): Promise<{ success: boolean; error?: string }> => {
    try {
      const res = await fetch('/api/auth/direct-register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      const data = await res.json();
      if (!res.ok) {
        return { success: false, error: data.error || 'Registration failed' };
      }

      localStorage.setItem('phishguard_auth_token', data.token);
      await syncWithDatabase();
      setIsModalOpen(false);
      return { success: true };
    } catch (err: any) {
      return { success: false, error: err.message || 'Network error during registration.' };
    }
  };

  const updateUserProfile = async (updates: {
    firstName?: string;
    lastName?: string;
    username?: string;
    dateOfBirth?: string;
    profileImageUrl?: string;
  }): Promise<{ success: boolean; error?: string }> => {
    const token = localStorage.getItem('phishguard_auth_token');
    if (!token) return { success: false, error: 'User is not authenticated.' };

    try {
      const response = await fetch('/api/user/profile', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(updates),
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        return { success: false, error: errData.error || 'Failed to update profile.' };
      }

      await syncWithDatabase();
      return { success: true };
    } catch (err: any) {
      return { success: false, error: err?.message || 'Network error updating profile.' };
    }
  };

  const handleSignOut = async () => {
    localStorage.removeItem('phishguard_auth_token');
    setUser(defaultGuestUser);
    setDbUser(defaultGuestUser);
    setUserStats(null);
  };

  const saveCustomClerkKey = (newKey: string) => {
    const trimmed = newKey.trim();
    if (trimmed) {
      localStorage.setItem('phishguard_clerk_pub_key', trimmed);
    } else {
      localStorage.removeItem('phishguard_clerk_pub_key');
    }
    window.location.reload();
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        dbUser,
        isLoggedIn: user.isLoggedIn,
        isLoaded,
        isClerkConfigured: false,
        clerkKeyStatus,
        userStats,
        getAuthToken,
        refreshUserProfile: syncWithDatabase,
        updateUserProfile,
        loginWithCredentials,
        loginWithGoogle,
        registerAccount,
        saveCustomClerkKey,
        isAuthModalOpen: isModalOpen,
        openSignIn: () => setIsModalOpen(true),
        openSignUp: () => setIsModalOpen(true),
        closeAuthModal: () => setIsModalOpen(false),
        signOut: handleSignOut,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

/**
 * Clerk Authentication Bridge (Active when a verified live Clerk key is provided)
 */
const ClerkAuthBridge: React.FC<{
  children: ReactNode;
  clerkKeyStatus: ClerkKeyStatus;
  isModalOpen: boolean;
  setIsModalOpen: (open: boolean) => void;
}> = ({ children, clerkKeyStatus, isModalOpen, setIsModalOpen }) => {
  const { user: clerkUser, isLoaded: isClerkUserLoaded, isSignedIn } = useUser();
  const { getToken, signOut: clerkSignOut } = useAuth();
  const clerk = useClerk();

  const [dbUser, setDbUser] = useState<User>(defaultGuestUser);
  const [userStats, setUserStats] = useState<UserDashboardStats | null>(null);
  const [isSyncing, setIsSyncing] = useState(false);

  const getAuthToken = useCallback(async (): Promise<string | null> => {
    try {
      if (isSignedIn) {
        return await getToken();
      }
      return localStorage.getItem('phishguard_auth_token');
    } catch (err) {
      console.warn('[Clerk] Error fetching token:', err);
      return localStorage.getItem('phishguard_auth_token');
    }
  }, [isSignedIn, getToken]);

  const syncWithDatabase = useCallback(async () => {
    const token = await getAuthToken();
    if (!token) {
      setDbUser(defaultGuestUser);
      setUserStats(null);
      return;
    }

    try {
      setIsSyncing(true);
      const res = await fetch('/api/auth/me', {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (res.ok) {
        const data = await res.json();
        const serverUser = data.user;
        const stats = data.stats;

        const effectiveEmail = (serverUser.email || clerkUser?.primaryEmailAddress?.emailAddress || '').toLowerCase();
        const isAdmin = 
          (serverUser.role || '').toLowerCase() === 'admin' ||
          serverUser.username === 'admin' ||
          clerkUser?.username === 'admin';

        setDbUser({
          id: String(serverUser.id),
          clerkUserId: serverUser.clerk_user_id,
          username: serverUser.username || clerkUser?.username || 'Analyst',
          firstName: serverUser.first_name || clerkUser?.firstName || '',
          lastName: serverUser.last_name || clerkUser?.lastName || '',
          email: serverUser.email || clerkUser?.primaryEmailAddress?.emailAddress || '',
          dateOfBirth: serverUser.date_of_birth || '',
          profileImage: serverUser.profile_image_url || clerkUser?.imageUrl,
          role: isAdmin ? 'Admin' : 'Free User',
          isLoggedIn: true,
          accountStatus: 'Active',
          verificationStatus: true,
          createdAt: serverUser.created_at ? serverUser.created_at.split('T')[0] : new Date().toISOString().split('T')[0],
          lastLogin: serverUser.last_active_at || new Date().toISOString(),
          lastActive: serverUser.last_active_at || new Date().toISOString(),
        });

        if (stats) {
          setUserStats(stats);
        }
      }
    } catch (err) {
      console.warn('[Auth Sync] Error syncing user with database:', err);
    } finally {
      setIsSyncing(false);
    }
  }, [getAuthToken, clerkUser]);

  useEffect(() => {
    if (isClerkUserLoaded) {
      syncWithDatabase();
    }
  }, [isClerkUserLoaded, isSignedIn, clerkUser?.id, syncWithDatabase]);

  const loginWithCredentials = async (username: string, password: string): Promise<{ success: boolean; error?: string }> => {
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });

      const data = await res.json();
      if (!res.ok) {
        return { success: false, error: data.error || 'Authentication failed' };
      }

      localStorage.setItem('phishguard_auth_token', data.token);
      await syncWithDatabase();
      setIsModalOpen(false);
      return { success: true };
    } catch (err: any) {
      return { success: false, error: err.message || 'Network error during login.' };
    }
  };

  const loginWithGoogle = async (email?: string, name?: string): Promise<{ success: boolean; error?: string }> => {
    try {
      const res = await fetch('/api/auth/google/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: email || 'analyst@phishguard.security',
          name: name || 'Security Analyst',
          googleId: 'g-analyst-sso',
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        return { success: false, error: data.error || 'Google login failed' };
      }

      localStorage.setItem('phishguard_auth_token', data.token);
      await syncWithDatabase();
      setIsModalOpen(false);
      return { success: true };
    } catch (err: any) {
      return { success: false, error: err.message || 'Network error during Google login.' };
    }
  };

  const registerAccount = async (payload: {
    username: string;
    email: string;
    password: string;
    firstName?: string;
    lastName?: string;
  }): Promise<{ success: boolean; error?: string }> => {
    try {
      const res = await fetch('/api/auth/direct-register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      const data = await res.json();
      if (!res.ok) {
        return { success: false, error: data.error || 'Registration failed' };
      }

      localStorage.setItem('phishguard_auth_token', data.token);
      await syncWithDatabase();
      setIsModalOpen(false);
      return { success: true };
    } catch (err: any) {
      return { success: false, error: err.message || 'Network error during registration.' };
    }
  };

  const updateUserProfile = async (updates: {
    firstName?: string;
    lastName?: string;
    username?: string;
    dateOfBirth?: string;
    profileImageUrl?: string;
  }): Promise<{ success: boolean; error?: string }> => {
    const token = await getAuthToken();
    if (!token) {
      return { success: false, error: 'User is not authenticated.' };
    }

    try {
      if (clerkUser && (updates.firstName !== undefined || updates.lastName !== undefined || updates.username !== undefined)) {
        try {
          await clerkUser.update({
            firstName: updates.firstName !== undefined ? updates.firstName : clerkUser.firstName,
            lastName: updates.lastName !== undefined ? updates.lastName : clerkUser.lastName,
            username: updates.username !== undefined ? updates.username : clerkUser.username,
          });
        } catch (clerkErr: any) {
          console.warn('[Clerk] Notice during Clerk user update:', clerkErr?.errors?.[0]?.message || clerkErr);
        }
      }

      const response = await fetch('/api/user/profile', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(updates),
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        return { success: false, error: errData.error || 'Failed to update profile.' };
      }

      await syncWithDatabase();
      return { success: true };
    } catch (err: any) {
      return { success: false, error: err?.message || 'Network error updating profile.' };
    }
  };

  const handleSignOut = async () => {
    localStorage.removeItem('phishguard_auth_token');
    try {
      if (isSignedIn) {
        await clerkSignOut();
      }
    } catch (err) {
      console.warn('Signout warning:', err);
    }
    setDbUser(defaultGuestUser);
    setUserStats(null);
  };

  const saveCustomClerkKey = (newKey: string) => {
    const trimmed = newKey.trim();
    if (trimmed) {
      localStorage.setItem('phishguard_clerk_pub_key', trimmed);
    } else {
      localStorage.removeItem('phishguard_clerk_pub_key');
    }
    window.location.reload();
  };

  const isUserAuthenticated = Boolean(isSignedIn || dbUser.isLoggedIn);

  return (
    <AuthContext.Provider
      value={{
        user: dbUser,
        dbUser,
        isLoggedIn: isUserAuthenticated,
        isLoaded: isClerkUserLoaded && !isSyncing,
        isClerkConfigured: true,
        clerkKeyStatus,
        userStats,
        getAuthToken,
        refreshUserProfile: syncWithDatabase,
        updateUserProfile,
        loginWithCredentials,
        loginWithGoogle,
        registerAccount,
        saveCustomClerkKey,
        isAuthModalOpen: isModalOpen,
        openSignIn: () => {
          setIsModalOpen(true);
          try {
            clerk.openSignIn({});
          } catch {
            // Virtual routing fallback
          }
        },
        openSignUp: () => {
          setIsModalOpen(true);
          try {
            clerk.openSignUp({});
          } catch {
            // Virtual routing fallback
          }
        },
        closeAuthModal: () => setIsModalOpen(false),
        signOut: handleSignOut,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

/**
 * Top-Level Application Authentication Provider
 * Intelligently validates Clerk configuration. If a live, valid Clerk key is detected,
 * mounts ClerkProvider. If missing or invalid/dummy (404), seamlessly falls back to
 * DirectAuthBridge without console noise or connection errors.
 */
export const AppAuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [isModalOpen, setIsModalOpen] = useState(false);
  const activeClerkKey = 
    (typeof window !== 'undefined' && localStorage.getItem('phishguard_clerk_pub_key')) ||
    RAW_CLERK_KEY;

  const clerkKeyStatus = getClerkKeyStatus(activeClerkKey);

  if (clerkKeyStatus !== 'live') {
    return (
      <DirectAuthBridge 
        clerkKeyStatus={clerkKeyStatus} 
        isModalOpen={isModalOpen}
        setIsModalOpen={setIsModalOpen}
      >
        {children}
      </DirectAuthBridge>
    );
  }

  return (
    <ClerkProvider
      publishableKey={activeClerkKey}
      appearance={{
        layout: {
          socialButtonsPlacement: 'top',
          logoPlacement: 'inside',
        },
        variables: {
          colorPrimary: '#3b82f6',
          colorBackground: '#0a0f1d',
          colorInputBackground: '#070a14',
          colorInputText: '#f8fafc',
          colorText: '#f1f5f9',
          colorTextSecondary: '#94a3b8',
          borderRadius: '0.65rem',
        },
        elements: {
          card: 'border border-slate-800 shadow-2xl bg-[#090d18]',
          headerTitle: 'text-slate-100 font-semibold',
          headerSubtitle: 'text-slate-400 text-xs',
          formButtonPrimary: 'bg-blue-600 hover:bg-blue-500 text-white font-medium text-xs py-2.5',
          formFieldInput: 'bg-[#070a14] border border-slate-700 text-slate-100 focus:border-blue-500 text-xs',
          footerActionLink: 'text-blue-400 hover:text-blue-300',
        },
      }}
    >
      <ClerkAuthBridge 
        clerkKeyStatus={clerkKeyStatus}
        isModalOpen={isModalOpen}
        setIsModalOpen={setIsModalOpen}
      >
        {children}
      </ClerkAuthBridge>
    </ClerkProvider>
  );
};
