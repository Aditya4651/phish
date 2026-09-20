import React, { createContext, useContext, useState, useEffect, ReactNode, useCallback, useMemo } from 'react';
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
  // Reject dummy placeholder key
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
  loginWithCredentials: async () => ({ success: false, error: 'Clerk authentication required.' }),
  loginWithGoogle: async () => ({ success: false, error: 'Clerk authentication required.' }),
  registerAccount: async () => ({ success: false, error: 'Clerk authentication required.' }),
  saveCustomClerkKey: () => {},
  isAuthModalOpen: false,
  openSignIn: () => {},
  openSignUp: () => {},
  closeAuthModal: () => {},
  signOut: async () => {},
});

export const useAppAuth = () => useContext(AuthContext);

/**
 * Direct Database Auth Bridge: Active for native relational SQLite multi-user authentication.
 * Manages verified sessions, persistent user credentials, tokens, and dashboard statistics.
 */
const DirectAuthBridge: React.FC<{
  children: ReactNode;
  clerkKeyStatus: ClerkKeyStatus;
  isModalOpen: boolean;
  setIsModalOpen: (open: boolean) => void;
}> = ({ children, clerkKeyStatus, isModalOpen, setIsModalOpen }) => {
  const [user, setUser] = useState<User>(() => {
    try {
      const savedUser = typeof window !== 'undefined' ? localStorage.getItem('phishguard_auth_user') : null;
      return savedUser ? JSON.parse(savedUser) : defaultGuestUser;
    } catch {
      return defaultGuestUser;
    }
  });
  const [authToken, setAuthToken] = useState<string | null>(() => {
    return typeof window !== 'undefined' ? (localStorage.getItem('phishguard_auth_token') || null) : null;
  });
  const [userStats, setUserStats] = useState<UserDashboardStats | null>(null);
  const [isLoaded, setIsLoaded] = useState(false);

  const isLoggedIn = Boolean(authToken && user.isLoggedIn);

  // Restore authenticated session on mount
  useEffect(() => {
    const restoreSession = async () => {
      const token = localStorage.getItem('phishguard_auth_token');
      if (token) {
        try {
          const res = await fetch('/api/auth/me', {
            headers: { Authorization: `Bearer ${token}` }
          });
          if (res.ok) {
            const data = await res.json();
            const syncedUser: User = {
              id: String(data.user.id),
              username: data.user.username || 'analyst',
              email: data.user.email || 'analyst@cybersec.org',
              role: (data.user.role === 'admin' ? 'Admin' : 'Analyst'),
              firstName: data.user.first_name || 'Security',
              lastName: data.user.last_name || 'Analyst',
              profileImage: data.user.profile_image_url || undefined,
              dateOfBirth: data.user.date_of_birth || undefined,
              isLoggedIn: true,
              accountStatus: 'Active',
              verificationStatus: true,
              createdAt: data.user.created_at || new Date().toISOString().split('T')[0],
              lastActive: data.user.last_active_at || new Date().toISOString(),
            };
            setUser(syncedUser);
            setAuthToken(token);
            setUserStats(data.stats);
            localStorage.setItem('phishguard_auth_user', JSON.stringify(syncedUser));
          } else {
            // Token expired or invalid
            localStorage.removeItem('phishguard_auth_token');
            localStorage.removeItem('phishguard_auth_user');
            setUser(defaultGuestUser);
            setAuthToken(null);
          }
        } catch (err) {
          console.warn('[DirectAuth] Error verifying session token:', err);
        }
      }
      setIsLoaded(true);
    };
    restoreSession();
  }, []);

  const getAuthToken = useCallback(async (): Promise<string | null> => {
    return typeof window !== 'undefined' ? (localStorage.getItem('phishguard_auth_token') || authToken) : authToken;
  }, [authToken]);

  const refreshUserProfile = useCallback(async () => {
    const token = localStorage.getItem('phishguard_auth_token') || authToken;
    if (!token) return;
    try {
      const res = await fetch('/api/auth/me', {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setUserStats(data.stats);
      }
    } catch (err) {
      console.warn('[DirectAuth] Error refreshing stats:', err);
    }
  }, [authToken]);

  const saveCustomClerkKey = (newKey: string) => {
    const trimmed = newKey.trim();
    if (trimmed) {
      localStorage.setItem('phishguard_clerk_pub_key', trimmed);
    } else {
      localStorage.removeItem('phishguard_clerk_pub_key');
    }
    window.location.reload();
  };

  const loginWithCredentials = async (
    username: string, 
    password?: string
  ): Promise<{ success: boolean; error?: string }> => {
    try {
      const cleanUsername = (username || 'analyst').trim();
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: cleanUsername, password: password || 'analyst' }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({ error: 'Authentication failed' }));
        return { success: false, error: errData.error || 'Failed to sign in' };
      }

      const data = await res.json();
      const authenticatedUser: User = {
        id: String(data.user.id),
        username: data.user.username || cleanUsername,
        email: data.user.email || `${cleanUsername}@cybersec.org`,
        role: (data.user.role === 'admin' ? 'Admin' : 'Analyst'),
        firstName: data.user.first_name || 'Security',
        lastName: data.user.last_name || 'Analyst',
        profileImage: data.user.profile_image_url || undefined,
        dateOfBirth: data.user.date_of_birth || undefined,
        isLoggedIn: true,
        accountStatus: 'Active',
        verificationStatus: true,
        createdAt: data.user.created_at || new Date().toISOString().split('T')[0],
        lastActive: data.user.last_active_at || new Date().toISOString(),
      };

      setUser(authenticatedUser);
      setAuthToken(data.token);
      setUserStats(data.stats || null);
      localStorage.setItem('phishguard_auth_token', data.token);
      localStorage.setItem('phishguard_auth_user', JSON.stringify(authenticatedUser));
      setIsModalOpen(false);

      return { success: true };
    } catch (err: any) {
      return { success: false, error: err.message || 'Network error connecting to auth service' };
    }
  };

  const loginWithGoogle = async (email?: string, name?: string): Promise<{ success: boolean; error?: string }> => {
    return loginWithCredentials(email ? email.split('@')[0] : 'google_analyst');
  };

  const registerAccount = async (data: {
    username: string;
    email: string;
    password: string;
    firstName?: string;
    lastName?: string;
  }): Promise<{ success: boolean; error?: string }> => {
    try {
      const res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({ error: 'Registration failed' }));
        return { success: false, error: errData.error || 'Failed to create account' };
      }

      const resData = await res.json();
      const registeredUser: User = {
        id: String(resData.user.id),
        username: resData.user.username,
        email: resData.user.email,
        role: (resData.user.role === 'admin' ? 'Admin' : 'Analyst'),
        firstName: resData.user.first_name || data.firstName || 'Analyst',
        lastName: resData.user.last_name || data.lastName || 'User',
        isLoggedIn: true,
        accountStatus: 'Active',
        verificationStatus: true,
        createdAt: resData.user.created_at,
        lastActive: resData.user.last_active_at,
      };

      setUser(registeredUser);
      setAuthToken(resData.token);
      setUserStats(resData.stats || null);
      localStorage.setItem('phishguard_auth_token', resData.token);
      localStorage.setItem('phishguard_auth_user', JSON.stringify(registeredUser));
      setIsModalOpen(false);

      return { success: true };
    } catch (err: any) {
      return { success: false, error: err.message || 'Network error registering account' };
    }
  };

  const updateUserProfile = async (updateData: {
    firstName?: string;
    lastName?: string;
    username?: string;
    dateOfBirth?: string;
    profileImageUrl?: string;
  }): Promise<{ success: boolean; error?: string }> => {
    const token = localStorage.getItem('phishguard_auth_token') || authToken;
    if (!token) return { success: false, error: 'Authentication required' };

    try {
      const res = await fetch('/api/user/profile', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(updateData),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: 'Update failed' }));
        return { success: false, error: err.error || 'Failed to update profile' };
      }

      const data = await res.json();
      const updatedUser: User = {
        ...user,
        firstName: data.user.first_name !== undefined ? data.user.first_name : user.firstName,
        lastName: data.user.last_name !== undefined ? data.user.last_name : user.lastName,
        username: data.user.username || user.username,
        dateOfBirth: data.user.date_of_birth || user.dateOfBirth,
        profileImage: data.user.profile_image_url || user.profileImage,
      };

      setUser(updatedUser);
      localStorage.setItem('phishguard_auth_user', JSON.stringify(updatedUser));
      return { success: true };
    } catch (err: any) {
      return { success: false, error: err.message || 'Error updating profile' };
    }
  };

  const signOut = async () => {
    localStorage.removeItem('phishguard_auth_token');
    localStorage.removeItem('phishguard_auth_user');
    setUser(defaultGuestUser);
    setAuthToken(null);
    setUserStats(null);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        dbUser: user,
        isLoggedIn,
        isLoaded,
        isClerkConfigured: false,
        clerkKeyStatus,
        userStats,
        getAuthToken,
        refreshUserProfile,
        updateUserProfile,
        loginWithCredentials,
        loginWithGoogle,
        registerAccount,
        saveCustomClerkKey,
        isAuthModalOpen: isModalOpen,
        openSignIn: () => setIsModalOpen(true),
        openSignUp: () => setIsModalOpen(true),
        closeAuthModal: () => setIsModalOpen(false),
        signOut,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

/**
 * Clerk Authenticated Bridge: Active when genuine live Clerk key is detected.
 * Uses official Clerk SDK session tokens for all requests and database sync.
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
      return null;
    } catch (err) {
      console.warn('[Clerk] Error fetching session token:', err);
      return null;
    }
  }, [isSignedIn, getToken]);

  const syncWithDatabase = useCallback(async () => {
    if (!isSignedIn) {
      setDbUser(defaultGuestUser);
      setUserStats(null);
      return;
    }

    const token = await getAuthToken();
    if (!token) {
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
      } else {
        console.warn('[Auth Sync] /api/auth/me returned status:', res.status);
      }
    } catch (err) {
      console.warn('[Auth Sync] Error syncing user with database:', err);
    } finally {
      setIsSyncing(false);
    }
  }, [getAuthToken, clerkUser, isSignedIn]);

  useEffect(() => {
    if (isClerkUserLoaded && isSignedIn) {
      syncWithDatabase();
    } else if (isClerkUserLoaded && !isSignedIn) {
      setDbUser(defaultGuestUser);
      setUserStats(null);
    }
  }, [isClerkUserLoaded, isSignedIn, clerkUser?.id, syncWithDatabase]);

  const loginWithCredentials = async (): Promise<{ success: boolean; error?: string }> => {
    setIsModalOpen(true);
    try {
      clerk.openSignIn({});
      return { success: true };
    } catch {
      return { success: false, error: 'Could not open Clerk Sign In dialog.' };
    }
  };

  const loginWithGoogle = async (): Promise<{ success: boolean; error?: string }> => {
    setIsModalOpen(true);
    try {
      clerk.openSignIn({});
      return { success: true };
    } catch {
      return { success: false, error: 'Could not open Clerk Google authentication.' };
    }
  };

  const registerAccount = async (): Promise<{ success: boolean; error?: string }> => {
    setIsModalOpen(true);
    try {
      clerk.openSignUp({});
      return { success: true };
    } catch {
      return { success: false, error: 'Could not open Clerk Sign Up dialog.' };
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

  // Derive effective user immediately from Clerk user + synced SQLite database user
  const effectiveUser: User = useMemo(() => {
    if (!isSignedIn) {
      return defaultGuestUser;
    }

    const primaryEmail = clerkUser?.primaryEmailAddress?.emailAddress || '';
    const fallbackUsername = clerkUser?.username || (primaryEmail ? primaryEmail.split('@')[0] : 'Analyst');
    const resolvedUsername = 
      dbUser.isLoggedIn && dbUser.username && dbUser.username !== 'Guest Analyst'
        ? dbUser.username
        : fallbackUsername;

    const isAdmin = 
      (dbUser.role || '').toLowerCase() === 'admin' ||
      resolvedUsername.toLowerCase() === 'admin' ||
      clerkUser?.username?.toLowerCase() === 'admin';

    return {
      id: dbUser.isLoggedIn ? dbUser.id : (clerkUser?.id || 'usr-temp'),
      clerkUserId: clerkUser?.id || dbUser.clerkUserId,
      username: resolvedUsername,
      firstName: dbUser.firstName || clerkUser?.firstName || '',
      lastName: dbUser.lastName || clerkUser?.lastName || '',
      email: dbUser.email || primaryEmail,
      dateOfBirth: dbUser.dateOfBirth || '',
      profileImage: dbUser.profileImage || clerkUser?.imageUrl,
      role: isAdmin ? 'Admin' : (dbUser.role && dbUser.role !== 'Guest' ? dbUser.role : 'Free User'),
      isLoggedIn: true,
      accountStatus: 'Active',
      verificationStatus: true,
      createdAt: dbUser.createdAt || (clerkUser?.createdAt ? new Date(clerkUser.createdAt).toISOString().split('T')[0] : new Date().toISOString().split('T')[0]),
      lastLogin: dbUser.lastActive || new Date().toISOString(),
      lastActive: dbUser.lastActive || new Date().toISOString(),
    };
  }, [isSignedIn, clerkUser, dbUser]);

  const isUserAuthenticated = Boolean(isSignedIn);

  return (
    <AuthContext.Provider
      value={{
        user: effectiveUser,
        dbUser: effectiveUser,
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
            // Fallback
          }
        },
        openSignUp: () => {
          setIsModalOpen(true);
          try {
            clerk.openSignUp({});
          } catch {
            // Fallback
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
 * Validates Clerk publishable key. Mounts ClerkProvider if valid, or DirectAuthBridge if setup needed.
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
