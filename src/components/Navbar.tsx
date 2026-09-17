import React from 'react';
import { motion } from 'motion/react';
import { 
  Shield, 
  Cpu, 
  BarChart2, 
  FileText, 
  Database, 
  ShieldAlert, 
  User as UserIcon, 
  LogOut, 
  Lock,
  Terminal
} from 'lucide-react';
import { User } from '../types';
import { MagneticButton } from './motion/MagneticButton';
import { BrandLogo } from './BrandLogo';

interface NavbarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  user: User;
  onOpenLogin: () => void;
  onLogout: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  user,
  onOpenLogin,
  onLogout
}) => {
  const [avatarError, setAvatarError] = React.useState(false);

  React.useEffect(() => {
    setAvatarError(false);
  }, [user.profileImage]);

  const navTabs = [
    { id: 'scanner', label: 'Inspector', icon: Cpu },
    { id: 'dashboard', label: 'Intelligence', icon: BarChart2 },
    { id: 'reports', label: 'Audit Dossiers', icon: FileText },
    { id: 'dataset', label: 'Corpus', icon: Database },
    { id: 'profile', label: 'Profile', icon: UserIcon },
  ];

  // Admin button is ONLY visible when an administrator is logged in
  const hasAdmin = Boolean(
    user.isLoggedIn && (
      (user.role || '').toLowerCase() === 'admin' ||
      user.username?.toLowerCase() === 'admin'
    )
  );

  return (
    <header className="sticky top-0 z-50 border-b border-slate-800/80 bg-[#090a0f]/90 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          
          {/* Brand / Logo */}
          <div id="brand-logo">
            <BrandLogo size="md" onClick={() => setActiveTab('scanner')} />
          </div>

          {/* Desktop Navigation Tabs with layoutId spring indicator */}
          <nav className="hidden lg:flex items-center gap-1 relative p-1 bg-slate-900/60 rounded-xl border border-slate-800/70">
            {navTabs.map((tab) => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  id={`nav-tab-${tab.id}`}
                  onClick={() => setActiveTab(tab.id)}
                  className={`relative z-10 flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
                    isActive ? 'text-slate-100 font-semibold' : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {isActive && (
                    <motion.div
                      layoutId="nav-active-pill"
                      transition={{ type: 'spring', stiffness: 350, damping: 30 }}
                      className="absolute inset-0 bg-slate-800/90 rounded-lg border border-slate-700/80 shadow-sm"
                    />
                  )}
                  <Icon className={`w-3.5 h-3.5 relative z-10 ${isActive ? 'text-blue-400' : 'text-slate-400'}`} />
                  <span className="relative z-10">{tab.label}</span>
                </button>
              );
            })}

            {hasAdmin && (
              <button
                id="nav-tab-admin"
                onClick={() => setActiveTab('admin')}
                className={`relative z-10 flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
                  activeTab === 'admin' ? 'text-indigo-200 font-semibold' : 'text-indigo-400/80 hover:text-indigo-300'
                }`}
              >
                {activeTab === 'admin' && (
                  <motion.div
                    layoutId="nav-active-pill"
                    transition={{ type: 'spring', stiffness: 350, damping: 30 }}
                    className="absolute inset-0 bg-indigo-950/60 rounded-lg border border-indigo-800/60"
                  />
                )}
                <ShieldAlert className="w-3.5 h-3.5 relative z-10 text-indigo-400" />
                <span className="relative z-10">Admin</span>
              </button>
            )}
          </nav>

          {/* Right Status & Auth Bar */}
          <div className="flex items-center gap-3">
            {/* Live System Telemetry Tag */}
            <div className="hidden xl:flex items-center gap-2 px-2.5 py-1 rounded-md bg-slate-900/50 border border-slate-800 text-[11px] font-mono text-slate-400">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-60"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
              </span>
              <span>CLASSIFIER ONLINE</span>
            </div>

            {user.isLoggedIn ? (
              <div className="flex items-center gap-2.5 pl-3 border-l border-slate-800">
                <div 
                  onClick={() => setActiveTab('profile')}
                  className="flex items-center gap-2 cursor-pointer p-1 rounded-lg hover:bg-slate-800/50 transition-colors"
                  title="View Security Profile"
                >
                  {user.profileImage && !avatarError ? (
                    <img
                      src={user.profileImage}
                      alt={user.username}
                      className="w-7 h-7 rounded-md object-cover border border-slate-700 bg-slate-800"
                      referrerPolicy="no-referrer"
                      onError={() => setAvatarError(true)}
                    />
                  ) : (
                    <div className="w-7 h-7 rounded-md bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-200 font-bold text-xs font-mono">
                      {user.username.charAt(0).toUpperCase()}
                    </div>
                  )}
                  <div className="hidden sm:block text-left">
                    <div className="text-xs font-medium text-slate-200 leading-tight truncate max-w-[110px]">
                      {user.username}
                    </div>
                    <div className="text-[10px] text-slate-400 font-mono leading-none">
                      {user.role}
                    </div>
                  </div>
                </div>

                <button
                  id="btn-logout"
                  onClick={onLogout}
                  title="Sign out of analyst portal"
                  className="p-1.5 text-slate-400 hover:text-rose-400 hover:bg-rose-950/30 rounded-lg transition-colors cursor-pointer"
                >
                  <LogOut className="w-4 h-4" />
                </button>
              </div>
            ) : (
              <div className="flex items-center gap-2">
                <MagneticButton
                  id="btn-clerk-signin"
                  onClick={onOpenLogin}
                  className="px-3.5 py-1.5 bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs rounded-lg transition-colors shadow-sm cursor-pointer gap-1.5 border border-blue-500/30 flex items-center"
                >
                  <Lock className="w-3.5 h-3.5" />
                  <span>Sign In</span>
                </MagneticButton>
              </div>
            )}
          </div>

        </div>
      </div>

      {/* Sub-bar for Mobile / Tablet Viewports */}
      <div className="lg:hidden flex items-center overflow-x-auto py-2 px-3 bg-[#0c101c] border-t border-slate-800/80 gap-1 text-xs">
        {navTabs.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-2.5 py-1 rounded-md whitespace-nowrap font-medium transition-colors ${
              activeTab === tab.id
                ? 'bg-slate-800 text-blue-400 border border-slate-700'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            {tab.label}
          </button>
        ))}
        {hasAdmin && (
          <button
            onClick={() => setActiveTab('admin')}
            className={`px-2.5 py-1 rounded-md whitespace-nowrap font-medium transition-colors ${
              activeTab === 'admin'
                ? 'bg-purple-950 text-purple-300 border border-purple-800'
                : 'text-purple-400 hover:text-purple-300'
            }`}
          >
            Admin
          </button>
        )}
      </div>
    </header>
  );
};
