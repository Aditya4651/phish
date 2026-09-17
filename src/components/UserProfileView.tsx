import React, { useState, useEffect, useRef } from 'react';
import {
  User as UserIcon,
  Lock,
  Key,
  ShieldCheck,
  Laptop,
  Globe,
  Trash2,
  Download,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
  Eye,
  EyeOff,
  LogOut,
  Edit2,
  Check,
  X,
  Mail,
  ShieldAlert,
  Fingerprint,
  Calendar,
  Save,
  Database,
  CheckCircle,
  Upload,
  Camera,
  Image as ImageIcon,
  Link as LinkIcon,
  HelpCircle,
  Sparkles
} from 'lucide-react';
import { User, UserSession } from '../types';
import { SpotlightCard } from './motion/SpotlightCard';
import { MagneticButton } from './motion/MagneticButton';
import { ScrambleText } from './motion/ScrambleText';
import { useAppAuth } from '../context/AuthContext';

interface UserProfileViewProps {
  user?: User;
  onUpdatePassword?: (oldPass: string, newPass: string) => Promise<boolean>;
  onRegenerateApiKey?: () => Promise<string>;
  onUpdateProfile?: (updatedUser: User) => void;
  onLogout?: () => void;
  onOpenLogin?: () => void;
}

export const UserProfileView: React.FC<UserProfileViewProps> = ({
  user: propUser,
  onUpdatePassword,
  onRegenerateApiKey,
  onUpdateProfile,
  onLogout,
  onOpenLogin,
}) => {
  const { 
    user: authUser, 
    dbUser, 
    isLoggedIn, 
    isClerkConfigured, 
    updateUserProfile: syncUpdateProfile, 
    openSignIn, 
    signOut,
    getAuthToken 
  } = useAppAuth();

  const effectiveUser = authUser?.isLoggedIn ? authUser : (propUser || authUser);
  const isAuthenticated = Boolean(effectiveUser?.isLoggedIn || isLoggedIn);

  // Profile Form States
  const [firstName, setFirstName] = useState(effectiveUser?.firstName || dbUser?.firstName || '');
  const [lastName, setLastName] = useState(effectiveUser?.lastName || dbUser?.lastName || '');
  const [username, setUsername] = useState(effectiveUser?.username || dbUser?.username || '');
  const [email, setEmail] = useState(effectiveUser?.email || dbUser?.email || '');
  const [dateOfBirth, setDateOfBirth] = useState(effectiveUser?.dateOfBirth || dbUser?.dateOfBirth || '');
  const [profileImageUrl, setProfileImageUrl] = useState(
    effectiveUser?.profileImage || dbUser?.profileImageUrl || 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?auto=format&fit=crop&q=80&w=250'
  );
  const [imageInputMode, setImageInputMode] = useState<'upload' | 'link'>('upload');
  const [imageLoadError, setImageLoadError] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const [isProcessingImage, setIsProcessingImage] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [isSaving, setIsSaving] = useState(false);
  const [profileMsg, setProfileMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Sync state whenever user or dbUser updates
  useEffect(() => {
    if (effectiveUser) {
      setFirstName(effectiveUser.firstName || dbUser?.firstName || '');
      setLastName(effectiveUser.lastName || dbUser?.lastName || '');
      setUsername(effectiveUser.username || dbUser?.username || '');
      setEmail(effectiveUser.email || dbUser?.email || '');
      setDateOfBirth(effectiveUser.dateOfBirth || dbUser?.dateOfBirth || '');
      if (effectiveUser.profileImage || dbUser?.profileImageUrl) {
        setProfileImageUrl(effectiveUser.profileImage || dbUser?.profileImageUrl || '');
        setImageLoadError(false);
      }
    }
  }, [effectiveUser, dbUser]);

  // Reset image error whenever URL or source changes
  useEffect(() => {
    setImageLoadError(false);
  }, [profileImageUrl]);

  // Handle client-side image compression & conversion to data URL
  const processImageFile = (file: File): Promise<string> => {
    return new Promise((resolve, reject) => {
      if (!file.type.startsWith('image/')) {
        return reject(new Error('Please upload a valid image file (PNG, JPG, WEBP, or GIF).'));
      }
      if (file.size > 10 * 1024 * 1024) {
        return reject(new Error('Image file is too large (maximum size is 10MB).'));
      }

      const reader = new FileReader();
      reader.onload = (e) => {
        const rawResult = e.target?.result as string;
        const img = new Image();
        img.onload = () => {
          try {
            const canvas = document.createElement('canvas');
            const MAX_DIM = 400; // Optimal avatar size: ultra-fast sync & crisp display
            let { width, height } = img;

            if (width > height) {
              if (width > MAX_DIM) {
                height = Math.round((height * MAX_DIM) / width);
                width = MAX_DIM;
              }
            } else {
              if (height > MAX_DIM) {
                width = Math.round((width * MAX_DIM) / height);
                height = MAX_DIM;
              }
            }

            canvas.width = width;
            canvas.height = height;
            const ctx = canvas.getContext('2d');
            if (ctx) {
              ctx.drawImage(img, 0, 0, width, height);
              const compressedDataUrl = canvas.toDataURL('image/jpeg', 0.88);
              resolve(compressedDataUrl);
            } else {
              resolve(rawResult);
            }
          } catch (canvasErr) {
            resolve(rawResult);
          }
        };
        img.onerror = () => resolve(rawResult);
        img.src = rawResult;
      };
      reader.onerror = () => reject(new Error('Failed to read selected image file.'));
      reader.readAsDataURL(file);
    });
  };

  const handleFileChosen = async (file: File) => {
    try {
      setIsProcessingImage(true);
      setProfileMsg(null);
      const dataUrl = await processImageFile(file);
      setProfileImageUrl(dataUrl);
      setImageLoadError(false);
      setProfileMsg({
        type: 'success',
        text: `Photo "${file.name}" loaded successfully. Click "Save Profile Settings" below to persist changes.`,
      });
    } catch (err: any) {
      setProfileMsg({
        type: 'error',
        text: err?.message || 'Failed to process selected image file.',
      });
    } finally {
      setIsProcessingImage(false);
    }
  };

  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      handleFileChosen(file);
    }
    // reset input so the same file can be selected again if needed
    if (e.target) {
      e.target.value = '';
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) {
      handleFileChosen(file);
    }
  };

  const handleRemovePhoto = () => {
    setProfileImageUrl('');
    setImageLoadError(false);
    setProfileMsg({
      type: 'success',
      text: 'Photo cleared. Click "Save Profile Settings" to confirm.',
    });
  };

  // Protected Route Guard for Unauthenticated Users
  if (!isAuthenticated) {
    return (
      <div className="max-w-xl mx-auto my-16 bg-slate-900/90 p-8 sm:p-10 rounded-2xl border border-slate-800 text-center space-y-5 shadow-2xl">
        <div className="w-14 h-14 rounded-xl bg-slate-800 border border-slate-700 text-blue-400 flex items-center justify-center mx-auto shadow-inner">
          <Lock className="w-7 h-7" />
        </div>
        <div className="space-y-2">
          <h2 className="text-xl sm:text-2xl font-bold text-slate-100 tracking-tight">
            Protected Settings & Profile
          </h2>
          <p className="text-xs sm:text-sm text-slate-400 leading-relaxed max-w-md mx-auto">
            Account preferences, security parameters, and profile details are private to your session. Please authenticate via Clerk to manage your account.
          </p>
        </div>

        <div className="pt-2 flex flex-col sm:flex-row items-center justify-center gap-3">
          <MagneticButton
            onClick={openSignIn || onOpenLogin}
            className="w-full sm:w-auto px-6 py-2.5 bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs rounded-xl shadow-lg transition-colors cursor-pointer flex items-center justify-center gap-2"
          >
            <Lock className="w-3.5 h-3.5" />
            <span>Sign In to Access Settings</span>
          </MagneticButton>
        </div>

        <div className="pt-4 border-t border-slate-800/80 flex items-center justify-center gap-2 text-[11px] font-mono text-slate-400">
          <Database className="w-3 h-3 text-emerald-400" />
          <span>Clerk & Relational DB Synchronization Guard</span>
        </div>
      </div>
    );
  }

  const handleSaveProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    setProfileMsg(null);
    setIsSaving(true);

    try {
      const res = await syncUpdateProfile({
        firstName: firstName.trim(),
        lastName: lastName.trim(),
        username: username.trim().toLowerCase(),
        dateOfBirth: dateOfBirth || undefined,
        profileImageUrl: profileImageUrl.trim(),
      });

      if (!res.success) {
        throw new Error(res.error || 'Failed to persist profile modifications.');
      }

      setProfileMsg({
        type: 'success',
        text: 'Profile details and avatar successfully persisted to database and synchronized.',
      });
    } catch (err: any) {
      console.error('Save profile error:', err);
      setProfileMsg({
        type: 'error',
        text: err?.message || 'Failed to persist profile modifications.',
      });
    } finally {
      setIsSaving(false);
    }
  };

  const handleSignOutClick = () => {
    if (signOut) {
      signOut();
    } else if (onLogout) {
      onLogout();
    }
  };

  const creationDateFormatted = effectiveUser?.createdAt
    ? new Date(effectiveUser.createdAt).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
      })
    : 'Active Session';

  return (
    <div className="space-y-8 max-w-5xl mx-auto">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[11px] font-mono uppercase tracking-wider text-blue-400">
              User Identity & Security Configuration
            </span>
            <span className="text-slate-600">•</span>
            <span className="text-[11px] font-mono text-emerald-400 flex items-center gap-1">
              <CheckCircle className="w-3 h-3" />
              <span>Clerk Authenticated</span>
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold text-slate-100 tracking-tight flex items-center gap-2.5">
            <UserIcon className="w-6 h-6 text-blue-400" />
            <span>Account Settings & Profile</span>
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1">
            Manage your personal profile, synchronized biometric identifiers, and relational database records.
          </p>
        </div>

        <button
          onClick={handleSignOutClick}
          className="px-4 py-2 bg-rose-950/40 hover:bg-rose-900/60 text-rose-300 border border-rose-800/60 rounded-xl text-xs font-semibold flex items-center gap-2 transition-colors self-start sm:self-center cursor-pointer shadow-sm"
        >
          <LogOut className="w-4 h-4" />
          <span>Sign Out</span>
        </button>
      </div>

      {/* Sync Status Banner */}
      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-emerald-950/60 border border-emerald-800/60 text-emerald-400">
            <Database className="w-4 h-4" />
          </div>
          <div>
            <div className="font-semibold text-slate-200">
              Single Source of Truth: Clerk & Relational SQLite
            </div>
            <div className="text-slate-400 text-[11px] font-mono">
              External Identity: {dbUser?.clerkUserId || effectiveUser?.id || 'clerk_authenticated_user'}
            </div>
          </div>
        </div>

        <div className="px-2.5 py-1 rounded-md bg-slate-800 border border-slate-700 font-mono text-[11px] text-slate-300">
          DB ID: #{dbUser?.id || '1'}
        </div>
      </div>

      {/* Profile Feedback Alert */}
      {profileMsg && (
        <div
          className={`p-4 rounded-xl border flex items-center gap-3 text-xs ${
            profileMsg.type === 'success'
              ? 'bg-emerald-950/40 border-emerald-800/60 text-emerald-200'
              : 'bg-rose-950/40 border-rose-800/60 text-rose-200'
          }`}
        >
          {profileMsg.type === 'success' ? (
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          ) : (
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
          )}
          <span>{profileMsg.text}</span>
        </div>
      )}

      {/* Editable Settings Form */}
      <SpotlightCard className="p-6 sm:p-8">
        <form onSubmit={handleSaveProfile} className="space-y-6">
          <div className="border-b border-slate-800 pb-4">
            <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
              <UserIcon className="w-4.5 h-4.5 text-blue-400" />
              <span>Personal Information</span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Editable user profile fields stored permanently in the application database and synced with Clerk.
            </p>
          </div>

          {/* Profile Picture & Avatar Section */}
          <div className="p-5 rounded-xl bg-slate-900/50 border border-slate-800 space-y-4">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
              <div>
                <label className="text-xs font-mono font-medium text-slate-200 flex items-center gap-2">
                  <Camera className="w-4 h-4 text-blue-400" />
                  <span>Analyst Profile Picture</span>
                </label>
                <p className="text-[11px] text-slate-400">
                  Upload an image from your device or specify a verified image link.
                </p>
              </div>

              {/* Mode Toggle Pills */}
              <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800 self-stretch sm:self-auto">
                <button
                  type="button"
                  onClick={() => setImageInputMode('upload')}
                  className={`flex-1 sm:flex-none px-3 py-1 text-xs font-medium rounded-md transition-colors flex items-center justify-center gap-1.5 cursor-pointer ${
                    imageInputMode === 'upload'
                      ? 'bg-blue-600 text-white shadow-sm'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Upload className="w-3.5 h-3.5" />
                  <span>Upload File</span>
                </button>

                <button
                  type="button"
                  onClick={() => setImageInputMode('link')}
                  className={`flex-1 sm:flex-none px-3 py-1 text-xs font-medium rounded-md transition-colors flex items-center justify-center gap-1.5 cursor-pointer ${
                    imageInputMode === 'link'
                      ? 'bg-blue-600 text-white shadow-sm'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <LinkIcon className="w-3.5 h-3.5" />
                  <span>Image URL</span>
                </button>
              </div>
            </div>

            <div className="flex flex-col md:flex-row items-start md:items-center gap-6 pt-1">
              {/* Avatar Preview & Drop Target */}
              <div
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onDrop={handleDrop}
                onClick={() => fileInputRef.current?.click()}
                title="Click or drop an image file to upload"
                className={`relative group cursor-pointer w-24 h-24 sm:w-28 sm:h-28 rounded-2xl shrink-0 overflow-hidden border-2 transition-all flex items-center justify-center bg-slate-800/90 ${
                  isDragging
                    ? 'border-blue-400 ring-4 ring-blue-500/20 scale-105'
                    : 'border-slate-700 hover:border-blue-500/70 shadow-lg'
                }`}
              >
                {isProcessingImage ? (
                  <div className="flex flex-col items-center justify-center gap-1.5 text-blue-400 p-2 text-center">
                    <RefreshCw className="w-6 h-6 animate-spin" />
                    <span className="text-[10px] font-mono">Optimizing...</span>
                  </div>
                ) : profileImageUrl && !imageLoadError ? (
                  <>
                    <img
                      src={profileImageUrl}
                      alt="Profile Avatar"
                      className="w-full h-full object-cover"
                      referrerPolicy="no-referrer"
                      crossOrigin="anonymous"
                      onError={() => setImageLoadError(true)}
                    />
                    <div className="absolute inset-0 bg-black/60 opacity-0 group-hover:opacity-100 transition-opacity flex flex-col items-center justify-center text-white gap-1 p-1 text-center">
                      <Camera className="w-5 h-5" />
                      <span className="text-[10px] font-medium leading-none">Change Photo</span>
                    </div>
                  </>
                ) : (
                  <div className="flex flex-col items-center justify-center text-slate-400 group-hover:text-blue-400 transition-colors p-2 text-center">
                    {username ? (
                      <span className="text-2xl font-bold font-mono text-slate-200">
                        {username.charAt(0).toUpperCase()}
                      </span>
                    ) : (
                      <UserIcon className="w-8 h-8" />
                    )}
                    <span className="text-[9px] font-mono mt-1 text-slate-400 group-hover:text-slate-200">
                      {isDragging ? 'Drop File' : 'Click to Upload'}
                    </span>
                  </div>
                )}

                {/* Upload Status Badge */}
                {profileImageUrl && !imageLoadError && (
                  <div className="absolute top-1.5 right-1.5 bg-emerald-500 text-white rounded-full p-0.5 shadow">
                    <Check className="w-2.5 h-2.5" />
                  </div>
                )}
              </div>

              {/* Hidden File Input */}
              <input
                ref={fileInputRef}
                type="file"
                accept="image/png,image/jpeg,image/webp,image/gif"
                onChange={handleFileInputChange}
                className="hidden"
              />

              {/* Controls Column */}
              <div className="flex-1 w-full space-y-3">
                {imageInputMode === 'upload' ? (
                  <div className="space-y-3">
                    <div
                      onDragOver={handleDragOver}
                      onDragLeave={handleDragLeave}
                      onDrop={handleDrop}
                      onClick={() => fileInputRef.current?.click()}
                      className={`p-4 rounded-xl border border-dashed text-center cursor-pointer transition-all ${
                        isDragging
                          ? 'border-blue-400 bg-blue-950/20'
                          : 'border-slate-700 hover:border-slate-600 bg-slate-950/40 hover:bg-slate-950/60'
                      }`}
                    >
                      <div className="flex flex-col items-center justify-center gap-1.5">
                        <div className="w-8 h-8 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400 flex items-center justify-center">
                          <Upload className="w-4 h-4" />
                        </div>
                        <div className="text-xs text-slate-200 font-medium">
                          <span className="text-blue-400 hover:underline">Click to browse</span> or drag and drop your photo
                        </div>
                        <p className="text-[10px] text-slate-400 font-mono">
                          PNG, JPG, WEBP, or GIF • Automatically optimized & saved to database
                        </p>
                      </div>
                    </div>

                    <div className="flex flex-wrap items-center gap-2 pt-1">
                      <button
                        type="button"
                        onClick={() => fileInputRef.current?.click()}
                        className="px-3 py-1.5 bg-blue-600/90 hover:bg-blue-600 text-white font-medium text-xs rounded-lg transition-colors flex items-center gap-1.5 cursor-pointer shadow-sm"
                      >
                        <Upload className="w-3.5 h-3.5" />
                        <span>Select File from Device</span>
                      </button>

                      {profileImageUrl && (
                        <button
                          type="button"
                          onClick={handleRemovePhoto}
                          className="px-3 py-1.5 bg-slate-800 hover:bg-rose-950/40 text-slate-300 hover:text-rose-300 border border-slate-700 hover:border-rose-800/60 font-medium text-xs rounded-lg transition-colors flex items-center gap-1.5 cursor-pointer"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                          <span>Clear Photo</span>
                        </button>
                      )}
                    </div>
                  </div>
                ) : (
                  <div className="space-y-2">
                    <div className="space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-mono font-medium text-slate-300">
                          External Image URL
                        </span>
                        {profileImageUrl && (
                          <span className={`text-[10px] font-mono px-2 py-0.5 rounded ${
                            imageLoadError 
                              ? 'bg-rose-950/60 border border-rose-800/60 text-rose-300'
                              : 'bg-emerald-950/60 border border-emerald-800/60 text-emerald-300'
                          }`}>
                            {imageLoadError ? 'Failed to Load Link' : 'URL Valid'}
                          </span>
                        )}
                      </div>
                      <div className="relative">
                        <LinkIcon className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                        <input
                          type="url"
                          value={profileImageUrl}
                          onChange={(e) => {
                            setProfileImageUrl(e.target.value);
                            setImageLoadError(false);
                          }}
                          placeholder="https://example.com/avatar.jpg"
                          className="w-full bg-[#080c14] text-xs text-slate-200 pl-9 pr-3.5 py-2.5 rounded-lg border border-slate-700 outline-none focus:border-blue-500 font-mono"
                        />
                      </div>
                    </div>

                    {imageLoadError && profileImageUrl && (
                      <div className="p-3 rounded-lg bg-rose-950/30 border border-rose-800/60 text-rose-200 text-xs flex items-start gap-2.5">
                        <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                        <div className="space-y-1">
                          <p className="font-semibold text-rose-300">
                            Image could not be displayed from this link
                          </p>
                          <p className="text-[11px] text-rose-300/80 leading-relaxed">
                            The host website may block external embedding (hotlink protection), or the URL is not a direct image file. Switch to the <strong>Upload File</strong> tab to directly upload the picture from your computer.
                          </p>
                        </div>
                      </div>
                    )}

                    <p className="text-[11px] text-slate-400 flex items-center gap-1.5">
                      <HelpCircle className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                      <span>Direct link to a public image (JPG, PNG, WEBP). Must allow cross-origin embedding.</span>
                    </p>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Core Fields Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-5">
            {/* First Name */}
            <div className="space-y-1.5">
              <label className="text-xs font-mono font-medium text-slate-300">
                First Name
              </label>
              <input
                type="text"
                value={firstName}
                onChange={(e) => setFirstName(e.target.value)}
                placeholder="e.g. Elena"
                className="w-full bg-[#080c14] text-xs text-slate-200 px-3.5 py-2.5 rounded-lg border border-slate-700 outline-none focus:border-blue-500 font-sans"
              />
            </div>

            {/* Last Name */}
            <div className="space-y-1.5">
              <label className="text-xs font-mono font-medium text-slate-300">
                Last Name
              </label>
              <input
                type="text"
                value={lastName}
                onChange={(e) => setLastName(e.target.value)}
                placeholder="e.g. Vance"
                className="w-full bg-[#080c14] text-xs text-slate-200 px-3.5 py-2.5 rounded-lg border border-slate-700 outline-none focus:border-blue-500 font-sans"
              />
            </div>

            {/* Username */}
            <div className="space-y-1.5">
              <label className="text-xs font-mono font-medium text-slate-300 flex items-center justify-between">
                <span>Username</span>
                <span className="text-[10px] text-blue-400">Unique Handle</span>
              </label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="analyst_code"
                required
                className="w-full bg-[#080c14] text-xs text-slate-200 px-3.5 py-2.5 rounded-lg border border-slate-700 outline-none focus:border-blue-500 font-mono"
              />
            </div>

            {/* Email (Managed & Verified) */}
            <div className="space-y-1.5">
              <label className="text-xs font-mono font-medium text-slate-300 flex items-center justify-between">
                <span>Email Address</span>
                <span className="text-[10px] text-emerald-400 font-mono">Clerk Verified</span>
              </label>
              <div className="relative">
                <input
                  type="email"
                  value={email}
                  disabled
                  readOnly
                  className="w-full bg-[#080c14]/80 text-xs text-slate-400 px-3.5 py-2.5 rounded-lg border border-slate-800 outline-none font-mono cursor-not-allowed"
                />
                <Mail className="w-4 h-4 text-slate-400 absolute right-3 top-1/2 -translate-y-1/2" />
              </div>
              <p className="text-[10px] text-slate-400">
                Email address is managed securely via Clerk identity authentication.
              </p>
            </div>

            {/* Date of Birth */}
            <div className="space-y-1.5">
              <label className="text-xs font-mono font-medium text-slate-300 flex items-center gap-1.5">
                <Calendar className="w-3.5 h-3.5 text-blue-400" />
                <span>Date of Birth</span>
              </label>
              <input
                type="date"
                value={dateOfBirth}
                onChange={(e) => setDateOfBirth(e.target.value)}
                className="w-full bg-[#080c14] text-xs text-slate-200 px-3.5 py-2.5 rounded-lg border border-slate-700 outline-none focus:border-blue-500 font-mono"
              />
              <p className="text-[10px] text-slate-400">
                Stored securely in database for compliance and age verification.
              </p>
            </div>

            {/* Account Creation Date (Read-only metadata) */}
            <div className="space-y-1.5">
              <label className="text-xs font-mono font-medium text-slate-300">
                Account Creation Date
              </label>
              <div className="w-full bg-[#080c14]/80 text-xs text-slate-400 px-3.5 py-2.5 rounded-lg border border-slate-800 font-mono flex items-center justify-between">
                <span>{creationDateFormatted}</span>
                <span className="text-[10px] text-emerald-400 uppercase font-semibold">Active</span>
              </div>
              <p className="text-[10px] text-slate-400">
                Date record initialized in the relational intelligence database.
              </p>
            </div>
          </div>

          {/* Form Action */}
          <div className="pt-4 border-t border-slate-800 flex items-center justify-end gap-3">
            <MagneticButton
              type="submit"
              disabled={isSaving}
              className="px-6 py-2.5 bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs rounded-xl shadow-md transition-colors cursor-pointer flex items-center gap-2"
            >
              {isSaving ? (
                <RefreshCw className="w-4 h-4 animate-spin" />
              ) : (
                <Save className="w-4 h-4" />
              )}
              <span>{isSaving ? 'Persisting Changes...' : 'Save Settings'}</span>
            </MagneticButton>
          </div>
        </form>
      </SpotlightCard>

      {/* Security & Access Tokens */}
      <SpotlightCard className="p-6 sm:p-8">
        <div className="space-y-4">
          <div className="border-b border-slate-800 pb-4 flex items-center justify-between">
            <div>
              <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
                <Key className="w-4.5 h-4.5 text-blue-400" />
                <span>Security Credentials & API Tokens</span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Authentication tokens for automated RESTful scan queries and CI/CD pipelines.
              </p>
            </div>

            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-950 text-emerald-300 border border-emerald-800">
              Active Key
            </span>
          </div>

          <div className="space-y-2">
            <label className="text-xs font-mono text-slate-300">
              REST API Authentication Key
            </label>
            <div className="flex items-center gap-3">
              <input
                type="password"
                value={effectiveUser?.apiKey || 'pk_live_sec_8f93a0219c83a7a92b3c'}
                readOnly
                className="flex-1 bg-[#080c14] text-xs font-mono text-slate-300 px-3.5 py-2.5 rounded-lg border border-slate-700 outline-none"
              />
              <button
                type="button"
                onClick={async () => {
                  if (onRegenerateApiKey) {
                    await onRegenerateApiKey();
                    setProfileMsg({ type: 'success', text: 'API token regenerated.' });
                  }
                }}
                className="px-4 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono rounded-lg border border-slate-700 transition-colors cursor-pointer"
              >
                Regenerate
              </button>
            </div>
            <p className="text-[11px] text-slate-400">
              Include in HTTP headers as <code className="text-blue-400 font-mono">X-API-Key: pk_live_...</code> for programmatic URL classification.
            </p>
          </div>
        </div>
      </SpotlightCard>
    </div>
  );
};
