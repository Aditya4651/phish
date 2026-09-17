import React from 'react';

interface BrandLogoProps {
  size?: 'sm' | 'md' | 'lg' | 'xl';
  showText?: boolean;
  className?: string;
  onClick?: () => void;
}

export const BrandLogo: React.FC<BrandLogoProps> = ({
  size = 'md',
  showText = true,
  className = '',
  onClick,
}) => {
  const iconDimensions = {
    sm: 'w-7 h-7',
    md: 'w-9 h-9',
    lg: 'w-12 h-12',
    xl: 'w-16 h-16',
  }[size];

  const titleSizes = {
    sm: 'text-sm',
    md: 'text-base',
    lg: 'text-xl',
    xl: 'text-2xl',
  }[size];

  const subSizes = {
    sm: 'text-[10px]',
    md: 'text-[11px]',
    lg: 'text-xs',
    xl: 'text-sm',
  }[size];

  return (
    <div
      onClick={onClick}
      className={`flex items-center gap-2.5 sm:gap-3 select-none ${onClick ? 'cursor-pointer group' : ''} ${className}`}
    >
      {/* Emblem Badge Container */}
      <div className={`relative ${iconDimensions} rounded-xl bg-slate-900/90 border border-slate-700/60 p-1 flex items-center justify-center shadow-lg shadow-blue-950/40 group-hover:border-blue-500/60 group-hover:shadow-blue-500/25 transition-all duration-300 shrink-0`}>
        <img
          src="/logo-emblem.png"
          alt="PhishGuard.ai Logo"
          className="w-full h-full object-contain filter drop-shadow-[0_2px_8px_rgba(0,140,255,0.45)] group-hover:scale-105 transition-transform"
          referrerPolicy="no-referrer"
          onError={(e) => {
            // Fallback to local asset if root public path varies
            (e.currentTarget as HTMLImageElement).src = '/logo.png';
          }}
        />
      </div>

      {showText && (
        <div className="flex flex-col">
          <div className="flex items-center gap-2">
            <span className={`font-bold ${titleSizes} text-slate-100 tracking-tight flex items-center leading-none`}>
              PHISH
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-sky-400 to-blue-500 font-extrabold ml-0.5">
                GUARD
              </span>
              <span className="text-slate-400 font-normal ml-0.5 opacity-90">.ai</span>
            </span>
            <span className="hidden sm:inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono font-medium bg-blue-950/70 text-cyan-300 border border-blue-800/70">
              ML-v2.4
            </span>
          </div>
          <span className={`${subSizes} text-slate-400 font-mono tracking-wide hidden sm:block mt-1 leading-none`}>
            URL Threat Extraction Engine
          </span>
        </div>
      )}
    </div>
  );
};
