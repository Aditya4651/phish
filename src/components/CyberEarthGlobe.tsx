import React, { useEffect, useState } from 'react';
import { motion } from 'motion/react';
import cyberEarthImg from '../assets/images/cyber_earth_globe_1788878803535.jpg';

interface CyberEarthGlobeProps {
  isScanning?: boolean;
}

export const CyberEarthGlobe: React.FC<CyberEarthGlobeProps> = ({ isScanning = false }) => {
  const [pulseCount, setPulseCount] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setPulseCount((prev) => (prev + 1) % 1000);
    }, 2500);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="relative w-full h-full select-none pointer-events-none flex items-center justify-center">
      {/* 1. Deep Atmospheric Outer Nebula Glow */}
      <motion.div
        animate={{
          scale: isScanning ? [1.1, 1.25, 1.1] : [1, 1.08, 1],
          opacity: isScanning ? [0.4, 0.7, 0.4] : [0.25, 0.45, 0.25],
        }}
        transition={{
          repeat: Infinity,
          duration: isScanning ? 2 : 5,
          ease: 'easeInOut',
        }}
        className="absolute inset-0 bg-radial from-blue-600/40 via-cyan-900/20 to-transparent blur-3xl scale-125"
      />

      {/* 2. Floating Animated Globe Container */}
      <motion.div
        animate={{
          y: [0, -8, 0],
          rotateZ: [0, 0.8, -0.8, 0],
        }}
        transition={{
          repeat: Infinity,
          duration: 8,
          ease: 'easeInOut',
        }}
        className="relative w-[320px] h-[320px] sm:w-[440px] sm:h-[440px] lg:w-[560px] lg:h-[560px] rounded-full"
      >
        {/* 3D Tilted Orbital Ellipses (Simulating dynamic satellite trajectories) */}
        <div className="absolute inset-[-14%] pointer-events-none">
          <svg className="w-full h-full" viewBox="0 0 500 500" fill="none">
            {/* Orbit 1: Equatorial cyber ring */}
            <motion.ellipse
              cx="250"
              cy="250"
              rx="230"
              ry="110"
              transform="rotate(-25 250 250)"
              stroke="rgba(56, 189, 248, 0.25)"
              strokeWidth="1.2"
              strokeDasharray="6 8"
              animate={{ strokeDashoffset: [0, -100] }}
              transition={{ repeat: Infinity, duration: 25, ease: 'linear' }}
            />

            {/* Orbit 2: Polar orbital loop */}
            <motion.ellipse
              cx="250"
              cy="250"
              rx="225"
              ry="85"
              transform="rotate(55 250 250)"
              stroke="rgba(99, 102, 241, 0.3)"
              strokeWidth="1"
              strokeDasharray="4 6"
              animate={{ strokeDashoffset: [0, 80] }}
              transition={{ repeat: Infinity, duration: 20, ease: 'linear' }}
            />

            {/* Orbit 3: Thin outer perimeter guard */}
            <circle
              cx="250"
              cy="250"
              r="245"
              stroke="rgba(14, 165, 233, 0.15)"
              strokeWidth="1"
            />

            {/* Satellite 1 moving on Orbit 1 */}
            <g transform="rotate(-25 250 250)">
              <motion.circle
                r="3.5"
                fill="#38bdf8"
                filter="drop-shadow(0 0 6px #38bdf8)"
                animate={{
                  cx: [20, 250, 480, 250, 20],
                  cy: [250, 360, 250, 140, 250],
                  opacity: [0.3, 0.9, 0.4, 0.8, 0.3],
                }}
                transition={{
                  repeat: Infinity,
                  duration: 14,
                  ease: 'linear',
                }}
              />
            </g>

            {/* Satellite 2 moving on Orbit 2 */}
            <g transform="rotate(55 250 250)">
              <motion.circle
                r="3"
                fill="#a855f7"
                filter="drop-shadow(0 0 6px #c084fc)"
                animate={{
                  cx: [25, 250, 475, 250, 25],
                  cy: [250, 165, 250, 335, 250],
                  opacity: [0.4, 1, 0.4, 0.9, 0.4],
                }}
                transition={{
                  repeat: Infinity,
                  duration: 18,
                  ease: 'linear',
                }}
              />
            </g>

            {/* Curved Inter-City Threat Vectors (Bezier arcs between threat nodes) */}
            {/* Arc from Europe (220, 170) to Middle East (310, 260) */}
            <motion.path
              d="M 220 170 Q 280 200 310 260"
              stroke="rgba(245, 158, 11, 0.5)"
              strokeWidth="1.5"
              strokeDasharray="4 4"
              animate={{ strokeDashoffset: [0, -32] }}
              transition={{ repeat: Infinity, duration: 2, ease: 'linear' }}
            />
            {/* Arc from Middle East (310, 260) to South Africa (240, 320) */}
            <motion.path
              d="M 310 260 Q 290 300 240 320"
              stroke="rgba(59, 130, 246, 0.5)"
              strokeWidth="1.5"
              strokeDasharray="4 4"
              animate={{ strokeDashoffset: [0, -32] }}
              transition={{ repeat: Infinity, duration: 2.5, ease: 'linear' }}
            />
            {/* Arc from Europe (220, 170) to Asia (330, 130) */}
            <motion.path
              d="M 220 170 Q 280 130 330 130"
              stroke="rgba(6, 182, 212, 0.5)"
              strokeWidth="1.5"
              strokeDasharray="4 4"
              animate={{ strokeDashoffset: [0, -32] }}
              transition={{ repeat: Infinity, duration: 3, ease: 'linear' }}
            />
          </svg>
        </div>

        {/* 3. The 3D Holographic Earth Sphere Core */}
        <div className="relative w-full h-full rounded-full overflow-hidden shadow-[0_0_100px_rgba(37,99,235,0.45)]">
          {/* Rotating Holographic Earth Image */}
          <motion.img
            src={cyberEarthImg}
            alt="Cyber Threat Intelligence Earth Globe"
            referrerPolicy="no-referrer"
            className="w-full h-full object-cover object-center"
            animate={{
              scale: isScanning ? [1.05, 1.08, 1.05] : [1.03, 1.06, 1.03],
            }}
            transition={{
              repeat: Infinity,
              duration: 10,
              ease: 'easeInOut',
            }}
          />

          {/* 4. Active Sweeping Radar Cone Animation */}
          <div className="absolute inset-0 rounded-full overflow-hidden pointer-events-none mix-blend-screen">
            <motion.div
              className="w-full h-full rounded-full"
              style={{
                background:
                  'conic-gradient(from 0deg, transparent 0deg, transparent 270deg, rgba(6,182,212,0.08) 320deg, rgba(59,130,246,0.35) 360deg)',
              }}
              animate={{ rotate: 360 }}
              transition={{
                repeat: Infinity,
                duration: isScanning ? 3 : 7,
                ease: 'linear',
              }}
            />
          </div>

          {/* 5. Holographic Cyber Scanline sweep across the sphere */}
          <motion.div
            className="absolute inset-x-0 h-16 bg-gradient-to-b from-transparent via-cyan-400/15 to-transparent pointer-events-none"
            animate={{
              top: ['-20%', '120%'],
            }}
            transition={{
              repeat: Infinity,
              duration: isScanning ? 2 : 4.5,
              ease: 'easeInOut',
            }}
          />

          {/* 6. Deep Atmospheric Inner Rim Glow */}
          <div className="absolute inset-0 rounded-full shadow-[inset_0_0_70px_rgba(59,130,246,0.7)] pointer-events-none" />

          {/* 7. Directional Light Overlay & Contrast Gradients */}
          <div className="absolute inset-0 bg-gradient-to-r from-[#070b13] via-[#070b13]/40 to-transparent pointer-events-none" />
          <div className="absolute inset-0 bg-gradient-to-t from-[#070b13]/70 via-transparent to-[#070b13]/30 pointer-events-none" />
        </div>

        {/* 8. Pulsing Cyber Threat Intelligence Beacons (Matching Reference Screenshot) */}
        {/* Beacon 1: Europe / Spain Threat Node (Amber) */}
        <div className="absolute top-[34%] left-[44%] -translate-x-1/2 -translate-y-1/2 flex items-center justify-center">
          <motion.span
            animate={{ scale: [1, 2.8], opacity: [0.85, 0] }}
            transition={{ repeat: Infinity, duration: 2.2, ease: 'easeOut' }}
            className="absolute inline-flex h-5 w-5 rounded-full bg-amber-400"
          />
          <motion.span
            animate={{ scale: [1, 1.9], opacity: [0.6, 0] }}
            transition={{ repeat: Infinity, duration: 2.2, delay: 0.6, ease: 'easeOut' }}
            className="absolute inline-flex h-4 w-4 rounded-full bg-amber-400"
          />
          <span className="relative inline-flex rounded-full h-3 w-3 bg-amber-500 shadow-[0_0_12px_#f59e0b] border border-amber-200" />
        </div>

        {/* Beacon 2: Middle East / Saudi Arabia Threat Cluster (Amber) */}
        <div className="absolute top-[52%] left-[62%] -translate-x-1/2 -translate-y-1/2 flex items-center justify-center">
          <motion.span
            animate={{ scale: [1, 2.6], opacity: [0.85, 0] }}
            transition={{ repeat: Infinity, duration: 2.5, delay: 0.8, ease: 'easeOut' }}
            className="absolute inline-flex h-5 w-5 rounded-full bg-amber-400"
          />
          <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-amber-500 shadow-[0_0_12px_#f59e0b] border border-amber-200" />
        </div>

        {/* Beacon 3: South Africa Threat Vector (Blue) */}
        <div className="absolute bottom-[36%] left-[48%] -translate-x-1/2 -translate-y-1/2 flex items-center justify-center">
          <motion.span
            animate={{ scale: [1, 2.4], opacity: [0.75, 0] }}
            transition={{ repeat: Infinity, duration: 2.8, delay: 1.4, ease: 'easeOut' }}
            className="absolute inline-flex h-4 w-4 rounded-full bg-blue-400"
          />
          <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-blue-400 shadow-[0_0_10px_#60a5fa] border border-blue-200" />
        </div>

        {/* Beacon 4: Asia / Eurasia Threat Vector (Cyan) */}
        <div className="absolute top-[26%] left-[66%] -translate-x-1/2 -translate-y-1/2 flex items-center justify-center">
          <motion.span
            animate={{ scale: [1, 2.2], opacity: [0.75, 0] }}
            transition={{ repeat: Infinity, duration: 2, delay: 0.3, ease: 'easeOut' }}
            className="absolute inline-flex h-4 w-4 rounded-full bg-cyan-400"
          />
          <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-300 shadow-[0_0_10px_#67e8f9] border border-cyan-100" />
        </div>

        {/* 9. Floating Orbital Telemetry Coordinates Tag */}
        <motion.div
          animate={{
            opacity: [0.6, 0.9, 0.6],
            x: [0, 4, 0],
          }}
          transition={{ repeat: Infinity, duration: 4, ease: 'easeInOut' }}
          className="absolute -bottom-3 right-8 px-2.5 py-1 rounded bg-[#090e1a]/80 border border-blue-500/30 text-[10px] font-mono text-cyan-400 backdrop-blur-md shadow-lg hidden sm:flex items-center gap-1.5"
        >
          <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
          <span>GEO-VECTOR • ACTIVE GLOBAL RADAR</span>
        </motion.div>
      </motion.div>
    </div>
  );
};
