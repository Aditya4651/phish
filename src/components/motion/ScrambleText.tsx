import React, { useEffect, useState } from 'react';

interface ScrambleTextProps {
  text: string;
  className?: string;
  characters?: string;
  durationMs?: number;
  trigger?: any;
}

const DEFAULT_CHARS = 'ABCDEF0123456789_#@*&%';

export const ScrambleText: React.FC<ScrambleTextProps> = ({
  text,
  className = '',
  characters = DEFAULT_CHARS,
  durationMs = 150,
  trigger
}) => {
  const [displayText, setDisplayText] = useState(text);

  useEffect(() => {
    setDisplayText(text);
    if (durationMs <= 50) return;

    let frame = 0;
    const totalFrames = Math.max(3, Math.floor(durationMs / 30));
    const targetLength = text.length;

    const interval = setInterval(() => {
      frame++;
      const progress = frame / totalFrames;
      const revealedCount = Math.floor(progress * targetLength);

      let scrambled = '';
      for (let i = 0; i < targetLength; i++) {
        if (i < revealedCount) {
          scrambled += text[i];
        } else if (text[i] === ' ' || text[i] === '-' || text[i] === ':') {
          scrambled += text[i];
        } else {
          scrambled += characters[Math.floor(Math.random() * characters.length)];
        }
      }

      setDisplayText(scrambled);

      if (frame >= totalFrames) {
        clearInterval(interval);
        setDisplayText(text);
      }
    }, 20);

    return () => clearInterval(interval);
  }, [text, trigger, durationMs, characters]);

  return <span className={className}>{displayText}</span>;
};
