export interface PasswordStrengthResult {
  score: number; // 0 to 100
  label: 'Very Weak' | 'Weak' | 'Medium' | 'Strong' | 'Very Strong';
  color: string;
  hasMinLength: boolean;
  hasUppercase: boolean;
  hasLowercase: boolean;
  hasNumber: boolean;
  hasSpecialChar: boolean;
}

export function checkPasswordStrength(password: string): PasswordStrengthResult {
  const hasMinLength = password.length >= 8;
  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSpecialChar = /[^A-Za-z0-9]/.test(password);

  let score = 0;
  if (password.length >= 8) score += 20;
  if (password.length >= 12) score += 10;
  if (hasUppercase) score += 20;
  if (hasLowercase) score += 15;
  if (hasNumber) score += 15;
  if (hasSpecialChar) score += 20;

  score = Math.min(100, score);

  let label: PasswordStrengthResult['label'] = 'Very Weak';
  let color = 'bg-rose-500';

  if (score >= 85 && hasMinLength && hasUppercase && hasLowercase && hasNumber && hasSpecialChar) {
    label = 'Very Strong';
    color = 'bg-emerald-400';
  } else if (score >= 70 && hasMinLength && (hasUppercase || hasLowercase) && (hasNumber || hasSpecialChar)) {
    label = 'Strong';
    color = 'bg-blue-500';
  } else if (score >= 50 && hasMinLength) {
    label = 'Medium';
    color = 'bg-amber-400';
  } else if (score >= 25) {
    label = 'Weak';
    color = 'bg-orange-500';
  }

  return {
    score,
    label,
    color,
    hasMinLength,
    hasUppercase,
    hasLowercase,
    hasNumber,
    hasSpecialChar
  };
}
