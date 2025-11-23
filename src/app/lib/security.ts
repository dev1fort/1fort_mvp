import crypto from 'crypto';

export function normalizePhoneNumber(input: string, defaultCountryCode = '1'): string {
  let digits = input.replace(/\D/g, '');
  
  if (digits.length > 10) {
    digits = digits.substring(0, 15);
  }
  
  // Handle country code
  if (!digits.startsWith(defaultCountryCode) && digits.length === 10) {
    digits = defaultCountryCode + digits;
  }
  
  // Validate E.164 format
  if (!/^[1-9]\d{1,14}$/.test(digits)) {
    throw new Error('Invalid phone number format');
  }
  
  return '+' + digits;
}

/**
 * Generates a cryptographically secure OTP
 */
export function generateOTP(length = 6): string {
  const digits = '0123456789';
  let otp = '';
  const randomBytes = crypto.randomBytes(length);
  
  for (let i = 0; i < length; i++) {
    otp += digits[randomBytes[i] % digits.length];
  }
  
  return otp;
}


export function hashOTP(otp: string): string {
  return crypto.createHash('sha256').update(otp).digest('hex');
}

export function generateDeviceFingerprint(
  userAgent: string,
  ip: string,
  additionalData?: Record<string, any>
): string {
  const data = JSON.stringify({
    userAgent,
    ip,
    ...additionalData,
  });
  
  return crypto.createHash('sha256').update(data).digest('hex');
}


export function generateId(prefix?: string): string {
  const id = crypto.randomUUID();
  return prefix ? `${prefix}_${id}` : id;
}


export function generateJti(): string {
  return crypto.randomBytes(16).toString('hex');
}


export function generateTokenFamily(): string {
  return crypto.randomBytes(16).toString('hex');
}


export function generateSecureToken(length = 32): string {
  return crypto.randomBytes(length).toString('base64url');
}


export function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}


export function secureCompare(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  
  return crypto.timingSafeEqual(
    Buffer.from(a, 'utf-8'),
    Buffer.from(b, 'utf-8')
  );
}


export function isValidEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}


export function sanitizeInput(input: string): string {
  return input
    .trim()
    .replace(/[<>]/g, '') // Remove potential HTML tags
    .substring(0, 255); // Limit length
}


export function generateSignupCode(): string {
  // Generate a URL-safe code
  return crypto.randomBytes(16).toString('base64url');
}


export const CLOCK_SKEW_SECONDS = 30;


export function isTimestampValid(
  timestamp: number,
  maxAgeSeconds?: number
): boolean {
  const now = Math.floor(Date.now() / 1000);
  const diff = Math.abs(now - timestamp);
  
  // Check clock skew
  if (diff > CLOCK_SKEW_SECONDS) {
    if (maxAgeSeconds && timestamp < now - maxAgeSeconds) {
      return false;
    }
  }
  
  return true;
}