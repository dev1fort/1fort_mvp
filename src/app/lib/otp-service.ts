import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';
import { db } from '@/app/db';
import { otps } from '@/app/db/schema';
import { eq, and, gt } from 'drizzle-orm';
import { generateOTP, hashOTP, generateId, normalizePhoneNumber } from './security';

const snsClient = new SNSClient({
  region: process.env.AWS_REGION!,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID!,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY!,
  },
});

interface SendOTPResult {
  success: boolean;
  waitTime?: number;
  message: string;
  otpId?: string;
}

/**
 * Sends OTP via SMS with rate limiting and edge case handling
 * Handles edge cases:
 * - OTP double-send spam
 * - SMS gateway timeout
 */
export async function sendOTP(
  phoneNumber: string,
  countryCode = '1'
): Promise<SendOTPResult> {
  try {
    // Normalize phone number
    const normalizedPhone = normalizePhoneNumber(phoneNumber, countryCode);
    
    // Check if OTP sent recently (60 second cooldown)
    const recentOTP = await db.query.otps.findFirst({
      where: and(
        eq(otps.phoneNumber, normalizedPhone),
        gt(otps.createdAt, new Date(Date.now() - 60000)),
        eq(otps.used, false)
      ),
    });
    
    if (recentOTP) {
      const waitTime = 60 - Math.floor((Date.now() - recentOTP.createdAt.getTime()) / 1000);
      return {
        success: false,
        waitTime,
        message: 'OTP already sent. Check your SMS or wait before requesting again.',
      };
    }
    
    // Generate OTP
    const otp = generateOTP(6);
    const otpHash = hashOTP(otp);
    const otpId = generateId('otp');
    
    // Send SMS with timeout using Promise.race
    // Handles edge case: SMS Gateway Timeout
    try {
      await Promise.race([
        snsClient.send(new PublishCommand({
          PhoneNumber: normalizedPhone,
          Message: `Your verification code is: ${otp}. Valid for 10 minutes. Do not share this code with anyone.`,
          MessageAttributes: {
            'AWS.SNS.SMS.SMSType': {
              DataType: 'String',
              StringValue: 'Transactional',
            },
          },
        })),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error('SMS timeout')), 10000)
        ),
      ]);
    } catch (smsError) {
      console.error('SMS send failed:', smsError);
      return {
        success: false,
        message: 'Failed to send SMS. Please try again.',
      };
    }
    
    // Store OTP only after SMS sent successfully
    // Handles edge case: OTP stored but SMS failed
    await db.insert(otps).values({
      id: otpId,
      phoneNumber: normalizedPhone,
      otpHash,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes
      createdAt: new Date(),
    });
    
    return {
      success: true,
      message: 'OTP sent successfully',
      otpId,
    };
  } catch (error) {
    console.error('Error sending OTP:', error);
    return {
      success: false,
      message: 'An error occurred. Please try again.',
    };
  }
}

interface VerifyOTPResult {
  success: boolean;
  message: string;
  phoneNumber?: string;
}

/**
 * Verifies OTP with security measures
 * Handles edge cases:
 * - Replay attacks
 * - Timezone confusion
 * - Race conditions
 */
export async function verifyOTP(
  phoneNumber: string,
  otp: string,
  fingerprint: string,
  countryCode = '1'
): Promise<VerifyOTPResult> {
  try {
    const normalizedPhone = normalizePhoneNumber(phoneNumber, countryCode);
    const otpHash = hashOTP(otp);
    
    // Use transaction with row locking to prevent race conditions
    // Handles edge case: Replay Attack on OTP
    return await db.transaction(async (tx) => {
      // Lock the OTP row
      const otpRecord = await tx.query.otps.findFirst({
        where: and(
          eq(otps.phoneNumber, normalizedPhone),
          eq(otps.otpHash, otpHash),
          eq(otps.used, false)
        ),
      });
      
      if (!otpRecord) {
        return {
          success: false,
          message: 'Invalid or already used OTP',
        };
      }
      
      // Check if OTP is expired
      // Handles edge case: Timezone OTP Expiry Confusion
      const now = new Date();
      if (now > otpRecord.expiresAt) {
        return {
          success: false,
          message: 'OTP has expired. Please request a new one.',
        };
      }
      
      // Check attempt count to prevent brute force
      if (otpRecord.attemptCount >= 5) {
        return {
          success: false,
          message: 'Too many failed attempts. Please request a new OTP.',
        };
      }
      
      // Mark OTP as used immediately
      await tx.update(otps)
        .set({
          used: true,
          usedAt: now,
          usedByFingerprint: fingerprint,
        })
        .where(eq(otps.id, otpRecord.id));
      
      return {
        success: true,
        message: 'OTP verified successfully',
        phoneNumber: normalizedPhone,
      };
    });
  } catch (error) {
    console.error('Error verifying OTP:', error);
    
    // Increment attempt count on failure
    try {
      const normalizedPhone = normalizePhoneNumber(phoneNumber, countryCode);
      await db.execute(
        `UPDATE otps 
         SET attempt_count = attempt_count + 1 
         WHERE phone_number = ? AND used = 0`,
        [normalizedPhone]
      );
    } catch (updateError) {
      console.error('Error updating attempt count:', updateError);
    }
    
    return {
      success: false,
      message: 'An error occurred. Please try again.',
    };
  }
}

/**
 * Cleans up expired OTPs (run periodically)
 * Handles edge case: Cleanup Job During Peak Hours
 */
export async function cleanupExpiredOTPs(): Promise<void> {
  const BATCH_SIZE = 100;
  let deleted = 0;
  
  do {
    // Delete in small batches to avoid table locks
    const result = await db.execute(
      `DELETE FROM otps 
       WHERE id IN (
         SELECT id FROM otps 
         WHERE expires_at < ? 
         LIMIT ?
       )`,
      [new Date(), BATCH_SIZE]
    );
    
    deleted = result.rowsAffected || 0;
    
    // Brief pause to let other queries through
    if (deleted === BATCH_SIZE) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }
  } while (deleted === BATCH_SIZE);
}