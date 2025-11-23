import jwt from 'jsonwebtoken';
import { db } from '@/app/db';
import { refreshTokens, sessions, tokenBlacklist } from '@/app/db/schema';
import { eq, and, gt, lt } from 'drizzle-orm';
import {
  generateId,
  generateJti,
  generateTokenFamily,
  generateSecureToken,
  hashToken,
  CLOCK_SKEW_SECONDS,
} from './security';

const JWT_SECRET = process.env.JWT_SECRET!;
const ACCESS_TOKEN_EXPIRY = '15m';
const REFRESH_TOKEN_EXPIRY_DAYS = 30;
const MAX_REFRESH_COUNT = 1000;
const MIN_REFRESH_INTERVAL = 60000; // 1 minute

interface TokenPayload {
  userId?: string;
  superuserId?: string;
  type: 'user' | 'superuser';
  jti: string;
  sessionId: string;
  iat: number;
  exp: number;
}

interface DeviceInfo {
  fingerprint: string;
  ipAddress: string;
  userAgent?: string;
}

interface TokenPair {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}


export async function generateTokenPair(
  userId: string | undefined,
  superuserId: string | undefined,
  deviceInfo: DeviceInfo,
  tokenFamily?: string
): Promise<TokenPair> {
  const type = superuserId ? 'superuser' : 'user';
  const family = tokenFamily || generateTokenFamily();
  const sessionId = generateId('session');
  const jti = generateJti();
  
  // Generate access token
  const accessToken = jwt.sign(
    {
      userId,
      superuserId,
      type,
      jti,
      sessionId,
    },
    JWT_SECRET,
    { expiresIn: ACCESS_TOKEN_EXPIRY }
  );
  
  // Generate refresh token
  const refreshToken = generateSecureToken();
  const refreshTokenHash = hashToken(refreshToken);
  const refreshTokenId = generateId('rt');
  
  const now = new Date();
  const expiresAt = new Date(now.getTime() + REFRESH_TOKEN_EXPIRY_DAYS * 24 * 60 * 60 * 1000);
  
  // Store refresh token
  await db.insert(refreshTokens).values({
    id: refreshTokenId,
    tokenHash: refreshTokenHash,
    userId,
    superuserId,
    tokenFamily: family,
    expiresAt,
    deviceFingerprint: deviceInfo.fingerprint,
    ipAddress: deviceInfo.ipAddress,
    userAgent: deviceInfo.userAgent,
    createdAt: now,
  });
  
  // Create or update session
  await db.insert(sessions).values({
    id: sessionId,
    userId,
    superuserId,
    tokenFamily: family,
    deviceFingerprint: deviceInfo.fingerprint,
    ipAddress: deviceInfo.ipAddress,
    userAgent: deviceInfo.userAgent,
    lastActivity: now,
    sessionStarted: now,
    refreshCount: 0,
    createdAt: now,
  }).onConflictDoUpdate({
    target: sessions.tokenFamily,
    set: {
      lastActivity: now,
    },
  });
  
  return {
    accessToken,
    refreshToken,
    expiresIn: 15 * 60, // 15 minutes in seconds
  };
}

export async function rotateRefreshToken(
  oldRefreshToken: string,
  deviceInfo: DeviceInfo
): Promise<TokenPair | { error: string }> {
  try {
    const tokenHash = hashToken(oldRefreshToken);
    
    return await db.transaction(async (tx) => {
      // Get token record with lock
      const tokenRecord = await tx.query.refreshTokens.findFirst({
        where: eq(refreshTokens.tokenHash, tokenHash),
      });
      
      if (!tokenRecord) {
        return { error: 'Invalid refresh token' };
      }
      
      // Check if token is revoked
      if (tokenRecord.revoked) {
        // Possible token theft - revoke entire token family
        await tx.update(refreshTokens)
          .set({ revoked: true, revokedAt: new Date() })
          .where(eq(refreshTokens.tokenFamily, tokenRecord.tokenFamily));
        
        await tx.update(sessions)
          .set({ revoked: true, isActive: false })
          .where(eq(sessions.tokenFamily, tokenRecord.tokenFamily));
        
        return { error: 'Token has been revoked' };
      }
      
      // Check if token expired
      if (new Date() > tokenRecord.expiresAt) {
        return { error: 'Refresh token expired. Please login again.' };
      }
      
      // Check for race condition - token was JUST rotated (within 10 seconds)
      if (tokenRecord.rotatedAt && tokenRecord.newTokenId) {
        const timeSinceRotation = Date.now() - tokenRecord.rotatedAt.getTime();
        
        if (timeSinceRotation < 10000) {
          // Return the same new token instead of treating as attack
          const newTokenRecord = await tx.query.refreshTokens.findFirst({
            where: eq(refreshTokens.id, tokenRecord.newTokenId),
          });
          
          if (newTokenRecord && !newTokenRecord.revoked) {
            // Generate new access token
            const jti = generateJti();
            const accessToken = jwt.sign(
              {
                userId: newTokenRecord.userId,
                superuserId: newTokenRecord.superuserId,
                type: newTokenRecord.superuserId ? 'superuser' : 'user',
                jti,
              },
              JWT_SECRET,
              { expiresIn: ACCESS_TOKEN_EXPIRY }
            );
            
            return {
              accessToken,
              refreshToken: oldRefreshToken, // Same token
              expiresIn: 15 * 60,
            };
          }
        }
      }
      
      // Get session for frequency checks
      const session = await tx.query.sessions.findFirst({
        where: eq(sessions.tokenFamily, tokenRecord.tokenFamily),
      });
      
      if (!session) {
        return { error: 'Session not found' };
      }
      
      // Check refresh frequency
      const timeSinceLastRefresh = Date.now() - session.lastActivity.getTime();
      if (timeSinceLastRefresh < MIN_REFRESH_INTERVAL) {
        return { error: 'Token refreshed too frequently' };
      }
      
      // 30 days max)
      const sessionAge = Date.now() - session.sessionStarted.getTime();
      if (sessionAge > REFRESH_TOKEN_EXPIRY_DAYS * 24 * 60 * 60 * 1000) {
        return { error: 'Session expired. Please login again.' };
      }
      
      // Check refresh count
      if (session.refreshCount > MAX_REFRESH_COUNT) {
        return { error: 'Session requires re-authentication' };
      }
      
      // Verify device fingerprint
      if (tokenRecord.deviceFingerprint !== deviceInfo.fingerprint) {
        await tx.update(refreshTokens)
          .set({ revoked: true, revokedAt: new Date() })
          .where(eq(refreshTokens.tokenFamily, tokenRecord.tokenFamily));
        
        return { error: 'Device fingerprint mismatch' };
      }
      
      // Generate new token pair
      const newRefreshToken = generateSecureToken();
      const newRefreshTokenHash = hashToken(newRefreshToken);
      const newRefreshTokenId = generateId('rt');
      const now = new Date();
      
      // Create new refresh token
      await tx.insert(refreshTokens).values({
        id: newRefreshTokenId,
        tokenHash: newRefreshTokenHash,
        userId: tokenRecord.userId,
        superuserId: tokenRecord.superuserId,
        tokenFamily: tokenRecord.tokenFamily,
        expiresAt: new Date(now.getTime() + REFRESH_TOKEN_EXPIRY_DAYS * 24 * 60 * 60 * 1000),
        deviceFingerprint: deviceInfo.fingerprint,
        ipAddress: deviceInfo.ipAddress,
        userAgent: deviceInfo.userAgent,
        createdAt: now,
      });
      
      // Mark old token as rotated (not revoked immediately for grace period)
      await tx.update(refreshTokens)
        .set({
          rotatedAt: now,
          newTokenId: newRefreshTokenId,
        })
        .where(eq(refreshTokens.id, tokenRecord.id));
      
      // Update session
      await tx.update(sessions)
        .set({
          lastActivity: now,
          refreshCount: session.refreshCount + 1,
        })
        .where(eq(sessions.id, session.id));
      
      // Generate new access token
      const jti = generateJti();
      const accessToken = jwt.sign(
        {
          userId: tokenRecord.userId,
          superuserId: tokenRecord.superuserId,
          type: tokenRecord.superuserId ? 'superuser' : 'user',
          jti,
        },
        JWT_SECRET,
        { expiresIn: ACCESS_TOKEN_EXPIRY }
      );
      
      return {
        accessToken,
        refreshToken: newRefreshToken,
        expiresIn: 15 * 60,
      };
    });
  } catch (error) {
    console.error('Error rotating refresh token:', error);
    return { error: 'An error occurred during token rotation' };
  }
}

/**
 * Verifies access token with clock skew tolerance
 */
export function verifyAccessToken(token: string): TokenPayload | null {
  try {
    const decoded = jwt.verify(token, JWT_SECRET, {
      clockTolerance: CLOCK_SKEW_SECONDS,
    }) as TokenPayload;
    
    return decoded;
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      return null;
    }
    if (error instanceof jwt.JsonWebTokenError) {
      return null;
    }
    throw error;
  }
}


export async function isTokenBlacklisted(jti: string): Promise<boolean> {
  const blacklisted = await db.query.tokenBlacklist.findFirst({
    where: eq(tokenBlacklist.tokenJti, jti),
  });
  
  return !!blacklisted;
}


export async function blacklistToken(
  jti: string,
  expiresAt: Date
): Promise<void> {
  await db.insert(tokenBlacklist).values({
    id: generateId('bl'),
    tokenJti: jti,
    expiresAt,
    createdAt: new Date(),
  });
}


export async function revokeAllTokens(
  userId?: string,
  superuserId?: string
): Promise<void> {
  const now = new Date();
  
  if (userId) {
    await db.update(refreshTokens)
      .set({ revoked: true, revokedAt: now })
      .where(eq(refreshTokens.userId, userId));
    
    await db.update(sessions)
      .set({ revoked: true, isActive: false })
      .where(eq(sessions.userId, userId));
  }
  
  if (superuserId) {
    await db.update(refreshTokens)
      .set({ revoked: true, revokedAt: now })
      .where(eq(refreshTokens.superuserId, superuserId));
    
    await db.update(sessions)
      .set({ revoked: true, isActive: false })
      .where(eq(sessions.superuserId, superuserId));
  }
}

/**
 * Cleans up expired tokens (run periodically)
 */
export async function cleanupExpiredTokens(): Promise<void> {
  const BATCH_SIZE = 100;
  const now = new Date();
  
  // Clean refresh tokens
  let deleted = 0;
  do {
    const result = await db.execute(
      `DELETE FROM refresh_tokens 
       WHERE id IN (
         SELECT id FROM refresh_tokens 
         WHERE expires_at < ? 
         LIMIT ?
       )`,
      [now, BATCH_SIZE]
    );
    
    deleted = result.rowsAffected || 0;
    if (deleted === BATCH_SIZE) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }
  } while (deleted === BATCH_SIZE);
  
  // Clean blacklist
  deleted = 0;
  do {
    const result = await db.execute(
      `DELETE FROM token_blacklist 
       WHERE id IN (
         SELECT id FROM token_blacklist 
         WHERE expires_at < ? 
         LIMIT ?
       )`,
      [now, BATCH_SIZE]
    );
    
    deleted = result.rowsAffected || 0;
    if (deleted === BATCH_SIZE) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }
  } while (deleted === BATCH_SIZE);
}

/**
 * Cleans up orphaned sessions
 * Handles edge case: Orphaned Sessions
 */
export async function cleanupOrphanedSessions(
  userId?: string,
  superuserId?: string
): Promise<void> {
  const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
  
  if (userId) {
    await db.delete(sessions)
      .where(
        and(
          eq(sessions.userId, userId),
          lt(sessions.lastActivity, sevenDaysAgo)
        )
      );
  }
  
  if (superuserId) {
    await db.delete(sessions)
      .where(
        and(
          eq(sessions.superuserId, superuserId),
          lt(sessions.lastActivity, sevenDaysAgo)
        )
      );
  }
}

// Enforces concurrent device limi
export async function enforceDeviceLimit(
  userId: string | undefined,
  superuserId: string | undefined,
  maxDevices = 5
): Promise<void> {
  const accountId = userId || superuserId;
  const accountType = userId ? 'user' : 'superuser';
  
  if (!accountId) return;
  
  const activeSessions = await db.query.sessions.findMany({
    where: and(
      accountType === 'user' 
        ? eq(sessions.userId, accountId)
        : eq(sessions.superuserId, accountId),
      eq(sessions.isActive, true)
    ),
    orderBy: (sessions, { asc }) => [asc(sessions.createdAt)],
  });
  
  if (activeSessions.length >= maxDevices) {
    // Revoke oldest session
    const oldest = activeSessions[0];
    await db.update(sessions)
      .set({ revoked: true, isActive: false })
      .where(eq(sessions.id, oldest.id));
    
    // Revoke associated refresh tokens
    await db.update(refreshTokens)
      .set({ revoked: true, revokedAt: new Date() })
      .where(eq(refreshTokens.tokenFamily, oldest.tokenFamily));
    
    // TODO: Send notification to user about logout
  }
}