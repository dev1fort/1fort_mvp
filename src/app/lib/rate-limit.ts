import { db } from '@/app/db';
import { rateLimits, auditLogs } from '@/app/db/schema';
import { eq, and, gt } from 'drizzle-orm';
import { generateId } from './security';

interface RateLimitConfig {
  windowMs: number; // Time window in milliseconds
  maxRequests: number; // Max requests per window
}

const RATE_LIMIT_CONFIGS: Record<string, RateLimitConfig> = {
  'auth:send-otp': {
    windowMs: 60 * 1000, // 1 minute
    maxRequests: 3,
  },
  'auth:verify-otp': {
    windowMs: 60 * 1000, // 1 minute
    maxRequests: 5,
  },
  'auth:login': {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 10,
  },
  'auth:refresh': {
    windowMs: 60 * 1000, // 1 minute
    maxRequests: 20,
  },
  'api:general': {
    windowMs: 60 * 1000, // 1 minute
    maxRequests: 100,
  },
  'appointment:create': {
    windowMs: 60 * 1000, // 1 minute
    maxRequests: 5,
  },
};

interface RateLimitResult {
  allowed: boolean;
  remainingRequests?: number;
  resetTime?: Date;
}

/**
 * Checks if request is within rate limit
 */
export async function checkRateLimit(
  identifier: string,
  endpoint: string
): Promise<RateLimitResult> {
  try {
    const config = RATE_LIMIT_CONFIGS[endpoint] || RATE_LIMIT_CONFIGS['api:general'];
    const now = new Date();
    const windowStart = new Date(now.getTime() - config.windowMs);
    
    // Get or create rate limit record
    const existing = await db.query.rateLimits.findFirst({
      where: and(
        eq(rateLimits.identifier, identifier),
        eq(rateLimits.endpoint, endpoint),
        gt(rateLimits.windowStart, windowStart)
      ),
    });
    
    if (existing) {
      if (existing.requestCount >= config.maxRequests) {
        return {
          allowed: false,
          remainingRequests: 0,
          resetTime: new Date(existing.windowStart.getTime() + config.windowMs),
        };
      }
      
      // Increment request count
      await db.update(rateLimits)
        .set({
          requestCount: existing.requestCount + 1,
          lastRequest: now,
        })
        .where(eq(rateLimits.id, existing.id));
      
      return {
        allowed: true,
        remainingRequests: config.maxRequests - existing.requestCount - 1,
        resetTime: new Date(existing.windowStart.getTime() + config.windowMs),
      };
    }
    
    // Create new rate limit record
    await db.insert(rateLimits).values({
      id: generateId('rl'),
      identifier,
      endpoint,
      requestCount: 1,
      windowStart: now,
      lastRequest: now,
    });
    
    return {
      allowed: true,
      remainingRequests: config.maxRequests - 1,
      resetTime: new Date(now.getTime() + config.windowMs),
    };
  } catch (error) {
    console.error('Rate limit check error:', error);
    // On error, allow request but log it
    return { allowed: true };
  }
}

/**
 * Cleans up old rate limit records
 */
export async function cleanupRateLimits(): Promise<void> {
  const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
  
  await db.execute(
    `DELETE FROM rate_limits WHERE window_start < ?`,
    [oneDayAgo]
  );
}

interface AuditLogData {
  userId?: string;
  superuserId?: string;
  action: string;
  resource: string;
  resourceId?: string;
  ipAddress: string;
  userAgent?: string;
  metadata?: Record<string, any>;
  success: boolean;
  errorMessage?: string;
  companyId?: string;
}

/**
 * Creates an audit log entry
 */
export async function createAuditLog(data: AuditLogData): Promise<void> {
  try {
    await db.insert(auditLogs).values({
      id: generateId('audit'),
      userId: data.userId,
      superuserId: data.superuserId,
      action: data.action,
      resource: data.resource,
      resourceId: data.resourceId,
      ipAddress: data.ipAddress,
      userAgent: data.userAgent,
      metadata: data.metadata ? JSON.stringify(data.metadata) : null,
      success: data.success,
      errorMessage: data.errorMessage,
      createdAt: new Date(),
    });
  } catch (error) {
    console.error('Failed to create audit log:', error);
    // Don't throw - audit logging should not break application flow
  }
}

/**
 * Audit log helper for authentication events
 */
export async function auditAuthEvent(
  action: 'signup' | 'login' | 'logout' | 'token-refresh' | 'otp-send' | 'otp-verify',
  data: {
    userId?: string;
    superuserId?: string;
    phoneNumber?: string;
    ipAddress: string;
    userAgent?: string;
    success: boolean;
    errorMessage?: string;
  }
): Promise<void> {
  await createAuditLog({
    userId: data.userId,
    superuserId: data.superuserId,
    action: `auth:${action}`,
    resource: 'authentication',
    resourceId: data.phoneNumber,
    ipAddress: data.ipAddress,
    userAgent: data.userAgent,
    success: data.success,
    errorMessage: data.errorMessage,
  });
}

/**
 * Cleans up old audit logs (keep for 90 days)
 */
export async function cleanupAuditLogs(): Promise<void> {
  const BATCH_SIZE = 1000;
  const ninetyDaysAgo = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);
  
  let deleted = 0;
  do {
    const result = await db.execute(
      `DELETE FROM audit_logs 
       WHERE id IN (
         SELECT id FROM audit_logs 
         WHERE created_at < ? 
         LIMIT ?
       )`,
      [ninetyDaysAgo, BATCH_SIZE]
    );
    
    deleted = result.rowsAffected || 0;
    
    if (deleted === BATCH_SIZE) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }
  } while (deleted === BATCH_SIZE);
}

/**
 * Gets recent failed login attempts for an identifier
 */
export async function getFailedLoginAttempts(
  identifier: string,
  windowMs = 15 * 60 * 1000
): Promise<number> {
  const windowStart = new Date(Date.now() - windowMs);
  
  const attempts = await db.query.auditLogs.findMany({
    where: and(
      eq(auditLogs.action, 'auth:login'),
      eq(auditLogs.resourceId, identifier),
      eq(auditLogs.success, false),
      gt(auditLogs.createdAt, windowStart)
    ),
  });
  
  return attempts.length;
}

/**
 * Checks if account should be locked due to failed attempts
 */
export async function shouldLockAccount(
  identifier: string,
  maxAttempts = 5
): Promise<boolean> {
  const attempts = await getFailedLoginAttempts(identifier);
  return attempts >= maxAttempts;
}