import { sqliteTable, text, integer, index, primaryKey } from 'drizzle-orm/sqlite-core';
import { sql } from 'drizzle-orm';

// Superusers
export const superusers = sqliteTable('superusers', {
  id: text('id').primaryKey(),
  email: text('email').notNull().unique(),
  phoneNumber: text('phone_number').notNull().unique(),
  name: text('name').notNull(),
  isActive: integer('is_active', { mode: 'boolean' }).notNull().default(true),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().default(sql`(unixepoch())`),
  deletedAt: integer('deleted_at', { mode: 'timestamp' }),
}, (table) => ({
  phoneIdx: index('superuser_phone_idx').on(table.phoneNumber),
  emailIdx: index('superuser_email_idx').on(table.email),
}));

// Companies
export const companies = sqliteTable('companies', {
  id: text('id').primaryKey(),
  superuserId: text('superuser_id').notNull().references(() => superusers.id),
  name: text('name').notNull(),
  description: text('description'),
  signupQrCode: text('signup_qr_code').notNull(), // QR code data URL
  signupLinkId: text('signup_link_id').notNull().unique(), // Unique code for signup URL
  isActive: integer('is_active', { mode: 'boolean' }).notNull().default(true),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().default(sql`(unixepoch())`),
  deletedAt: integer('deleted_at', { mode: 'timestamp' }),
}, (table) => ({
  superuserIdx: index('company_superuser_idx').on(table.superuserId),
  linkIdIdx: index('company_link_id_idx').on(table.signupLinkId),
}));

// Regular users (customers)
export const users = sqliteTable('users', {
  id: text('id').primaryKey(),
  email: text('email').notNull().unique(),
  phoneNumber: text('phone_number').notNull().unique(),
  name: text('name').notNull(),
  isActive: integer('is_active', { mode: 'boolean' }).notNull().default(true),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().default(sql`(unixepoch())`),
  deletedAt: integer('deleted_at', { mode: 'timestamp' }),
}, (table) => ({
  phoneIdx: index('user_phone_idx').on(table.phoneNumber),
  emailIdx: index('user_email_idx').on(table.email),
}));

// A user can be affiliated with multiple companies
export const userCompanies = sqliteTable('user_companies', {
  userId: text('user_id').notNull().references(() => users.id),
  companyId: text('company_id').notNull().references(() => companies.id),
  status: text('status').notNull().default('pending'), // pending, approved, rejected
  affiliatedAt: integer('affiliated_at', { mode: 'timestamp' }).notNull().default(sql`(unixepoch())`),
  approvedAt: integer('approved_at', { mode: 'timestamp' }),
  approvedBy: text('approved_by'),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().default(sql`(unixepoch())`),
}, (table) => ({
  pk: primaryKey({ columns: [table.userId, table.companyId] }),
  userIdx: index('user_company_user_idx').on(table.userId),
  companyIdx: index('user_company_company_idx').on(table.companyId),
}));

// OTP 
export const otps = sqliteTable('otps', {
  id: text('id').primaryKey(),
  phoneNumber: text('phone_number').notNull(),
  otpHash: text('otp_hash').notNull(),
  expiresAt: integer('expires_at', { mode: 'timestamp' }).notNull(),
  used: integer('used', { mode: 'boolean' }).notNull().default(false),
  usedAt: integer('used_at', { mode: 'timestamp' }),
  usedByFingerprint: text('used_by_fingerprint'),
  attemptCount: integer('attempt_count').notNull().default(0),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().default(sql`(unixepoch())`),
}, (table) => ({
  phoneIdx: index('otp_phone_idx').on(table.phoneNumber),
  expiresIdx: index('otp_expires_idx').on(table.expiresAt),
}));

// Refresh tokens rotation
export const refreshTokens = sqliteTable('refresh_tokens', {
  id: text('id').primaryKey(),
  tokenHash: text('token_hash').notNull().unique(),
  userId: text('user_id'),
  superuserId: text('superuser_id'),
  tokenFamily: text('token_family').notNull(),
  expiresAt: integer('expires_at', { mode: 'timestamp' }).notNull(),
  revoked: integer('revoked', { mode: 'boolean' }).notNull().default(false),
  revokedAt: integer('revoked_at', { mode: 'timestamp' }),
  rotatedAt: integer('rotated_at', { mode: 'timestamp' }),
  newTokenId: text('new_token_id'),
  deviceFingerprint: text('device_fingerprint').notNull(),
  ipAddress: text('ip_address').notNull(),
  userAgent: text('user_agent'),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().default(sql`(unixepoch())`),
}, (table) => ({
  userIdx: index('refresh_token_user_idx').on(table.userId),
  superuserIdx: index('refresh_token_superuser_idx').on(table.superuserId),
  familyIdx: index('refresh_token_family_idx').on(table.tokenFamily),
  expiresIdx: index('refresh_token_expires_idx').on(table.expiresAt),
}));

// Sessions active logins
export const sessions = sqliteTable('sessions', {
  id: text('id').primaryKey(),
  userId: text('user_id'),
  superuserId: text('superuser_id'),
  tokenFamily: text('token_family').notNull(),
  deviceFingerprint: text('device_fingerprint').notNull(),
  ipAddress: text('ip_address').notNull(),
  userAgent: text('user_agent'),
  lastActivity: integer('last_activity', { mode: 'timestamp' }).notNull(),
  sessionStarted: integer('session_started', { mode: 'timestamp' }).notNull().default(sql`(unixepoch())`),
  refreshCount: integer('refresh_count').notNull().default(0),
  isActive: integer('is_active', { mode: 'boolean' }).notNull().default(true),
  revoked: integer('revoked', { mode: 'boolean' }).notNull().default(false),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().default(sql`(unixepoch())`),
}, (table) => ({
  userIdx: index('session_user_idx').on(table.userId),
  superuserIdx: index('session_superuser_idx').on(table.superuserId),
  familyIdx: index('session_family_idx').on(table.tokenFamily),
}));

// Token blacklist for immediate invalidation
export const tokenBlacklist = sqliteTable('token_blacklist', {
  id: text('id').primaryKey(),
  tokenJti: text('token_jti').notNull().unique(),
  expiresAt: integer('expires_at', { mode: 'timestamp' }).notNull(),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().default(sql`(unixepoch())`),
}, (table) => ({
  jtiIdx: index('blacklist_jti_idx').on(table.tokenJti),
  expiresIdx: index('blacklist_expires_idx').on(table.expiresAt),
}));

// Signup links tracking for companies
export const signupLinks = sqliteTable('signup_links', {
  id: text('id').primaryKey(),
  companyId: text('company_id').notNull().references(() => companies.id),
  code: text('code').notNull().unique(),
  maxUses: integer('max_uses'), // null = unlimited
  useCount: integer('use_count').notNull().default(0),
  isActive: integer('is_active', { mode: 'boolean' }).notNull().default(true),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().default(sql`(unixepoch())`),
}, (table) => ({
  codeIdx: index('signup_link_code_idx').on(table.code),
  companyIdx: index('signup_link_company_idx').on(table.companyId),
}));

// Registration attempts for QR code tracking
export const registrationAttempts = sqliteTable('registration_attempts', {
  id: text('id').primaryKey(),
  signupCode: text('signup_code').notNull(),
  companyId: text('company_id').notNull(),
  registrationToken: text('registration_token').notNull().unique(),
  ipAddress: text('ip_address').notNull(),
  userAgent: text('user_agent'),
  expiresAt: integer('expires_at', { mode: 'timestamp' }).notNull(),
  completed: integer('completed', { mode: 'boolean' }).notNull().default(false),
  userId: text('user_id'),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().default(sql`(unixepoch())`),
}, (table) => ({
  companyIdx: index('reg_attempt_company_idx').on(table.companyId),
}));

// Appointments/bookings
export const appointments = sqliteTable('appointments', {
  id: text('id').primaryKey(),
  userId: text('user_id').notNull().references(() => users.id),
  companyId: text('company_id').notNull().references(() => companies.id),
  superuserId: text('superuser_id').notNull().references(() => superusers.id),
  appointmentDate: integer('appointment_date', { mode: 'timestamp' }).notNull(),
  status: text('status').notNull().default('pending'), // pending, approved, rejected, completed
  details: text('details'),
  confirmationQrCode: text('confirmation_qr_code'),
  approvedAt: integer('approved_at', { mode: 'timestamp' }),
  approvedBy: text('approved_by'),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().default(sql`(unixepoch())`),
  updatedAt: integer('updated_at', { mode: 'timestamp' }).notNull().default(sql`(unixepoch())`),
}, (table) => ({
  userIdx: index('appointment_user_idx').on(table.userId),
  companyIdx: index('appointment_company_idx').on(table.companyId),
  superuserIdx: index('appointment_superuser_idx').on(table.superuserId),
  statusIdx: index('appointment_status_idx').on(table.status),
}));

// Rate limiting
export const rateLimits = sqliteTable('rate_limits', {
  id: text('id').primaryKey(),
  identifier: text('identifier').notNull(),
  endpoint: text('endpoint').notNull(),
  requestCount: integer('request_count').notNull().default(1),
  windowStart: integer('window_start', { mode: 'timestamp' }).notNull(),
  lastRequest: integer('last_request', { mode: 'timestamp' }).notNull(),
}, (table) => ({
  identifierIdx: index('rate_limit_identifier_idx').on(table.identifier, table.endpoint),
}));

// Audit logs
export const auditLogs = sqliteTable('audit_logs', {
  id: text('id').primaryKey(),
  userId: text('user_id'),
  superuserId: text('superuser_id'),
  companyId: text('company_id'),
  action: text('action').notNull(),
  resource: text('resource').notNull(),
  resourceId: text('resource_id'),
  ipAddress: text('ip_address').notNull(),
  userAgent: text('user_agent'),
  metadata: text('metadata'),
  success: integer('success', { mode: 'boolean' }).notNull(),
  errorMessage: text('error_message'),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().default(sql`(unixepoch())`),
}, (table) => ({
  userIdx: index('audit_user_idx').on(table.userId),
  superuserIdx: index('audit_superuser_idx').on(table.superuserId),
  companyIdx: index('audit_company_idx').on(table.companyId),
  actionIdx: index('audit_action_idx').on(table.action),
  createdIdx: index('audit_created_idx').on(table.createdAt),
}));

// SSE connections for real-time notifications - company-aware
export const sseConnections = sqliteTable('sse_connections', {
  id: text('id').primaryKey(),
  superuserId: text('superuser_id').notNull().references(() => superusers.id),
  companyId: text('company_id'), // Optional - can filter notifications by company
  connectionId: text('connection_id').notNull().unique(),
  lastHeartbeat: integer('last_heartbeat', { mode: 'timestamp' }).notNull(),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().default(sql`(unixepoch())`),
}, (table) => ({
  superuserIdx: index('sse_superuser_idx').on(table.superuserId),
  companyIdx: index('sse_company_idx').on(table.companyId),
  heartbeatIdx: index('sse_heartbeat_idx').on(table.lastHeartbeat),
}));