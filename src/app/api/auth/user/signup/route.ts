import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/app/db';
import { users, signupLinks, companies, registrationAttempts, userCompanies } from '@/app/db/schema';
import { eq, and } from 'drizzle-orm';
import {
  generateId,
  normalizePhoneNumber,
  isValidEmail,
  sanitizeInput,
  generateSecureToken,
} from '@/app/lib/security';
import { sendOTP } from '@/app/lib/otp-service';
import { checkRateLimit, auditAuthEvent } from '@/app/lib/rate-limit';
import { sendUserWelcomeMessage } from '@/app/lib/qr-service';

interface UserSignupRequest {
  signupCode: string;
  registrationToken?: string;
  email: string;
  phoneNumber: string;
  name: string;
}

/**
 * Step 1: Validate signup code (company QR code)
 * GET /api/auth/user/signup?code=xxx
 */
export async function GET(request: NextRequest) {
  const searchParams = request.url?.searchParams;
  const code = searchParams.get('code');
  const ipAddress = request.headers.get('x-forwarded-for') || 'unknown';
  const userAgent = request.headers.get('user-agent') || undefined;
  
  if (!code) {
    return NextResponse.json(
      { error: 'Signup code is required' },
      { status: 400 }
    );
  }
  
  try {
    // Find signup link
    const link = await db.query.signupLinks.findFirst({
      where: eq(signupLinks.code, code),
    });
    
    if (!link) {
      return NextResponse.json(
        { error: 'Invalid signup code' },
        { status: 404 }
      );
    }
    
    // Check if link is active
    if (!link.isActive) {
      return NextResponse.json(
        { error: 'This signup link is no longer active' },
        { status: 400 }
      );
    }
    
    // Check usage limit
    if (link.maxUses && link.useCount >= link.maxUses) {
      return NextResponse.json(
        { error: 'This signup link has reached its limit' },
        { status: 400 }
      );
    }
    
    // Get company details
    const company = await db.query.companies.findFirst({
      where: eq(companies.id, link.companyId),
    });
    
    if (!company || !company.isActive) {
      return NextResponse.json(
        {
          error: 'This company is no longer accepting signups',
          reason: 'inactive',
        },
        { status: 400 }
      );
    }
    
    // Generate unique registration token for this attempt
    const registrationToken = generateSecureToken();
    
    await db.insert(registrationAttempts).values({
      id: generateId('ra'),
      signupCode: code,
      companyId: company.id,
      registrationToken,
      ipAddress,
      userAgent,
      expiresAt: new Date(Date.now() + 30 * 60 * 1000), // 30 minutes
      createdAt: new Date(),
    });
    
    return NextResponse.json({
      valid: true,
      company: {
        id: company.id,
        name: company.name,
        description: company.description,
      },
      registrationToken,
    });
    
  } catch (error) {
    console.error('Validate signup code error:', error);
    return NextResponse.json(
      { error: 'An error occurred' },
      { status: 500 }
    );
  }
}

/**
 * Step 2: Complete user signup with company affiliation
 * POST /api/auth/user/signup
 */
export async function POST(request: NextRequest) {
  const ipAddress = request.headers.get('x-forwarded-for') || 'unknown';
  const userAgent = request.headers.get('user-agent') || undefined;
  
  try {
    // Rate limiting
    const rateLimitResult = await checkRateLimit(ipAddress, 'auth:signup');
    if (!rateLimitResult.allowed) {
      return NextResponse.json(
        { error: 'Too many signup attempts. Please try again later.' },
        { status: 429 }
      );
    }
    
    const body: UserSignupRequest = await request.json();
    
    // Validate input
    if (!body.email || !body.phoneNumber || !body.name || !body.signupCode) {
      return NextResponse.json(
        { error: 'All fields are required' },
        { status: 400 }
      );
    }
    
    if (!body.registrationToken) {
      return NextResponse.json(
        { error: 'Registration token is required' },
        { status: 400 }
      );
    }
    
    // Validate email
    if (!isValidEmail(body.email)) {
      return NextResponse.json(
        { error: 'Invalid email address' },
        { status: 400 }
      );
    }
    
    // Sanitize inputs
    const email = sanitizeInput(body.email.toLowerCase());
    const name = sanitizeInput(body.name);
    
    // Normalize phone number
    let phoneNumber: string;
    try {
      phoneNumber = normalizePhoneNumber(body.phoneNumber);
    } catch (error) {
      return NextResponse.json(
        { error: 'Invalid phone number format' },
        { status: 400 }
      );
    }
    
    // Verify registration token
    const registrationAttempt = await db.query.registrationAttempts.findFirst({
      where: and(
        eq(registrationAttempts.registrationToken, body.registrationToken),
        eq(registrationAttempts.signupCode, body.signupCode)
      ),
    });
    
    if (!registrationAttempt) {
      return NextResponse.json(
        { error: 'Invalid registration token' },
        { status: 400 }
      );
    }
    
    if (registrationAttempt.completed) {
      return NextResponse.json(
        { error: 'Registration token already used' },
        { status: 400 }
      );
    }
    
    if (new Date() > registrationAttempt.expiresAt) {
      return NextResponse.json(
        { error: 'Registration token expired. Please scan the QR code again.' },
        { status: 400 }
      );
    }
    
    // Get company
    const company = await db.query.companies.findFirst({
      where: eq(companies.id, registrationAttempt.companyId),
    });
    
    if (!company || !company.isActive) {
      return NextResponse.json(
        { error: 'This company is no longer accepting signups' },
        { status: 400 }
      );
    }
    
    // Check if email or phone already exists
    const existingByEmail = await db.query.users.findFirst({
      where: eq(users.email, email),
    });
    
    if (existingByEmail) {
      // User already exists - check if already affiliated with this company
      const existingAffiliation = await db.query.userCompanies.findFirst({
        where: and(
          eq(userCompanies.userId, existingByEmail.id),
          eq(userCompanies.companyId, company.id)
        ),
      });
      
      if (existingAffiliation) {
        return NextResponse.json(
          {
            error: 'You are already registered with this company',
            userId: existingByEmail.id,
          },
          { status: 400 }
        );
      }
      
      // User exists but not affiliated with this company
      // Create affiliation
      await db.insert(userCompanies).values({
        userId: existingByEmail.id,
        companyId: company.id,
        status: 'approved', // Auto-approve on signup
        affiliatedAt: new Date(),
        approvedAt: new Date(),
        createdAt: new Date(),
      });
      
      // Update signup link usage
      await db.execute(
        `UPDATE signup_links SET use_count = use_count + 1 WHERE id = ?`,
        [registrationAttempt.id]
      );
      
      // Mark registration attempt as completed
      await db.update(registrationAttempts)
        .set({
          completed: true,
          userId: existingByEmail.id,
        })
        .where(eq(registrationAttempts.id, registrationAttempt.id));
      
      return NextResponse.json({
        success: true,
        message: 'You have been added to this company',
        userId: existingByEmail.id,
        requiresOtp: false,
      });
    }
    
    const existingByPhone = await db.query.users.findFirst({
      where: eq(users.phoneNumber, phoneNumber),
    });
    
    if (existingByPhone) {
      // Same as email case
      const existingAffiliation = await db.query.userCompanies.findFirst({
        where: and(
          eq(userCompanies.userId, existingByPhone.id),
          eq(userCompanies.companyId, company.id)
        ),
      });
      
      if (existingAffiliation) {
        return NextResponse.json(
          {
            error: 'You are already registered with this company',
            userId: existingByPhone.id,
          },
          { status: 400 }
        );
      }
      
      await db.insert(userCompanies).values({
        userId: existingByPhone.id,
        companyId: company.id,
        status: 'approved',
        affiliatedAt: new Date(),
        approvedAt: new Date(),
        createdAt: new Date(),
      });
      
      await db.execute(
        `UPDATE signup_links SET use_count = use_count + 1 WHERE id = ?`,
        [registrationAttempt.id]
      );
      
      await db.update(registrationAttempts)
        .set({
          completed: true,
          userId: existingByPhone.id,
        })
        .where(eq(registrationAttempts.id, registrationAttempt.id));
      
      return NextResponse.json({
        success: true,
        message: 'You have been added to this company',
        userId: existingByPhone.id,
        requiresOtp: false,
      });
    }
    
    // New user - create account
    const userId = generateId('u');
    
    // Create user with transaction
    try {
      await db.transaction(async (tx) => {
        // Insert user
        await tx.insert(users).values({
          id: userId,
          email,
          phoneNumber,
          name,
          isActive: false, // Not active until phone verified
          createdAt: new Date(),
        });
        
        // Create company affiliation
        await tx.insert(userCompanies).values({
          userId,
          companyId: company.id,
          status: 'approved', // Auto-approve on signup
          affiliatedAt: new Date(),
          approvedAt: new Date(),
          createdAt: new Date(),
        });
        
        // Update signup link usage
        await tx.execute(
          `UPDATE signup_links SET use_count = use_count + 1 WHERE code = ?`,
          [body.signupCode]
        );
        
        // Mark registration attempt as completed
        await tx.update(registrationAttempts)
          .set({
            completed: true,
            userId,
          })
          .where(eq(registrationAttempts.id, registrationAttempt.id));
      });
    } catch (error: any) {
      if (error.code === 'SQLITE_CONSTRAINT') {
        return NextResponse.json(
          { error: 'Email or phone number already registered' },
          { status: 400 }
        );
      }
      throw error;
    }
    
    // Send OTP for verification
    const otpResult = await sendOTP(phoneNumber);
    
    if (!otpResult.success) {
      // Rollback - delete the user
      await db.delete(users).where(eq(users.id, userId));
      
      return NextResponse.json(
        { error: otpResult.message },
        { status: 500 }
      );
    }
    
    // Send WhatsApp welcome message (async)
    sendUserWelcomeMessage(
      phoneNumber,
      name,
      company.name
    ).catch(err => console.error('Failed to send welcome message:', err));
    
    // Audit log
    await auditAuthEvent('signup', {
      userId,
      phoneNumber,
      ipAddress,
      userAgent,
      success: true,
    });
    
    return NextResponse.json({
      success: true,
      message: 'Signup successful. Please verify your phone number.',
      userId,
      requiresOtp: true,
    });
    
  } catch (error) {
    console.error('User signup error:', error);
    
    await auditAuthEvent('signup', {
      userId: undefined,
      phoneNumber: undefined,
      ipAddress,
      userAgent,
      success: false,
      errorMessage: error instanceof Error ? error.message : 'Unknown error',
    });
    
    return NextResponse.json(
      { error: 'An error occurred during signup' },
      { status: 500 }
    );
  }
}