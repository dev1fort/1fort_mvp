import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/app/db';
import { superusers } from '@/app/db/schema';
import { eq } from 'drizzle-orm';
import {
  generateId,
  normalizePhoneNumber,
  isValidEmail,
  sanitizeInput,
} from '@/app/lib/security';
import { sendOTP } from '@/app/lib/otp-service';
import { checkRateLimit, auditAuthEvent } from '@/app/lib/rate-limit';

interface SuperuserSignupRequest {
  email: string;
  phoneNumber: string;
  name: string;
}

/**
 * Superuser Signup
 * Creates superuser account - NO QR code generation
 */
export async function POST(request: NextRequest) {
  const ipAddress = request.headers.get('x-forwarded-for') || 
                    request.headers.get('x-real-ip') || 
                    'unknown';
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
    
    const body: SuperuserSignupRequest = await request.json();
    
    // Validate input
    if (!body.email || !body.phoneNumber || !body.name) {
      return NextResponse.json(
        { error: 'All fields are required' },
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
    
    // Check if email or phone already exists
    const existingByEmail = await db.query.superusers.findFirst({
      where: eq(superusers.email, email),
    });
    
    if (existingByEmail) {
      await auditAuthEvent('signup', {
        superuserId: undefined,
        phoneNumber,
        ipAddress,
        userAgent,
        success: false,
        errorMessage: 'Email already registered',
      });
      
      return NextResponse.json(
        { error: 'Email already registered' },
        { status: 400 }
      );
    }
    
    const existingByPhone = await db.query.superusers.findFirst({
      where: eq(superusers.phoneNumber, phoneNumber),
    });
    
    if (existingByPhone) {
      await auditAuthEvent('signup', {
        superuserId: undefined,
        phoneNumber,
        ipAddress,
        userAgent,
        success: false,
        errorMessage: 'Phone number already registered',
      });
      
      return NextResponse.json(
        { error: 'Phone number already registered' },
        { status: 400 }
      );
    }
    
    const superuserId = generateId('su');
    
    // Create superuser record
    try {
      await db.insert(superusers).values({
        id: superuserId,
        email,
        phoneNumber,
        name,
        isActive: false, // Not active until phone verified
        createdAt: new Date(),
      });
    } catch (error: any) {
      // Check for unique constraint violation
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
      // Rollback - delete the superuser
      await db.delete(superusers).where(eq(superusers.id, superuserId));
      
      return NextResponse.json(
        { error: otpResult.message },
        { status: 500 }
      );
    }
    
    // Audit log
    await auditAuthEvent('signup', {
      superuserId,
      phoneNumber,
      ipAddress,
      userAgent,
      success: true,
    });
    
    return NextResponse.json({
      success: true,
      message: 'Signup successful. Please verify your phone number.',
      superuserId,
      requiresOtp: true,
    });
    
  } catch (error) {
    console.error('Superuser signup error:', error);
    
    await auditAuthEvent('signup', {
      superuserId: undefined,
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