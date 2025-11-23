import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/db';
import { companies, signupLinks, superusers } from '@/db/schema';
import { eq } from 'drizzle-orm';
import { verifyAccessToken } from '@/lib/token-service';
import { checkRateLimit, createAuditLog } from '@/lib/rate-limit';
import {
  generateId,
  sanitizeInput,
  generateSignupCode,
} from '@/lib/security';
import {
  generateSignupQRCode,
  sendSuperuserSignupQR,
  uploadQRCodeImage,
} from '@/lib/qr-service';

interface CreateCompanyRequest {
  name: string;
  description?: string;
}

/**
 * Create Company
 * Superuser creates a new company and gets a QR code for it
 * POST /api/companies
 */
export async function POST(request: NextRequest) {
  const ipAddress = request.headers.get('x-forwarded-for') || 'unknown';
  const userAgent = request.headers.get('user-agent') || undefined;
  
  try {
    // Verify authentication
    const authHeader = request.headers.get('authorization');
    const accessToken = authHeader?.replace('Bearer ', '');
    
    if (!accessToken) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }
    
    const decoded = verifyAccessToken(accessToken);
    
    if (!decoded || !decoded.superuserId) {
      return NextResponse.json(
        { error: 'Unauthorized - Superusers only' },
        { status: 401 }
      );
    }
    
    // Rate limiting
    const rateLimitResult = await checkRateLimit(
      decoded.superuserId,
      'company:create'
    );
    if (!rateLimitResult.allowed) {
      return NextResponse.json(
        { error: 'Too many company creation requests' },
        { status: 429 }
      );
    }
    
    const body: CreateCompanyRequest = await request.json();
    
    if (!body.name) {
      return NextResponse.json(
        { error: 'Company name is required' },
        { status: 400 }
      );
    }
    
    // Sanitize inputs
    const name = sanitizeInput(body.name);
    const description = body.description ? sanitizeInput(body.description) : null;
    
    // Get superuser details
    const superuser = await db.query.superusers.findFirst({
      where: eq(superusers.id, decoded.superuserId),
    });
    
    if (!superuser) {
      return NextResponse.json(
        { error: 'Superuser not found' },
        { status: 404 }
      );
    }
    
    // Generate QR code for this company
    const baseUrl = process.env.NEXT_PUBLIC_BASE_URL || 'http://localhost:3000';
    const companyId = generateId('comp');
    const signupLinkId = generateSignupCode();
    
    const qrCodeData = await generateSignupQRCode(baseUrl, signupLinkId);
    
    // Upload QR code image for WhatsApp
    const qrCodeUrl = await uploadQRCodeImage(
      qrCodeData.qrCodeDataUrl,
      `company-${companyId}.png`
    );
    
    // Create company with transaction
    try {
      await db.transaction(async (tx) => {
        // Insert company
        await tx.insert(companies).values({
          id: companyId,
          superuserId: superuser.id,
          name,
          description,
          signupQrCode: qrCodeData.qrCodeDataUrl,
          signupLinkId,
          isActive: true,
          createdAt: new Date(),
        });
        
        // Create signup link
        await tx.insert(signupLinks).values({
          id: generateId('sl'),
          companyId,
          code: signupLinkId,
          maxUses: null, // Unlimited uses
          useCount: 0,
          isActive: true,
          createdAt: new Date(),
        });
      });
    } catch (error: any) {
      console.error('Company creation error:', error);
      throw error;
    }
    
    // Send WhatsApp message with QR code (async)
    sendSuperuserSignupQR(
      superuser.phoneNumber,
      name,
      qrCodeUrl,
      qrCodeData.url
    ).catch(err => console.error('Failed to send WhatsApp QR:', err));
    
    // Audit log
    await createAuditLog({
      superuserId: superuser.id,
      companyId,
      action: 'company:create',
      resource: 'company',
      resourceId: companyId,
      ipAddress,
      userAgent,
      metadata: { name, description },
      success: true,
    });
    
    return NextResponse.json({
      success: true,
      message: 'Company created successfully',
      company: {
        id: companyId,
        name,
        description,
        signupUrl: qrCodeData.url,
        qrCodeDataUrl: qrCodeData.qrCodeDataUrl,
      },
    });
    
  } catch (error) {
    console.error('Create company error:', error);
    
    return NextResponse.json(
      { error: 'An error occurred while creating company' },
      { status: 500 }
    );
  }
}

/**
 * Get Companies
 * List all companies for the authenticated superuser
 * GET /api/companies
 */
export async function GET(request: NextRequest) {
  try {
    // Verify authentication
    const authHeader = request.headers.get('authorization');
    const accessToken = authHeader?.replace('Bearer ', '');
    
    if (!accessToken) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }
    
    const decoded = verifyAccessToken(accessToken);
    
    if (!decoded || !decoded.superuserId) {
      return NextResponse.json(
        { error: 'Unauthorized - Superusers only' },
        { status: 401 }
      );
    }
    
    // Get all companies for this superuser
    const userCompanies = await db.query.companies.findMany({
      where: eq(companies.superuserId, decoded.superuserId),
      orderBy: (companies, { desc }) => [desc(companies.createdAt)],
    });
    
    return NextResponse.json({
      success: true,
      companies: userCompanies.map(company => ({
        id: company.id,
        name: company.name,
        description: company.description,
        isActive: company.isActive,
        signupUrl: `${process.env.NEXT_PUBLIC_BASE_URL}/signup?code=${company.signupLinkId}`,
        qrCodeDataUrl: company.signupQrCode,
        createdAt: company.createdAt.toISOString(),
      })),
    });
    
  } catch (error) {
    console.error('Get companies error:', error);
    return NextResponse.json(
      { error: 'An error occurred' },
      { status: 500 }
    );
  }
}