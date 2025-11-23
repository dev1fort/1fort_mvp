import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/app/db';
import { appointments, users, companies, userCompanies } from '@/app/db/schema';
import { eq, and } from 'drizzle-orm';
import { verifyAccessToken } from '@/app/lib/token-service';
import { checkRateLimit, createAuditLog } from '@/app/lib/rate-limit';
import { notifySuperuserNewAppointment } from '@/app/lib/sse-service';
import { sendAppointmentNotification } from '@/app/lib/qr-service';
import { generateId } from '@/app/lib/security';

interface CreateAppointmentRequest {
  companyId: string;
  appointmentDate: string;
  details?: string;
}

// create appointment
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
    
    if (!decoded || !decoded.userId) {
      return NextResponse.json(
        { error: 'Unauthorized - Users only' },
        { status: 401 }
      );
    }
    
    // Rate limiting
    const rateLimitResult = await checkRateLimit(
      decoded.userId,
      'appointment:create'
    );
    if (!rateLimitResult.allowed) {
      return NextResponse.json(
        { error: 'Too many appointment requests' },
        { status: 429 }
      );
    }
    
    const body: CreateAppointmentRequest = await request.json();
    
    if (!body.appointmentDate || !body.companyId) {
      return NextResponse.json(
        { error: 'Appointment date and company are required' },
        { status: 400 }
      );
    }
    
    // Validate date is in the future
    const date = new Date(body.appointmentDate);
    if (date < new Date()) {
      return NextResponse.json(
        { error: 'Appointment date must be in the future' },
        { status: 400 }
      );
    }
    
    // Get user details
    const user = await db.query.users.findFirst({
      where: eq(users.id, decoded.userId),
    });
    
    if (!user) {
      return NextResponse.json(
        { error: 'User not found' },
        { status: 404 }
      );
    }
    
    // Get company details
    const company = await db.query.companies.findFirst({
      where: eq(companies.id, body.companyId),
    });
    
    if (!company || !company.isActive) {
      return NextResponse.json(
        { error: 'Company not found or inactive' },
        { status: 404 }
      );
    }
    
    // Check if user is affiliated with this company
    const affiliation = await db.query.userCompanies.findFirst({
      where: and(
        eq(userCompanies.userId, user.id),
        eq(userCompanies.companyId, company.id)
      ),
    });
    
    if (!affiliation) {
      return NextResponse.json(
        {
          error: 'You are not affiliated with this company. Please sign up first.',
          companyName: company.name,
        },
        { status: 403 }
      );
    }
    
    // Create appointment
    const appointmentId = generateId('appt');
    
    await db.insert(appointments).values({
      id: appointmentId,
      userId: user.id,
      companyId: company.id,
      superuserId: company.superuserId,
      appointmentDate: date,
      details: body.details || null,
      status: 'pending',
      createdAt: new Date(),
      updatedAt: new Date(),
    });
    
    // Send SSE notification to superuser (company-specific)
    notifySuperuserNewAppointment(company.superuserId, {
      id: appointmentId,
      userId: user.id,
      userName: user.name,
      userPhone: user.phoneNumber,
      appointmentDate: date,
      details: body.details,
      companyId: company.id,
      companyName: company.name,
    }).catch(err => console.error('SSE notification failed:', err));
    
    // Send WhatsApp notification to superuser
    sendAppointmentNotification(
      // TODO: Get superuser phone from companies.superuserId
      '+1234567890', // Placeholder
      user.name,
      date,
      company.name
    ).catch(err => console.error('WhatsApp notification failed:', err));
    
    // Audit log
    await createAuditLog({
      userId: user.id,
      superuserId: company.superuserId,
      companyId: company.id,
      action: 'appointment:create',
      resource: 'appointment',
      resourceId: appointmentId,
      ipAddress,
      userAgent,
      metadata: { appointmentDate: date.toISOString(), details: body.details },
      success: true,
    });
    
    return NextResponse.json({
      success: true,
      appointment: {
        id: appointmentId,
        companyId: company.id,
        companyName: company.name,
        appointmentDate: date.toISOString(),
        status: 'pending',
        details: body.details,
      },
    });
    
  } catch (error) {
    console.error('Create appointment error:', error);
    return NextResponse.json(
      { error: 'An error occurred' },
      { status: 500 }
    );
  }
}

/**
 * Get User's Appointments
 * GET /api/appointments
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
    
    if (!decoded || !decoded.userId) {
      return NextResponse.json(
        { error: 'Unauthorized - Users only' },
        { status: 401 }
      );
    }
    
    // Get query parameters
    const url = new URL(request.url);
    const companyId = url.searchParams.get('companyId');
    const status = url.searchParams.get('status');
    
    // Build query
    let query = db.query.appointments.findMany({
      where: eq(appointments.userId, decoded.userId),
      orderBy: (appointments, { desc }) => [desc(appointments.appointmentDate)],
    });
    
    const userAppointments = await query;
    
    // Filter by company if specified
    let filteredAppointments = userAppointments;
    if (companyId) {
      filteredAppointments = userAppointments.filter(a => a.companyId === companyId);
    }
    if (status) {
      filteredAppointments = filteredAppointments.filter(a => a.status === status);
    }
    
    // Get company details for each appointment
    const appointmentsWithCompany = await Promise.all(
      filteredAppointments.map(async (appointment) => {
        const company = await db.query.companies.findFirst({
          where: eq(companies.id, appointment.companyId),
        });
        
        return {
          id: appointment.id,
          companyId: appointment.companyId,
          companyName: company?.name,
          appointmentDate: appointment.appointmentDate.toISOString(),
          status: appointment.status,
          details: appointment.details,
          approvedAt: appointment.approvedAt?.toISOString(),
          createdAt: appointment.createdAt.toISOString(),
        };
      })
    );
    
    return NextResponse.json({
      success: true,
      appointments: appointmentsWithCompany,
    });
    
  } catch (error) {
    console.error('Get appointments error:', error);
    return NextResponse.json(
      { error: 'An error occurred' },
      { status: 500 }
    );
  }
}