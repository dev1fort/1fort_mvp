import QRCode from 'qrcode';
import { generateSignupCode } from './security';

interface QRCodeData {
  code: string;
  url: string;
  qrCodeDataUrl: string;
}

/**
 * Generates a permanent signup QR code for a company
 */
export async function generateSignupQRCode(
  baseUrl: string,
  signupLinkId: string
): Promise<QRCodeData> {
  const url = `${baseUrl}/signup?code=${signupLinkId}`;
  
  // Generate QR code as data URL
  const qrCodeDataUrl = await QRCode.toDataURL(url, {
    errorCorrectionLevel: 'H',
    type: 'image/png',
    width: 400,
    margin: 2,
    color: {
      dark: '#000000',
      light: '#FFFFFF',
    },
  });
  
  return {
    code: signupLinkId,
    url,
    qrCodeDataUrl,
  };
}

/**
 * Generates appointment confirmation QR code
 */
export async function generateAppointmentQRCode(
  baseUrl: string,
  appointmentId: string
): Promise<string> {
  const url = `${baseUrl}/appointment/verify?id=${appointmentId}`;
  
  const qrCodeDataUrl = await QRCode.toDataURL(url, {
    errorCorrectionLevel: 'H',
    type: 'image/png',
    width: 300,
    margin: 2,
  });
  
  return qrCodeDataUrl;
}

/**
 * Converts data URL to buffer for sending via WhatsApp
 */
export function dataUrlToBuffer(dataUrl: string): Buffer {
  const base64Data = dataUrl.split(',')[1];
  return Buffer.from(base64Data, 'base64');
}

// WhatsApp Business API Integration
interface WhatsAppConfig {
  apiUrl: string;
  accessToken: string;
  phoneNumberId: string;
}

const whatsappConfig: WhatsAppConfig = {
  apiUrl: process.env.WHATSAPP_API_URL || 'https://graph.facebook.com/v17.0',
  accessToken: process.env.WHATSAPP_ACCESS_TOKEN || '',
  phoneNumberId: process.env.WHATSAPP_PHONE_NUMBER_ID || '',
};

/**
 * Sends a text message via WhatsApp
 */
async function sendWhatsAppMessage(
  to: string,
  message: string
): Promise<boolean> {
  try {
    const response = await fetch(
      `${whatsappConfig.apiUrl}/${whatsappConfig.phoneNumberId}/messages`,
      {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${whatsappConfig.accessToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          messaging_product: 'whatsapp',
          to: to.replace('+', ''),
          type: 'text',
          text: { body: message },
        }),
      }
    );
    
    if (!response.ok) {
      console.error('WhatsApp message failed:', await response.text());
      return false;
    }
    
    return true;
  } catch (error) {
    console.error('WhatsApp message error:', error);
    return false;
  }
}

/**
 * Sends an image via WhatsApp
 */
async function sendWhatsAppImage(
  to: string,
  imageUrl: string,
  caption?: string
): Promise<boolean> {
  try {
    const response = await fetch(
      `${whatsappConfig.apiUrl}/${whatsappConfig.phoneNumberId}/messages`,
      {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${whatsappConfig.accessToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          messaging_product: 'whatsapp',
          to: to.replace('+', ''),
          type: 'image',
          image: {
            link: imageUrl,
            caption: caption,
          },
        }),
      }
    );
    
    if (!response.ok) {
      console.error('WhatsApp image failed:', await response.text());
      return false;
    }
    
    return true;
  } catch (error) {
    console.error('WhatsApp image error:', error);
    return false;
  }
}

/**
 * Sends company QR code to superuser via WhatsApp
 */
export async function sendSuperuserSignupQR(
  phoneNumber: string,
  companyName: string,
  qrCodeUrl: string,
  signupUrl: string
): Promise<boolean> {
  const message = `🏢 ${companyName} - Signup QR Code Ready!\n\nYour permanent signup QR code for ${companyName} is ready. Share this with your customers to let them sign up.\n\n📱 Signup Link: ${signupUrl}\n\nYou can also download the QR code from your dashboard.`;
  
  // First send the message
  const textSent = await sendWhatsAppMessage(phoneNumber, message);
  
  if (!textSent) {
    return false;
  }
  
  // Then send the QR code image
  const imageSent = await sendWhatsAppImage(
    phoneNumber,
    qrCodeUrl,
    `${companyName} - Share this QR code with customers`
  );
  
  return imageSent;
}

/**
 * Sends welcome message to new user via WhatsApp
 */
export async function sendUserWelcomeMessage(
  phoneNumber: string,
  userName: string,
  companyName: string
): Promise<boolean> {
  const message = `👋 Welcome ${userName}!\n\nThank you for signing up with ${companyName}. You can now book appointments and manage your bookings through our app.\n\nIf you need any help, feel free to contact us.`;
  
  return await sendWhatsAppMessage(phoneNumber, message);
}

/**
 * Sends appointment confirmation to user via WhatsApp
 */
export async function sendAppointmentConfirmation(
  phoneNumber: string,
  userName: string,
  appointmentDetails: {
    date: Date;
    companyName: string;
    details?: string;
  },
  qrCodeUrl: string
): Promise<boolean> {
  const dateStr = appointmentDetails.date.toLocaleString('en-US', {
    dateStyle: 'full',
    timeStyle: 'short',
  });
  
  const message = `✅ Appointment Confirmed!\n\nHi ${userName},\n\nYour appointment with ${appointmentDetails.companyName} has been confirmed.\n\n📅 Date & Time: ${dateStr}\n${appointmentDetails.details ? `\n📝 Details: ${appointmentDetails.details}` : ''}\n\nPlease show the QR code below when you arrive.`;
  
  // Send message first
  const textSent = await sendWhatsAppMessage(phoneNumber, message);
  
  if (!textSent) {
    return false;
  }
  
  // Send QR code
  const imageSent = await sendWhatsAppImage(
    phoneNumber,
    qrCodeUrl,
    'Show this QR code at your appointment'
  );
  
  return imageSent;
}

/**
 * Sends appointment approval notification to superuser
 */
export async function sendAppointmentNotification(
  phoneNumber: string,
  userName: string,
  appointmentDate: Date,
  companyName: string
): Promise<boolean> {
  const dateStr = appointmentDate.toLocaleString('en-US', {
    dateStyle: 'full',
    timeStyle: 'short',
  });
  
  const message = `🔔 New Appointment Request - ${companyName}\n\n${userName} has requested an appointment for ${dateStr}.\n\nPlease review and approve/reject in your dashboard.`;
  
  return await sendWhatsAppMessage(phoneNumber, message);
}

/**
 * Uploads image to your server for WhatsApp
 * WhatsApp requires publicly accessible URLs
 */
export async function uploadQRCodeImage(
  qrCodeDataUrl: string,
  filename: string
): Promise<string> {
  // This is a placeholder - implement based on your storage solution
  // You could use AWS S3, Cloudinary, or your own server
  
  const buffer = dataUrlToBuffer(qrCodeDataUrl);
  
  // TODO: Upload to your preferred storage service
  // For now, return a placeholder URL
  const baseUrl = process.env.NEXT_PUBLIC_BASE_URL || 'http://localhost:3000';
  return `${baseUrl}/api/qr-codes/${filename}`;
}