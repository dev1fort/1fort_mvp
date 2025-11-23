import { db } from '@/app/db';
import { sseConnections } from '@/app/db/schema';
import { eq, lt, and } from 'drizzle-orm';
import { generateId } from '@/app/lib/security';

interface SSEConnection {
  id: string;
  superuserId: string;
  companyId: string | null;
  response: Response;
  controller: ReadableStreamDefaultController;
}

// In-memory store for active SSE connections
const activeConnections = new Map<string, SSEConnection>();

/**
 * Creates a new SSE connection for superuser
 * Can optionally filter by company
 */
export function createSSEConnection(
  superuserId: string,
  request: Request,
  companyId?: string
): Response {
  const connectionId = generateId('sse');
  
  // Create a readable stream for SSE
  const stream = new ReadableStream({
    start(controller) {
      // Store connection
      const connection: SSEConnection = {
        id: connectionId,
        superuserId,
        companyId: companyId || null,
        response: new Response(),
        controller,
      };
      
      activeConnections.set(connectionId, connection);
      
      // Store in database
      db.insert(sseConnections).values({
        id: generateId('sse_rec'),
        superuserId,
        companyId: companyId || null,
        connectionId,
        lastHeartbeat: new Date(),
        createdAt: new Date(),
      }).catch(err => console.error('Failed to store SSE connection:', err));
      
      // Send initial connection message
      sendSSEMessage(controller, {
        type: 'connected',
        data: { 
          connectionId,
          companyId: companyId || null,
        },
      });
      
      // Setup heartbeat to keep connection alive
      const heartbeatInterval = setInterval(() => {
        try {
          sendSSEMessage(controller, {
            type: 'heartbeat',
            data: { timestamp: Date.now() },
          });
          
          // Update database heartbeat
          db.update(sseConnections)
            .set({ lastHeartbeat: new Date() })
            .where(eq(sseConnections.connectionId, connectionId))
            .catch(err => console.error('Failed to update heartbeat:', err));
        } catch (error) {
          console.error('Heartbeat failed:', error);
          clearInterval(heartbeatInterval);
          cleanup();
        }
      }, 30000); // Every 30 seconds
      
      // Cleanup on close
      const cleanup = () => {
        clearInterval(heartbeatInterval);
        activeConnections.delete(connectionId);
        
        // Remove from database
        db.delete(sseConnections)
          .where(eq(sseConnections.connectionId, connectionId))
          .catch(err => console.error('Failed to delete SSE connection:', err));
      };
      
      // Handle client disconnect
      request.signal.addEventListener('abort', cleanup);
    },
  });
  
  return new Response(stream, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no', // Disable nginx buffering
    },
  });
}

interface SSEMessage {
  type: string;
  data: any;
  id?: string;
}

/**
 * Sends a message through SSE
 */
function sendSSEMessage(
  controller: ReadableStreamDefaultController,
  message: SSEMessage
): void {
  const id = message.id || generateId('msg');
  const data = JSON.stringify(message.data);
  
  const formattedMessage = `id: ${id}\nevent: ${message.type}\ndata: ${data}\n\n`;
  
  controller.enqueue(new TextEncoder().encode(formattedMessage));
}

/**
 * Sends appointment notification to superuser (company-aware)
 */
export async function notifySuperuserNewAppointment(
  superuserId: string,
  appointmentData: {
    id: string;
    userId: string;
    userName: string;
    userPhone: string;
    appointmentDate: Date;
    details?: string;
    companyId: string;
    companyName: string;
  }
): Promise<boolean> {
  // Find active connections for this superuser
  // Filter by company if the connection is company-specific
  const connections = Array.from(activeConnections.values()).filter(
    conn => {
      if (conn.superuserId !== superuserId) return false;
      
      // If connection has a company filter, only send if it matches
      if (conn.companyId && conn.companyId !== appointmentData.companyId) {
        return false;
      }
      
      return true;
    }
  );
  
  if (connections.length === 0) {
    console.log('No active SSE connections for superuser:', superuserId);
    return false;
  }
  
  // Send notification to all matching connections
  const message: SSEMessage = {
    type: 'appointment:new',
    data: {
      appointment: {
        id: appointmentData.id,
        userId: appointmentData.userId,
        userName: appointmentData.userName,
        userPhone: appointmentData.userPhone,
        date: appointmentData.appointmentDate.toISOString(),
        details: appointmentData.details,
        companyId: appointmentData.companyId,
        companyName: appointmentData.companyName,
      },
      timestamp: Date.now(),
    },
  };
  
  connections.forEach(conn => {
    try {
      sendSSEMessage(conn.controller, message);
    } catch (error) {
      console.error('Failed to send SSE message:', error);
    }
  });
  
  return true;
}

/**
 * Sends appointment approval confirmation
 */
export async function notifyAppointmentStatusChange(
  superuserId: string,
  companyId: string,
  appointmentData: {
    id: string;
    status: 'approved' | 'rejected';
    userId: string;
    userName: string;
  }
): Promise<boolean> {
  const connections = Array.from(activeConnections.values()).filter(
    conn => {
      if (conn.superuserId !== superuserId) return false;
      if (conn.companyId && conn.companyId !== companyId) return false;
      return true;
    }
  );
  
  const message: SSEMessage = {
    type: 'appointment:status',
    data: {
      appointmentId: appointmentData.id,
      status: appointmentData.status,
      userId: appointmentData.userId,
      userName: appointmentData.userName,
      companyId,
      timestamp: Date.now(),
    },
  };
  
  connections.forEach(conn => {
    try {
      sendSSEMessage(conn.controller, message);
    } catch (error) {
      console.error('Failed to send SSE message:', error);
    }
  });
  
  return true;
}

/**
 * Broadcasts a message to all superuser connections for a specific company
 */
export async function broadcastToCompany(
  superuserId: string,
  companyId: string,
  message: SSEMessage
): Promise<void> {
  const connections = Array.from(activeConnections.values()).filter(
    conn => {
      if (conn.superuserId !== superuserId) return false;
      if (conn.companyId && conn.companyId !== companyId) return false;
      return true;
    }
  );
  
  connections.forEach(conn => {
    try {
      sendSSEMessage(conn.controller, message);
    } catch (error) {
      console.error('Failed to broadcast SSE message:', error);
    }
  });
}

/**
 * Closes a specific SSE connection
 */
export function closeSSEConnection(connectionId: string): void {
  const connection = activeConnections.get(connectionId);
  
  if (connection) {
    try {
      connection.controller.close();
    } catch (error) {
      console.error('Error closing SSE connection:', error);
    }
    
    activeConnections.delete(connectionId);
    
    // Remove from database
    db.delete(sseConnections)
      .where(eq(sseConnections.connectionId, connectionId))
      .catch(err => console.error('Failed to delete SSE connection:', err));
  }
}

/**
 * Cleans up stale SSE connections (run periodically)
 */
export async function cleanupStaleSSEConnections(): Promise<void> {
  const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
  
  // Find stale connections in database
  const staleConnections = await db.query.sseConnections.findMany({
    where: lt(sseConnections.lastHeartbeat, fiveMinutesAgo),
  });
  
  // Remove them
  for (const conn of staleConnections) {
    closeSSEConnection(conn.connectionId);
  }
  
  // Clean up database
  await db.delete(sseConnections)
    .where(lt(sseConnections.lastHeartbeat, fiveMinutesAgo));
}

/**
 * Gets count of active SSE connections for a superuser
 */
export function getActiveConnectionCount(
  superuserId: string,
  companyId?: string
): number {
  return Array.from(activeConnections.values()).filter(
    conn => {
      if (conn.superuserId !== superuserId) return false;
      if (companyId && conn.companyId !== companyId) return false;
      return true;
    }
  ).length;
}

/**
 * Gets all companies with active connections for a superuser
 */
export function getConnectedCompanies(superuserId: string): string[] {
  const companyIds = new Set<string>();
  
  Array.from(activeConnections.values())
    .filter(conn => conn.superuserId === superuserId)
    .forEach(conn => {
      if (conn.companyId) {
        companyIds.add(conn.companyId);
      }
    });
  
  return Array.from(companyIds);
}