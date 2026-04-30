import { Injectable, Logger, NotFoundException, ForbiddenException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import * as crypto from 'crypto';
// Simple user agent parsing (no external dependency)
import {
  SessionDto,
  SessionListQueryDto,
  SessionStatsDto,
  SessionSettingsDto,
  UpdateSessionSettingsDto,
} from './dto/session.dto';
import { 
  parsePaginationParams, 
  createPaginatedResponse,
} from '@gigachad-grc/shared';

interface SessionRecord {
  id: string;
  userId: string;
  organizationId: string;
  deviceInfo: string;
  browser: string;
  os: string;
  ipAddress: string;
  userAgent: string;
  isActive: boolean;
  createdAt: Date;
  lastActivityAt: Date;
  expiresAt: Date;
}

interface SessionSettings {
  sessionTimeoutMinutes: number;
  maxConcurrentSessions: number;
  enforceSingleSession: boolean;
  requireReauthForSensitiveActions: boolean;
}

// In-memory stores (would be Redis/database in production)
const sessionStore = new Map<string, SessionRecord>();
const settingsStore = new Map<string, SessionSettings>();

const DEFAULT_SETTINGS: SessionSettings = {
  sessionTimeoutMinutes: 480, // 8 hours
  maxConcurrentSessions: 5,
  enforceSingleSession: false,
  requireReauthForSensitiveActions: true,
};

@Injectable()
export class SessionsService {
  private readonly logger = new Logger(SessionsService.name);

  constructor(private readonly prisma: PrismaService) {}

  async createSession(
    userId: string,
    organizationId: string,
    ipAddress: string,
    userAgent: string,
  ): Promise<SessionDto> {
    const settings = this.getSettings(organizationId);
    const { browser, os, device } = this.parseUserAgent(userAgent);

    // Enforce session limits
    const userSessions = Array.from(sessionStore.values())
      .filter(s => s.userId === userId && s.isActive);

    if (settings.enforceSingleSession && userSessions.length > 0) {
      // Invalidate all existing sessions
      for (const session of userSessions) {
        session.isActive = false;
        sessionStore.set(session.id, session);
      }
      this.logger.log(`Enforced single session for user ${userId}, invalidated ${userSessions.length} sessions`);
    } else if (userSessions.length >= settings.maxConcurrentSessions) {
      // Remove oldest session
      const oldest = userSessions.sort((a, b) => 
        a.lastActivityAt.getTime() - b.lastActivityAt.getTime()
      )[0];
      oldest.isActive = false;
      sessionStore.set(oldest.id, oldest);
      this.logger.log(`Session limit reached for user ${userId}, removed oldest session`);
    }

    const now = new Date();
    const expiresAt = new Date(now.getTime() + settings.sessionTimeoutMinutes * 60 * 1000);

    const session: SessionRecord = {
      id: crypto.randomUUID(),
      userId,
      organizationId,
      deviceInfo: device,
      browser,
      os,
      ipAddress,
      userAgent,
      isActive: true,
      createdAt: now,
      lastActivityAt: now,
      expiresAt,
    };

    sessionStore.set(session.id, session);
    this.logger.log(`Created session ${session.id} for user ${userId}`);

    return this.toDto(session, session.id);
  }

  async getUserSessions(
    organizationId: string,
    userId: string,
    currentSessionId: string,
    query: SessionListQueryDto,
  ) {
    const pagination = parsePaginationParams({
      page: query.page,
      limit: query.limit,
    });

    let sessions = Array.from(sessionStore.values())
      .filter(s => s.organizationId === organizationId && s.userId === userId);

    if (query.activeOnly) {
      sessions = sessions.filter(s => s.isActive && s.expiresAt > new Date());
    }

    // Sort by last activity (most recent first)
    sessions.sort((a, b) => b.lastActivityAt.getTime() - a.lastActivityAt.getTime());

    const total = sessions.length;
    const offset = (pagination.page - 1) * pagination.limit;
    const paginatedSessions = sessions.slice(offset, offset + pagination.limit);

    const dtos = paginatedSessions.map(s => this.toDto(s, currentSessionId));

    return createPaginatedResponse(dtos, total, pagination);
  }

  async getAllSessions(
    organizationId: string,
    query: SessionListQueryDto,
  ) {
    const pagination = parsePaginationParams({
      page: query.page,
      limit: query.limit,
    });

    let sessions = Array.from(sessionStore.values())
      .filter(s => s.organizationId === organizationId);

    if (query.activeOnly) {
      sessions = sessions.filter(s => s.isActive && s.expiresAt > new Date());
    }

    if (query.userId) {
      sessions = sessions.filter(s => s.userId === query.userId);
    }

    sessions.sort((a, b) => b.lastActivityAt.getTime() - a.lastActivityAt.getTime());

    const total = sessions.length;
    const offset = (pagination.page - 1) * pagination.limit;
    const paginatedSessions = sessions.slice(offset, offset + pagination.limit);

    const dtos = paginatedSessions.map(s => this.toDto(s, ''));

    return createPaginatedResponse(dtos, total, pagination);
  }

  async invalidateSession(
    organizationId: string,
    sessionId: string,
    currentSessionId: string,
    reason?: string,
  ): Promise<void> {
    const session = sessionStore.get(sessionId);
    if (!session || session.organizationId !== organizationId) {
      throw new NotFoundException(`Session ${sessionId} not found`);
    }

    if (sessionId === currentSessionId) {
      throw new ForbiddenException('Cannot invalidate your current session');
    }

    session.isActive = false;
    sessionStore.set(sessionId, session);

    this.logger.log(`Invalidated session ${sessionId}${reason ? `: ${reason}` : ''}`);
  }

  async invalidateAllUserSessions(
    organizationId: string,
    userId: string,
    currentSessionId: string,
    reason?: string,
  ): Promise<number> {
    const sessions = Array.from(sessionStore.values())
      .filter(s => 
        s.organizationId === organizationId && 
        s.userId === userId && 
        s.id !== currentSessionId &&
        s.isActive
      );

    for (const session of sessions) {
      session.isActive = false;
      sessionStore.set(session.id, session);
    }

    this.logger.log(`Invalidated ${sessions.length} sessions for user ${userId}${reason ? `: ${reason}` : ''}`);
    return sessions.length;
  }

  async invalidateAllSessions(
    organizationId: string,
    currentSessionId: string,
    reason?: string,
  ): Promise<number> {
    const sessions = Array.from(sessionStore.values())
      .filter(s => 
        s.organizationId === organizationId && 
        s.id !== currentSessionId &&
        s.isActive
      );

    for (const session of sessions) {
      session.isActive = false;
      sessionStore.set(session.id, session);
    }

    this.logger.log(`Invalidated all ${sessions.length} sessions for org ${organizationId}${reason ? `: ${reason}` : ''}`);
    return sessions.length;
  }

  async updateSessionActivity(sessionId: string): Promise<void> {
    const session = sessionStore.get(sessionId);
    if (session && session.isActive) {
      const settings = this.getSettings(session.organizationId);
      session.lastActivityAt = new Date();
      session.expiresAt = new Date(Date.now() + settings.sessionTimeoutMinutes * 60 * 1000);
      sessionStore.set(sessionId, session);
    }
  }

  async getSessionStats(organizationId: string): Promise<SessionStatsDto> {
    const now = new Date();
    const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const weekStart = new Date(todayStart.getTime() - 7 * 24 * 60 * 60 * 1000);

    const sessions = Array.from(sessionStore.values())
      .filter(s => s.organizationId === organizationId);

    const activeSessions = sessions.filter(s => s.isActive && s.expiresAt > now);

    const browserCounts = new Map<string, number>();
    const osCounts = new Map<string, number>();

    for (const session of activeSessions) {
      browserCounts.set(session.browser, (browserCounts.get(session.browser) || 0) + 1);
      osCounts.set(session.os, (osCounts.get(session.os) || 0) + 1);
    }

    return {
      totalActiveSessions: activeSessions.length,
      uniqueUsers: new Set(activeSessions.map(s => s.userId)).size,
      sessionsToday: sessions.filter(s => s.createdAt >= todayStart).length,
      sessionsThisWeek: sessions.filter(s => s.createdAt >= weekStart).length,
      browserDistribution: Array.from(browserCounts.entries())
        .map(([browser, count]) => ({ browser, count }))
        .sort((a, b) => b.count - a.count),
      osDistribution: Array.from(osCounts.entries())
        .map(([os, count]) => ({ os, count }))
        .sort((a, b) => b.count - a.count),
    };
  }

  getSessionSettings(organizationId: string): SessionSettingsDto {
    return this.getSettings(organizationId);
  }

  updateSessionSettings(
    organizationId: string,
    dto: UpdateSessionSettingsDto,
  ): SessionSettingsDto {
    const current = this.getSettings(organizationId);
    const updated: SessionSettings = {
      sessionTimeoutMinutes: dto.sessionTimeoutMinutes ?? current.sessionTimeoutMinutes,
      maxConcurrentSessions: dto.maxConcurrentSessions ?? current.maxConcurrentSessions,
      enforceSingleSession: dto.enforceSingleSession ?? current.enforceSingleSession,
      requireReauthForSensitiveActions: dto.requireReauthForSensitiveActions ?? current.requireReauthForSensitiveActions,
    };
    settingsStore.set(organizationId, updated);
    this.logger.log(`Updated session settings for org ${organizationId}`);
    return updated;
  }

  private getSettings(organizationId: string): SessionSettings {
    return settingsStore.get(organizationId) || { ...DEFAULT_SETTINGS };
  }

  private parseUserAgent(userAgent: string): { browser: string; os: string; device: string } {
    // Simple regex-based parsing
    let browser = 'Unknown';
    let os = 'Unknown';
    let device = 'desktop';

    // Browser detection
    if (userAgent.includes('Chrome') && !userAgent.includes('Edg')) {
      const match = userAgent.match(/Chrome\/(\d+)/);
      browser = match ? `Chrome ${match[1]}` : 'Chrome';
    } else if (userAgent.includes('Firefox')) {
      const match = userAgent.match(/Firefox\/(\d+)/);
      browser = match ? `Firefox ${match[1]}` : 'Firefox';
    } else if (userAgent.includes('Safari') && !userAgent.includes('Chrome')) {
      const match = userAgent.match(/Version\/(\d+)/);
      browser = match ? `Safari ${match[1]}` : 'Safari';
    } else if (userAgent.includes('Edg')) {
      const match = userAgent.match(/Edg\/(\d+)/);
      browser = match ? `Edge ${match[1]}` : 'Edge';
    }

    // OS detection
    if (userAgent.includes('Windows')) {
      os = 'Windows';
    } else if (userAgent.includes('Mac OS X')) {
      os = 'macOS';
    } else if (userAgent.includes('Linux')) {
      os = 'Linux';
    } else if (userAgent.includes('Android')) {
      os = 'Android';
      device = 'mobile';
    } else if (userAgent.includes('iPhone') || userAgent.includes('iPad')) {
      os = 'iOS';
      device = userAgent.includes('iPad') ? 'tablet' : 'mobile';
    }

    return { browser, os, device };
  }

  private toDto(session: SessionRecord, currentSessionId: string): SessionDto {
    return {
      id: session.id,
      userId: session.userId,
      deviceInfo: session.deviceInfo,
      browser: session.browser,
      os: session.os,
      ipAddress: session.ipAddress,
      isActive: session.isActive && session.expiresAt > new Date(),
      isCurrent: session.id === currentSessionId,
      createdAt: session.createdAt,
      lastActivityAt: session.lastActivityAt,
      expiresAt: session.expiresAt,
    };
  }
}
