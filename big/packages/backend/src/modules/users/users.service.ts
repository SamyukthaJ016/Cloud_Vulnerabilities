import { Injectable, NotFoundException } from '@nestjs/common';
import { SsoProvider, UserStatus } from '@prisma/client';
import { randomUUID } from 'crypto';
import { PrismaService } from '../../infra/prisma/prisma.service';

export interface SsoProfile {
  sub: string;
  email: string;
  name?: string;
  picture?: string;
}

@Injectable()
export class UsersService {
  constructor(private readonly prisma: PrismaService) {}

  /**
   * Flow node I → K/L. Idempotent: called by AuthService on every login.
   *
   * Resolution order:
   *   1. Exact match by (ssoProvider, ssoSubject) — fast path for repeat logins.
   *   2. Match by email — handles the invite flow where an admin pre-created a
   *      User row with a placeholder ssoSubject. Links Google identity to that row.
   *   3. Brand-new user — create with status=PENDING.
   *
   * Always updates lastLoginAt + name + avatarUrl on return path.
   */
  async findOrCreateFromSso(profile: SsoProfile) {
    const byIdentity = await this.prisma.user.findUnique({
      where: {
        ssoProvider_ssoSubject: {
          ssoProvider: SsoProvider.GOOGLE,
          ssoSubject: profile.sub,
        },
      },
    });
    if (byIdentity) {
      return this.prisma.user.update({
        where: { id: byIdentity.id },
        data: {
          lastLoginAt: new Date(),
          name: profile.name ?? byIdentity.name,
          avatarUrl: profile.picture ?? byIdentity.avatarUrl,
        },
      });
    }

    const byEmail = await this.prisma.user.findUnique({ where: { email: profile.email } });
    if (byEmail) {
      return this.prisma.user.update({
        where: { id: byEmail.id },
        data: {
          ssoProvider: SsoProvider.GOOGLE,
          ssoSubject: profile.sub,
          status: UserStatus.ACTIVE,
          emailVerified: true,
          name: profile.name ?? byEmail.name,
          avatarUrl: profile.picture ?? byEmail.avatarUrl,
          lastLoginAt: new Date(),
        },
      });
    }

    return this.prisma.user.create({
      data: {
        email: profile.email,
        ssoProvider: SsoProvider.GOOGLE,
        ssoSubject: profile.sub,
        name: profile.name ?? null,
        avatarUrl: profile.picture ?? null,
        emailVerified: true,
        status: UserStatus.PENDING,
        lastLoginAt: new Date(),
      },
    });
  }

  /**
   * Pre-creates a User row by email for the invite flow.
   * Placeholder ssoSubject is replaced with the real Google `sub` on first sign-in.
   */
  async findOrCreateInvited(email: string) {
    const existing = await this.prisma.user.findUnique({ where: { email } });
    if (existing) return existing;

    return this.prisma.user.create({
      data: {
        email,
        ssoProvider: SsoProvider.GOOGLE,
        ssoSubject: `invite:${randomUUID()}`,
        status: UserStatus.PENDING,
      },
    });
  }

  async findById(userId: string) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) throw new NotFoundException('User not found');
    return user;
  }

  async updateProfile(userId: string, patch: { name?: string; avatarUrl?: string }) {
    return this.prisma.user.update({ where: { id: userId }, data: patch });
  }
}
