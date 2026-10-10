import { Controller, Post, Req, Injectable, UnauthorizedException, ForbiddenException, ConflictException, ServiceUnavailableException } from '@nestjs/common';
import { Request } from 'express';
import { randomUUID } from 'crypto';
import { JwtAuthGuard, KeycloakAdminService } from '@gigachad-grc/shared';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class RegistrationService {
  constructor(private readonly prisma: PrismaService, private readonly verifier: JwtAuthGuard) {}

  protected adminClient() { return new KeycloakAdminService(); }

  async onboard(token: string) {
    let claims;
    try { claims = await this.verifier.verifyRegistrationToken(token); }
    catch { throw new UnauthorizedException('Invalid access token'); }
    if (claims.email_verified !== true || !claims.email) {
      throw new ForbiddenException('Verify your email before creating an organization');
    }
    let admin: KeycloakAdminService;
    try { admin = this.adminClient(); }
    catch { throw new ServiceUnavailableException('Account setup is not configured'); }
    const identity = await admin.getUser(claims.sub);
    if (!identity) throw new ServiceUnavailableException('Identity service unavailable');
    if (!identity.enabled || !identity.emailVerified) throw new ForbiddenException('Account is not verified');

    // Existing members keep their assignment and roles. Neither token claims nor
    // request bodies may select another tenant or elevate an existing member.
    const assigned = identity.attributes?.organization_id?.[0];
    if (assigned) return { organizationId: assigned, created: false };

    const user = await this.prisma.$transaction(async tx => {
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended(${`signup:${claims.sub}`}, 0))`;
      const existing = await tx.user.findUnique({ where: { keycloakId: claims.sub } });
      if (existing) {
        const preferences = existing.preferences as Record<string, unknown>;
        if (preferences?.selfSignup !== true || existing.status !== 'active' || existing.role !== 'admin') {
          throw new ConflictException('Existing membership requires administrator assistance');
        }
        return existing;
      }
      const id = randomUUID();
      const name = (identity.firstName || 'My').slice(0, 80);
      await tx.organization.create({ data: { id, name: `${name}'s organization`, slug: `workspace-${id}` } });
      return tx.user.create({ data: {
        id: claims.sub, keycloakId: claims.sub, email: identity.email,
        firstName: identity.firstName || '', lastName: identity.lastName || '',
        displayName: [identity.firstName, identity.lastName].filter(Boolean).join(' ') || identity.email,
        organizationId: id, role: 'admin', preferences: { selfSignup: true },
      } });
    });

    // Commit the durable reservation first. If Keycloak is unavailable, retrying
    // reuses this user/organization rather than creating duplicate tenants.
    try {
      const current = await admin.getUser(claims.sub);
      if (!current || !current.enabled) throw new Error('Identity unavailable');
      const currentOrg = current.attributes?.organization_id?.[0];
      if (currentOrg && currentOrg !== user.organizationId) throw new ConflictException('Membership changed during setup');
      await admin.assignRealmRoles(claims.sub, ['admin']);
      await admin.updateUser(claims.sub, { attributes: { ...current.attributes, organization_id: [user.organizationId] } });
    } catch (error) {
      if (error instanceof ConflictException) throw error;
      throw new ServiceUnavailableException('Account setup is incomplete; please retry');
    }
    return { organizationId: user.organizationId, created: true };
  }
}

@Controller('api/auth')
export class RegistrationController {
  constructor(private readonly registration: RegistrationService) {}

  // This route verifies a signed, audience-bound token before tenant assignment.
  // Normal JwtAuthGuard routes continue to require an organization_id claim.
  @Post('onboard')
  onboard(@Req() request: Request) {
    const match = /^Bearer ([^\s]+)$/.exec(request.headers.authorization || '');
    if (!match) throw new UnauthorizedException('Bearer token required');
    return this.registration.onboard(match[1]);
  }
}
