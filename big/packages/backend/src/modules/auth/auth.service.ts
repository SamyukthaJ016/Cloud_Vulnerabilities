import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from '../../common/types/jwt-payload';
import { UsersService } from '../users/users.service';
import { OrganizationsService } from '../organizations/organizations.service';

export interface GoogleProfile {
  sub: string;
  email: string;
  email_verified: boolean;
  name?: string;
  picture?: string;
}

export interface CompleteLoginResult {
  accessToken: string;
  payload: JwtPayload;
}

/**
 * Owns flow nodes F → P:
 *   - validate SSO claims
 *   - upsert user (UsersService)
 *   - resolve org membership (OrganizationsService)
 *   - sign JWT
 *
 * If no org membership is found, the JWT is still issued but with `orgId: null`,
 * `roleKey: null`. The frontend's RequireAuth guard sees that and routes to
 * /onboarding (flow N1).
 */
@Injectable()
export class AuthService {
  constructor(
    private readonly jwt: JwtService,
    private readonly users: UsersService,
    private readonly orgs: OrganizationsService,
  ) {}

  async completeLogin(profile: GoogleProfile): Promise<CompleteLoginResult> {
    if (!profile.email) {
      throw new UnauthorizedException('Google did not return an email');
    }
    if (!profile.email_verified) {
      throw new UnauthorizedException('Email not verified by Google');
    }

    const user = await this.users.findOrCreateFromSso({
      sub: profile.sub,
      email: profile.email,
      name: profile.name,
      picture: profile.picture,
    });

    const emailDomain = profile.email.split('@')[1] ?? '';
    const membership = await this.orgs.resolveForUser(user.id, emailDomain);

    const payload: JwtPayload = {
      sub: user.id,
      email: user.email,
      orgId: membership?.orgId ?? null,
      roleKey: membership?.roleKey ?? null,
    };

    return {
      accessToken: this.signAccessToken(payload),
      payload,
    };
  }

  async completeDevelopmentLogin(): Promise<CompleteLoginResult> {
    const profile: GoogleProfile = {
      sub: 'local-dev-user',
      email: 'local-dev@cloudguard.dev',
      email_verified: true,
      name: 'Local Dev User',
    };

    const user = await this.users.findOrCreateFromSso({
      sub: profile.sub,
      email: profile.email,
      name: profile.name,
    });

    let membership = await this.orgs.resolveForUser(user.id, 'cloudguard.dev');
    if (!membership) {
      const created = await this.orgs.createWithFirstAdmin({
        userId: user.id,
        name: 'Local Dev Organization',
        slug: `local-dev-${user.id.slice(0, 8)}`,
      });
      membership = {
        orgId: created.orgId,
        roleId: created.roleId,
        roleKey: created.roleKey,
      };
    }

    const payload: JwtPayload = {
      sub: user.id,
      email: user.email,
      orgId: membership.orgId,
      roleKey: membership.roleKey,
    };

    return {
      accessToken: this.signAccessToken(payload),
      payload,
    };
  }

  signAccessToken(payload: JwtPayload): string {
    return this.jwt.sign(payload);
  }
}
