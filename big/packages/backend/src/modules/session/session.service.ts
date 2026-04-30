import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { Response } from 'express';
import { JwtPayload } from '../../common/types/jwt-payload';
import { ACCESS_COOKIE } from './session.constants';

/**
 * Owns the JWT signing + cookie lifecycle in one place.
 *
 * Both AuthController (login/logout) and OrganizationsController (org-create
 * needs a fresh JWT with the new orgId) call into this — extracted to avoid
 * a circular dependency between AuthModule and OrganizationsModule.
 */
@Injectable()
export class SessionService {
  constructor(
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
  ) {}

  signAccessToken(payload: JwtPayload): string {
    return this.jwt.sign(payload);
  }

  /** Sets the HTTP-only session cookie on the response. */
  setCookie(res: Response, token: string) {
    res.cookie(ACCESS_COOKIE, token, {
      httpOnly: true,
      secure: this.config.get<string>('app.env') === 'production',
      sameSite: 'lax',
      maxAge: 60 * 60 * 1000, // 1h, matches JWT_EXPIRES_IN
      path: '/',
    });
  }

  /** Sign + set in one call. */
  issue(res: Response, payload: JwtPayload) {
    this.setCookie(res, this.signAccessToken(payload));
  }

  clearCookie(res: Response) {
    res.clearCookie(ACCESS_COOKIE, { path: '/' });
  }
}
