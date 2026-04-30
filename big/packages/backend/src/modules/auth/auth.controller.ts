import { Controller, Get, Logger, Req, Res, UseGuards } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AuthGuard } from '@nestjs/passport';
import { Request, Response } from 'express';
import { AuthService, GoogleProfile } from './auth.service';
import { Public } from '../../common/decorators/public.decorator';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { AuthenticatedUser } from '../../common/types/authenticated-user';
import { SessionService } from '../session/session.service';
import { RbacService } from '../rbac/rbac.service';

@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(
    private readonly authService: AuthService,
    private readonly config: ConfigService,
    private readonly session: SessionService,
    private readonly rbac: RbacService,
  ) {}

  /** Flow C → D. Passport redirects to Google. */
  @Public()
  @Get('google')
  @UseGuards(AuthGuard('google'))
  googleAuth() {
    /* passport redirects */
  }

  /**
   * Flow F → P. Google returns here after user authenticates.
   *   - GoogleStrategy.validate() puts the profile on `req.user`
   *   - completeLogin upserts user + resolves org + signs JWT
   *   - we set an HTTP-only cookie and redirect to the frontend
   */
  @Public()
  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  async googleCallback(@Req() req: Request, @Res() res: Response) {
    const frontendBase = this.config.get<string>('app.frontendBaseUrl') ?? 'http://localhost:5173';

    try {
      const profile = req.user as GoogleProfile;
      const { payload } = await this.authService.completeLogin(profile);
      this.session.issue(res, payload);

      return res.redirect(`${frontendBase}/auth/callback`);
    } catch (err) {
      this.logger.error('Google callback failed', err as Error);
      return res.redirect(`${frontendBase}/auth/error`);
    }
  }

  @Public()
  @Get('dev-login')
  async devLogin(@Res() res: Response) {
    const frontendBase = this.config.get<string>('app.frontendBaseUrl') ?? 'http://localhost:5173';

    if (this.config.get<string>('app.env') === 'production') {
      return res.status(404).json({ message: 'Not found' });
    }

    try {
      const { payload } = await this.authService.completeDevelopmentLogin();
      this.session.issue(res, payload);
      return res.redirect(`${frontendBase}/auth/callback`);
    } catch (err) {
      this.logger.error('Dev login failed', err as Error);
      return res.redirect(`${frontendBase}/auth/error`);
    }
  }

  /** Returns the authenticated user (frontend session bootstrap). */
  @Get('me')
  async me(@CurrentUser() user: AuthenticatedUser) {
    const permissions = user.roleKey
      ? await this.rbac.permissionsForRoleKey(user.roleKey)
      : [];

    return {
      ...user,
      permissions,
    };
  }

  /** Clears the session cookie. Public so even an expired session can sign out. */
  @Public()
  @Get('logout')
  logout(@Res() res: Response) {
    this.session.clearCookie(res);
    return res.json({ ok: true });
  }
}
