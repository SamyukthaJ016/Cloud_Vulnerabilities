import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, VerifyCallback } from 'passport-google-oauth20';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(config: ConfigService) {
    super({
      clientID: config.get<string>('google.clientId')!,
      clientSecret: config.get<string>('google.clientSecret')!,
      callbackURL: config.get<string>('google.callbackUrl')!,
      scope: ['email', 'profile'],
    });
  }

  /**
   * Called by passport on successful Google auth.
   * Must return the shape expected by AuthService.completeLogin.
   */
  async validate(
    _accessToken: string,
    _refreshToken: string,
    profile: any,
    done: VerifyCallback,
  ): Promise<void> {
    const { id, emails, displayName, photos } = profile;
    done(null, {
      sub: id,
      email: emails?.[0]?.value,
      email_verified: emails?.[0]?.verified ?? false,
      name: displayName,
      picture: photos?.[0]?.value,
    });
  }
}
