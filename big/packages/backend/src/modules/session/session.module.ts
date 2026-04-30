import { Global, Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { SessionService } from './session.service';

/**
 * Global because both AuthController and OrganizationsController need to
 * issue/clear the session cookie. Marking @Global() avoids forwardRef chains.
 */
@Global()
@Module({
  imports: [
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        secret: config.get<string>('jwt.secret'),
        signOptions: { expiresIn: config.get<string>('jwt.expiresIn') },
      }),
    }),
  ],
  providers: [SessionService],
  exports: [SessionService, JwtModule],
})
export class SessionModule {}
