import { Module } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { GoogleStrategy } from './strategies/google.strategy';
import { JwtStrategy } from './strategies/jwt.strategy';
import { UsersModule } from '../users/users.module';
import { OrganizationsModule } from '../organizations/organizations.module';
import { RbacModule } from '../rbac/rbac.module';

/**
 * Note: JWT signing + cookie management lives in the global SessionModule
 * (src/modules/session) so OrganizationsController can also issue session
 * cookies (when self-serve creating an org) without a circular import.
 */
@Module({
  imports: [PassportModule, UsersModule, OrganizationsModule, RbacModule],
  controllers: [AuthController],
  providers: [AuthService, GoogleStrategy, JwtStrategy],
  exports: [AuthService],
})
export class AuthModule {}
