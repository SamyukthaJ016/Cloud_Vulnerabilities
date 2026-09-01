import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { Request } from 'express';

/**
 * Authenticated user context attached to requests
 */
interface AuthenticatedUser {
  userId: string;
  organizationId: string;
  email?: string;
  role?: string;
  permissions: string[];
}

/**
 * Request with authenticated user
 */
interface AuthenticatedRequest extends Request {
  user: AuthenticatedUser;
}

/**
 * Compatibility guard for routes that receive an identity from a preceding
 * verified authentication guard. It never reconstructs a user from request
 * headers, because browser clients can forge those values.
 */
@Injectable()
export class AuthGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<Request & { user?: AuthenticatedUser }>();

    if (request.user?.userId && request.user.organizationId) {
      return true;
    }

    throw new UnauthorizedException('Authentication required');
  }
}
