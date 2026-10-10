import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { AuthGuard } from './auth.guard';

describe('AuthGuard verified context contract', () => {
  const guard = new AuthGuard();
  const context = (user: unknown, headers = {}) => ({
    switchToHttp: () => ({ getRequest: () => ({ user, headers }) }),
  }) as ExecutionContext;

  it('accepts the identity already verified by JwtAuthGuard', () => {
    expect(guard.canActivate(context({ userId: 'user-a', organizationId: 'org-a' }))).toBe(true);
  });

  it.each([
    {},
    { 'x-user-id': 'user-a', 'x-organization-id': 'org-a' },
    { 'x-dev-user-id': 'user-a' },
    { 'x-proxy-secret': 'test-proxy-secret', 'x-user-id': 'user-a', 'x-organization-id': 'org-a' },
  ])('does not authenticate caller-supplied identity headers: %j', (headers) => {
    expect(() => guard.canActivate(context(undefined, headers))).toThrow(UnauthorizedException);
  });

  it.each([{ userId: 'user-a' }, { organizationId: 'org-a' }, {}])('rejects incomplete verified context: %j', (user) => {
    expect(() => guard.canActivate(context(user))).toThrow(UnauthorizedException);
  });
});
