import { generateKeyPairSync } from 'crypto';
import * as jwt from 'jsonwebtoken';
import { ExecutionContext, ForbiddenException, UnauthorizedException } from '@nestjs/common';
import { JwtAuthGuard, RolesGuard } from '@gigachad-grc/shared';
import { PortalController } from './portal.controller';

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const issuer = 'https://issuer.example.test/realms/regression';
const audience = 'regression-api';

describe('Audit portal administration authorization', () => {
  let auth: JwtAuthGuard;
  const saved = { ...process.env };
  beforeAll(() => {
    process.env.KEYCLOAK_ISSUER = issuer;
    process.env.KEYCLOAK_AUDIENCE = audience;
    auth = new JwtAuthGuard();
    // Only key discovery is stubbed; JWT signature, issuer, audience, expiry,
    // identity, and role checks use the production guard.
    (auth as any).jwksClient = { getSigningKey: async () => ({ getPublicKey: () => publicKey.export({ type: 'spki', format: 'pem' }) }) };
  });
  afterAll(() => { process.env = saved; });

  const methods = ['listPortalUsers', 'createPortalUser', 'updatePortalUser', 'deletePortalUser', 'getAccessLogs', 'bulkCreatePortalUsers'];
  const context = (method: string, headers: Record<string, string>) => {
    const request = { headers, user: undefined };
    return {
      getHandler: () => (PortalController.prototype as any)[method],
      getClass: () => PortalController,
      switchToHttp: () => ({ getRequest: () => request }),
    } as unknown as ExecutionContext;
  };
  const token = (role: string) => jwt.sign({
    sub: '11111111-1111-4111-8111-111111111111', organization_id: '22222222-2222-4222-8222-222222222222',
    realm_access: { roles: [role] },
  }, privateKey, { algorithm: 'RS256', keyid: 'regression', issuer, audience, expiresIn: '5m' });

  it.each(methods)('rejects viewers and auditors on %s', async method => {
    expect((PortalController.prototype as any)[method]).toBeDefined();
    for (const role of ['viewer', 'auditor']) {
      const ctx = context(method, { authorization: `Bearer ${token(role)}` });
      await expect(auth.canActivate(ctx)).rejects.toThrow(ForbiddenException);
    }
  });
  it.each(['admin', 'compliance_manager'])('allows %s to administer the portal', async role => {
    const ctx = context('createPortalUser', { authorization: `Bearer ${token(role)}` });
    expect(await auth.canActivate(ctx)).toBe(true);
    expect(new RolesGuard().canActivate(ctx)).toBe(true);
  });
  it('rejects forged identity headers without a bearer token', async () => {
    await expect(auth.canActivate(context('createPortalUser', { 'x-dev-user-id': 'admin', 'x-user-id': 'admin' }))).rejects.toThrow(UnauthorizedException);
  });
});
