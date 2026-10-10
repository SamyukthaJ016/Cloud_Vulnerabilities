import { generateKeyPairSync } from 'crypto';
import * as jwt from 'jsonwebtoken';
import { JwtAuthGuard } from '@gigachad-grc/shared';

describe('Registration token verification', () => {
  const keys = generateKeyPairSync('rsa', { modulusLength: 2048 });
  let guard: JwtAuthGuard;
  const environment = { ...process.env };
  beforeEach(() => {
    process.env.KEYCLOAK_ISSUER = 'https://identity.example.test/realms/test';
    process.env.KEYCLOAK_AUDIENCE = 'grc-api';
    process.env.KEYCLOAK_ONBOARDING_AUDIENCES = 'grc-api,cloudguard-api';
    guard = new JwtAuthGuard();
    (guard as any).jwksClient = { getSigningKey: async () => ({ getPublicKey: () => keys.publicKey.export({ type: 'spki', format: 'pem' }) }) };
  });
  afterAll(() => { process.env = environment; });
  const token = (audience: string, issuer = 'https://identity.example.test/realms/test') => jwt.sign(
    { sub: 'new-user', email: 'new@example.test', email_verified: true }, keys.privateKey,
    { algorithm: 'RS256', keyid: 'test', audience, issuer, expiresIn: 60 },
  );
  it.each(['grc-api', 'cloudguard-api'])('accepts a signed %s token before tenant assignment', async audience => {
    expect((await guard.verifyRegistrationToken(token(audience))).sub).toBe('new-user');
  });
  it('rejects the wrong audience and issuer', async () => {
    await expect(guard.verifyRegistrationToken(token('other-api'))).rejects.toThrow();
    await expect(guard.verifyRegistrationToken(token('grc-api', 'https://other.example.test'))).rejects.toThrow();
  });
  it('does not let an unassigned account use ordinary protected APIs', async () => {
    const request = { headers: { authorization: `Bearer ${token('grc-api')}` } };
    const context = { switchToHttp: () => ({ getRequest: () => request }), getHandler: () => ({}), getClass: () => ({}) };
    await expect(guard.canActivate(context as any)).rejects.toThrow('organization_id');
  });
});
