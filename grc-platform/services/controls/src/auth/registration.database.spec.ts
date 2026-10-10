import { PrismaClient } from '@prisma/client';
import { randomUUID } from 'crypto';
import { RegistrationService } from './registration';

const url = process.env.GRC_TEST_DATABASE_URL;
(url ? describe : describe.skip)('Registration PostgreSQL concurrency', () => {
  let prisma: PrismaClient;
  beforeAll(() => {
    const parsed = new URL(url!);
    if (!['localhost', '127.0.0.1'].includes(parsed.hostname) || !parsed.pathname.endsWith('_regression')) throw new Error('Use a disposable local regression database');
    prisma = new PrismaClient({ datasources: { db: { url } } });
  });
  afterAll(async () => { await prisma?.$disconnect(); });

  it('creates one organization for concurrent requests and separate organizations for different identities', async () => {
    const first = randomUUID(), second = randomUUID();
    const attributes: Record<string, any> = {};
    const admin = {
      getUser: async (id: string) => ({ id, email: 'verified@example.test', enabled: true, emailVerified: true, attributes: attributes[id] || {} }),
      assignRealmRoles: jest.fn().mockResolvedValue(undefined),
      updateUser: async (id: string, changes: any) => { attributes[id] = changes.attributes; },
    };
    const verifier = { verifyRegistrationToken: async (sub: string) => ({ sub, email: 'verified@example.test', email_verified: true }) };
    const service = () => {
      const instance = new RegistrationService(prisma as any, verifier as any);
      jest.spyOn(instance as any, 'adminClient').mockReturnValue(admin);
      return instance;
    };
    const results = await Promise.all([service().onboard(first), service().onboard(first)]);
    expect(results[0].organizationId).toBe(results[1].organizationId);
    expect(await prisma.user.count({ where: { keycloakId: first } })).toBe(1);
    expect(await prisma.organization.count({ where: { users: { some: { keycloakId: first } } } })).toBe(1);
    expect((await service().onboard(second)).organizationId).not.toBe(results[0].organizationId);
    expect((await prisma.user.findUnique({ where: { keycloakId: first } }))?.role).toBe('admin');
  });
});
