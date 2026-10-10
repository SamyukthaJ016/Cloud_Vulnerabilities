import { RegistrationService } from './registration';

describe('Automatic organization registration', () => {
  let service: RegistrationService;
  let admin: any;
  let prisma: any;
  let verifier: any;
  beforeEach(() => {
    admin = {
      getUser: jest.fn().mockResolvedValue({ id: 'subject', email: 'new@example.test', firstName: 'New', enabled: true, emailVerified: true, attributes: {} }),
      assignRealmRoles: jest.fn().mockResolvedValue(undefined), updateUser: jest.fn().mockResolvedValue(undefined),
    };
    prisma = { $executeRaw: jest.fn(), user: { findUnique: jest.fn().mockResolvedValue(null), create: jest.fn().mockImplementation(({ data }) => data) }, organization: { create: jest.fn() } };
    prisma.$transaction = jest.fn((work) => work(prisma));
    verifier = { verifyRegistrationToken: jest.fn().mockResolvedValue({ sub: 'subject', email: 'new@example.test', email_verified: true }) };
    service = new RegistrationService(prisma, verifier);
    jest.spyOn(service as any, 'adminClient').mockReturnValue(admin);
  });

  it('creates an isolated organization and owner, then assigns the trusted tenant claim', async () => {
    const result = await service.onboard('signed-token');
    expect(verifier.verifyRegistrationToken).toHaveBeenCalledWith('signed-token');
    expect(prisma.organization.create).toHaveBeenCalledTimes(1);
    expect(prisma.user.create.mock.calls[0][0].data).toMatchObject({ keycloakId: 'subject', role: 'admin', organizationId: result.organizationId });
    expect(admin.updateUser).toHaveBeenCalledWith('subject', { attributes: { organization_id: [result.organizationId] } });
  });

  it('rejects invalid tokens before any side effect', async () => {
    verifier.verifyRegistrationToken.mockRejectedValue(new Error('bad signature'));
    await expect(service.onboard('forged')).rejects.toThrow('Invalid access token');
    expect(prisma.$transaction).not.toHaveBeenCalled();
    expect(admin.getUser).not.toHaveBeenCalled();
  });

  it('requires verified email', async () => {
    verifier.verifyRegistrationToken.mockResolvedValue({ sub: 'subject', email: 'new@example.test', email_verified: false });
    await expect(service.onboard('token')).rejects.toThrow('Verify your email');
    expect(prisma.$transaction).not.toHaveBeenCalled();
  });

  it('does not move or promote existing members', async () => {
    admin.getUser.mockResolvedValue({ enabled: true, emailVerified: true, attributes: { organization_id: ['existing-org'] } });
    expect(await service.onboard('token')).toEqual({ organizationId: 'existing-org', created: false });
    expect(prisma.$transaction).not.toHaveBeenCalled();
    expect(admin.assignRealmRoles).not.toHaveBeenCalled();
  });

  it('reuses a durable reservation after an identity-service failure', async () => {
    admin.updateUser.mockRejectedValueOnce(new Error('unavailable'));
    await expect(service.onboard('token')).rejects.toThrow('please retry');
    const saved = prisma.user.create.mock.calls[0][0].data;
    prisma.user.findUnique.mockResolvedValue({ ...saved, status: 'active' });
    const result = await service.onboard('token');
    expect(result.organizationId).toBe(saved.organizationId);
    expect(prisma.organization.create).toHaveBeenCalledTimes(1);
  });

  it('cannot elevate an existing unassigned viewer', async () => {
    prisma.user.findUnique.mockResolvedValue({ role: 'viewer', status: 'active', preferences: {} });
    await expect(service.onboard('token')).rejects.toThrow('administrator assistance');
    expect(admin.assignRealmRoles).not.toHaveBeenCalled();
  });
});
