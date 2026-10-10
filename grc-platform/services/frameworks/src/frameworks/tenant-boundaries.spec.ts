import { FrameworksService } from './frameworks.service';
import { FrameworksController } from './frameworks.controller';
import { NotFoundException } from '@nestjs/common';

describe('Framework requirement ownership', () => {
  const prisma = {
    framework: { findFirst: jest.fn() },
    frameworkRequirement: { create: jest.fn(), findFirst: jest.fn(), update: jest.fn() },
  };
  beforeEach(() => jest.resetAllMocks());
  it.each(['create', 'bulk', 'update'])('rejects %s before touching foreign or global catalog requirements', async operation => {
    const service = new FrameworksService(prisma as any);
    prisma.framework.findFirst.mockResolvedValue(null);
    const action = operation === 'create'
      ? service.createRequirement('foreign-framework', 'org-a', { reference: '1', title: 'Test', description: 'Test' })
      : operation === 'bulk'
        ? service.bulkUploadRequirements('foreign-framework', 'org-a', {} as any)
        : service.updateRequirement('foreign-framework', 'org-a', 'requirement', {});
    await expect(action).rejects.toThrow(NotFoundException);
    expect(prisma.framework.findFirst).toHaveBeenCalledWith({ where: { id: 'foreign-framework', organizationId: 'org-a', deletedAt: null } });
    expect(prisma.frameworkRequirement.create).not.toHaveBeenCalled();
    expect(prisma.frameworkRequirement.update).not.toHaveBeenCalled();
  });
  it('includes organization context in requirement mutations from the controller', async () => {
    const service = { updateRequirement: jest.fn() };
    const controller = new FrameworksController(service as any);
    await controller.updateRequirement({ organizationId: 'org-a' } as any, 'framework', 'requirement', {});
    expect(service.updateRequirement).toHaveBeenCalledWith('framework', 'org-a', 'requirement', {});
  });
});
