import { NotFoundException, ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { RunbooksService } from './runbooks.service';
import { BusinessProcessesService } from './business-processes.service';
import { CommunicationPlansService } from './communication-plans.service';
import { BCDRPlansService } from './bcdr-plans.service';
import { RunbooksController } from './runbooks.controller';
import { CommunicationPlansController } from './communication-plans.controller';
import { PermissionGuard } from '../auth/permission.guard';
import { PermissionsService } from '../permissions/permissions.service';

describe('BCDR child ownership boundaries', () => {
  const prisma = { $queryRaw: jest.fn(), $executeRaw: jest.fn(), $queryRawUnsafe: jest.fn() };
  const factories = [
    () => new RunbooksService(prisma as any, {} as any, {} as any),
    () => new BusinessProcessesService(prisma as any, {} as any),
    () => new CommunicationPlansService(prisma as any, {} as any),
    () => new BCDRPlansService(prisma as any, {} as any, {} as any),
  ];
  const cases = [
    [0, 'addStep', ['parent', 'foreign-org', 'user', {}]],
    [0, 'updateStep', ['parent', 'foreign-org', 1, {}]],
    [0, 'deleteStep', ['parent', 'foreign-org', 1]],
    [0, 'reorderSteps', ['parent', 'foreign-org', ['step']]],
    [1, 'removeDependency', ['parent', 'foreign-org', 'other']],
    [1, 'unlinkAsset', ['parent', 'foreign-org', 'asset']],
    [1, 'linkRisk', ['parent', 'foreign-org', 'risk', 'user']],
    [1, 'unlinkRisk', ['parent', 'foreign-org', 'risk']],
    [2, 'addContact', ['parent', 'foreign-org', 'user', {}]],
    [2, 'updateContact', ['parent', 'foreign-org', 'contact', {}]],
    [2, 'deleteContact', ['parent', 'foreign-org', 'contact']],
    [2, 'reorderContacts', ['parent', 'foreign-org', ['contact']]],
    [3, 'linkControl', ['parent', 'foreign-org', 'control', 'user']],
    [3, 'unlinkControl', ['parent', 'foreign-org', 'control']],
  ] as const;

  beforeEach(() => jest.clearAllMocks());
  it.each(cases)('authorizes the parent before service %s operation %s', async (index, method, args) => {
    const service = factories[index]();
    const lookup = jest.spyOn(service, 'findOne').mockRejectedValue(new NotFoundException());
    await expect((service as any)[method](...args)).rejects.toThrow(NotFoundException);
    expect(lookup).toHaveBeenCalledWith('parent', 'foreign-org');
    expect(prisma.$executeRaw).not.toHaveBeenCalled();
    expect(prisma.$queryRawUnsafe).not.toHaveBeenCalled();
    expect(prisma.$queryRaw).not.toHaveBeenCalled();
  });

  it('passes the caller and parent into contact updates', async () => {
    const service = { updateContact: jest.fn() };
    const controller = new CommunicationPlansController(service as any);
    await controller.updateContact('plan-a', { organizationId: 'org-a' } as any, 'contact-b', {});
    expect(service.updateContact).toHaveBeenCalledWith('plan-a', 'org-a', 'contact-b', {});
  });

  it('requires write permission on runbook step deletion', async () => {
    const permissions = { hasPermission: jest.fn().mockResolvedValue({ allowed: false }) };
    const guard = new PermissionGuard(new Reflector(), permissions as unknown as PermissionsService);
    const context = {
      getClass: () => RunbooksController,
      getHandler: () => RunbooksController.prototype.deleteStep,
      switchToHttp: () => ({ getRequest: () => ({ user: { userId: 'viewer', permissions: [] }, params: {} }) }),
    } as unknown as ExecutionContext;
    await expect(guard.canActivate(context)).rejects.toThrow(ForbiddenException);
  });
});
