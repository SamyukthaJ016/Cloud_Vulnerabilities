import { randomUUID } from 'crypto';
import { PrismaClient } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { CustomFieldsService } from './custom-fields.service';
import { CustomFieldEntityType, CustomFieldType } from './dto/custom-field.dto';
import { RetentionService } from '../retention/retention.service';
import { RetentionEntityType } from '../retention/dto/retention.dto';
import { DelegationService } from '../delegation/delegation.service';

const databaseUrl = process.env.GRC_TEST_DATABASE_URL;
const databaseDescribe = databaseUrl ? describe : describe.skip;

databaseDescribe('Persistent tenant settings across service recreation', () => {
  let prisma: PrismaClient;
  const orgA = randomUUID(), orgB = randomUUID(), userA = randomUUID(), userB = randomUUID();
  const controlId = randomUUID();
  const client = () => prisma as unknown as PrismaService;

  beforeAll(async () => {
    const url = new URL(databaseUrl!);
    if (!['localhost', '127.0.0.1'].includes(url.hostname) || !url.pathname.endsWith('_regression')) {
      throw new Error('Integration tests require an isolated local *_regression database');
    }
    prisma = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
    await prisma.organization.createMany({ data: [orgA, orgB].map(id => ({ id, name: 'Test', slug: id })) });
    await prisma.user.createMany({ data: [userA, userB].map(id => ({
      id, organizationId: orgA, keycloakId: id, email: `${id}@example.test`, firstName: 'Test', lastName: 'User', displayName: 'Test User',
    })) });
    await prisma.control.create({ data: { id: controlId, organizationId: orgA, controlId, title: 'Test', description: 'Test', category: 'custom' } });
  });

  afterAll(async () => { await prisma?.$disconnect(); });

  it('persists definitions and values and rejects a foreign organization', async () => {
    const service = new CustomFieldsService(client());
    const field = await service.createField(orgA, userA, { name: 'Owner note', slug: 'owner_note', fieldType: CustomFieldType.TEXT, entityType: CustomFieldEntityType.Control });
    await service.setEntityFieldValue(orgA, userA, CustomFieldEntityType.Control, controlId, { fieldIdOrSlug: field.id, value: 'kept across restart' });
    await prisma.$disconnect();
    const restarted = new CustomFieldsService(client());
    expect((await restarted.getField(orgA, field.id)).name).toBe('Owner note');
    expect((await restarted.getEntityFieldValues(orgA, CustomFieldEntityType.Control, controlId)).values[0].value).toBe('kept across restart');
    await expect(restarted.getField(orgB, field.id)).rejects.toThrow('not found');
    await expect(restarted.setEntityFieldValue(orgB, userB, CustomFieldEntityType.Control, controlId, { fieldIdOrSlug: field.id, value: 'foreign' })).rejects.toThrow('not found');
    await restarted.deleteField(orgA, field.id);
    expect(await prisma.customFieldValue.count({ where: { fieldId: field.id } })).toBe(0);
  });

  it('enforces slug uniqueness across concurrent creates', async () => {
    const dto = { name: 'Duplicate', slug: 'duplicate', fieldType: CustomFieldType.TEXT, entityType: CustomFieldEntityType.Control };
    const results = await Promise.allSettled([new CustomFieldsService(client()).createField(orgA, userA, dto), new CustomFieldsService(client()).createField(orgA, userA, dto)]);
    expect(results.filter(result => result.status === 'fulfilled')).toHaveLength(1);
  });

  it('persists retention policies and tenant ownership', async () => {
    const service = new RetentionService(client());
    const policy = await service.createPolicy(orgA, userA, { name: 'Test retention', entityType: RetentionEntityType.NOTIFICATIONS, retentionDays: 90 });
    await prisma.$disconnect();
    const restarted = new RetentionService(client());
    expect((await restarted.getPolicy(orgA, policy.id)).retentionDays).toBe(90);
    await expect(restarted.updatePolicy(orgB, policy.id, { retentionDays: 1 })).rejects.toThrow('not found');
  });

  it('persists delegation and revocation across service recreation', async () => {
    const dto = { delegateeId: userB, startDate: new Date(Date.now() - 1000).toISOString(), endDate: new Date(Date.now() + 86400000).toISOString() };
    const delegation = await new DelegationService(client()).createDelegation(orgA, userA, dto);
    await prisma.$disconnect();
    const restarted = new DelegationService(client());
    expect((await restarted.getDelegation(orgA, delegation.id)).delegateeId).toBe(userB);
    await expect(restarted.getDelegation(orgB, delegation.id)).rejects.toThrow('not found');
    await expect(restarted.revokeDelegation(orgA, userB, delegation.id)).rejects.toThrow('Only the delegator');
    await restarted.revokeDelegation(orgA, userA, delegation.id);
    expect((await new DelegationService(client()).getDelegation(orgA, delegation.id)).status).toBe('revoked');
  });

  it('serializes overlapping delegations from different service instances', async () => {
    const dto = { delegateeId: userB, startDate: new Date(Date.now() + 86400000).toISOString(), endDate: new Date(Date.now() + 172800000).toISOString() };
    const results = await Promise.allSettled([
      new DelegationService(client()).createDelegation(orgA, userA, dto),
      new DelegationService(client()).createDelegation(orgA, userA, dto),
    ]);
    expect(results.filter(result => result.status === 'fulfilled')).toHaveLength(1);
    expect(results.filter(result => result.status === 'rejected')).toHaveLength(1);
    // Adjacent time intervals are valid, despite using the same scopes.
    await expect(new DelegationService(client()).createDelegation(orgA, userA, {
      ...dto, startDate: dto.endDate, endDate: new Date(Date.now() + 259200000).toISOString(),
    })).resolves.toBeDefined();
  });
});
