/** Optional real-PostgreSQL regression. Uses only a disposable localhost *_regression DB. */
import { randomUUID } from 'crypto';
import { PrismaClient } from '@prisma/client';
import { CloudGuardImportService } from './cloudguard-import.service';

const databaseUrl = process.env.CLOUDGUARD_GRC_TEST_DATABASE_URL;
const databaseTest = databaseUrl ? it : it.skip;

databaseTest('concurrent imports produce one evidence report, one risk and one observation', async () => {
  const url = new URL(databaseUrl!);
  expect(['localhost', '127.0.0.1']).toContain(url.hostname);
  expect(url.pathname.endsWith('_regression')).toBe(true);
  const prisma = new PrismaClient({datasources:{db:{url:databaseUrl}}});
  const organizationId = randomUUID(), userId = randomUUID();
  const scan={id:26,provider:'kubernetes',account_id:'cluster',started_at:'2026-10-14T00:00:00Z',resource_count:1,finding_count:1,findings:[
    {id:1,severity:'critical',title:'Privileged container',description:'Privileged container',resource:'pod-a',resource_type:'Pod',provider:'kubernetes'},
  ]};
  const objects=new Map<string,Buffer>();
  const source={getDashboard:async()=>({tenant_id:organizationId,latest_scan:scan})};
  const storage={exists:async path=>objects.has(path),upload:async (bytes,path)=>{objects.set(path,bytes);return path;}};
  const service=new CloudGuardImportService(source as never,prisma as never,{log:jest.fn()} as never,{del:jest.fn()} as never,storage as never);
  try {
    await prisma.organization.create({data:{id:organizationId,name:'Import regression',slug:organizationId}});
    await prisma.user.create({data:{id:userId,keycloakId:userId,email:`${userId}@example.test`,firstName:'Test',lastName:'Import',displayName:'Test Import',organizationId,role:'admin'}});
    const results=await Promise.all([service.importLatest(organizationId,userId,26),service.importLatest(organizationId,userId,26)]);
    expect(results.reduce((total,r)=>total+r.createdRisks,0)).toBe(1);
    expect(await prisma.evidence.count({where:{organizationId}})).toBe(1);
    expect(await prisma.risk.count({where:{organizationId}})).toBe(1);
    expect(await prisma.riskHistory.count({where:{risk:{organizationId}}})).toBe(1);
    const risk=await prisma.risk.findFirstOrThrow({where:{organizationId}});
    const evidence=await prisma.evidence.findFirstOrThrow({where:{organizationId}});
    expect(risk.documentation).toEqual(expect.arrayContaining([expect.objectContaining({evidenceId:evidence.id})]));
    expect(risk.initialSeverity).toBe('very_high');
    await prisma.risk.update({where:{id:risk.id},data:{status:'risk_analyzed',treatmentPlan:'mitigate'}});
    await service.importLatest(organizationId,userId,26);
    expect(await prisma.risk.findUnique({where:{id:risk.id}})).toMatchObject({status:'risk_analyzed',treatmentPlan:'mitigate'});
  } finally {
    await prisma.riskHistory.deleteMany({where:{risk:{organizationId}}});
    await prisma.risk.deleteMany({where:{organizationId}});
    await prisma.evidence.deleteMany({where:{organizationId}});
    await prisma.user.deleteMany({where:{organizationId}});
    await prisma.organization.deleteMany({where:{id:organizationId}});
    await prisma.$disconnect();
  }
},30_000);
