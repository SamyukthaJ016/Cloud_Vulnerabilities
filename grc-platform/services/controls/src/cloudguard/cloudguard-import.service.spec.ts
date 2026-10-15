import { BadGatewayException, ConflictException } from '@nestjs/common';
import { CloudGuardImportService, scanEvidenceId } from './cloudguard-import.service';

describe('CloudGuard native record import', () => {
  function fixture() {
    const scan = {id:26,provider:'kubernetes',account_id:'cluster',started_at:'2026-10-14T00:00:00Z',resource_count:93,finding_count:2,findings:[
      {id:101,severity:'critical',title:'Privileged container',description:'[K8S] Privileged container',resource:'pod-a',resource_type:'Pod',provider:'kubernetes'},
      {id:102,severity:'info',title:'No IaC baseline',description:'No IaC baseline',resource:'cluster',resource_type:'Cluster',provider:'kubernetes'},
    ]};
    const evidence = new Map<string, any>();
    const risks = new Map<string, any>();
    const history: any[] = [];
    const objects = new Map<string, Buffer>();
    const upstream = {getDashboard:jest.fn(async () => ({tenant_id:'tenant-a',latest_scan:scan}))};
    const tx = {
      $executeRaw:jest.fn(),
      evidence:{findUnique:jest.fn(async ({where})=>evidence.get(where.id)),create:jest.fn(async ({data})=>{evidence.set(data.id,data);return data;})},
      risk:{findUnique:jest.fn(async ({where})=>risks.get(JSON.stringify(where.organizationId_riskId))),create:jest.fn(async ({data})=>{
        const row={...data,id:`risk-${risks.size+1}`};risks.set(JSON.stringify({organizationId:data.organizationId,riskId:data.riskId}),row);return row;
      })},
      riskHistory:{findFirst:jest.fn(async ({where})=>history.find(row=>row.riskId===where.riskId&&row.action===where.action&&row.notes===where.notes)),create:jest.fn(async ({data})=>{history.push(data);return data;})},
    };
    const prisma = {$transaction:jest.fn(async callback=>callback(tx))};
    const audit={log:jest.fn()};
    const cache={del:jest.fn()};
    const storage={exists:jest.fn(async path=>objects.has(path)),upload:jest.fn(async (data,path)=>{objects.set(path,data);return path;})};
    const service=new CloudGuardImportService(upstream as never,prisma as never,audit as never,cache as never,storage as never);
    return {service,scan,upstream,tx,evidence,risks,history,objects,audit,cache,storage};
  }

  it('creates a pending evidence report and one risk, retaining informational observations in the report', async () => {
    const f=fixture();
    const result=await f.service.importLatest('tenant-a','actor-a',26);
    expect(f.upstream.getDashboard).toHaveBeenCalledWith('tenant-a');
    expect(result.createdRisks).toBe(1);
    expect(result.informationalFindings).toBe(1);
    expect(f.evidence.get(result.evidenceId)).toMatchObject({organizationId:'tenant-a',createdBy:'actor-a',status:'pending_review',source:'cloudguard'});
    const risk=[...f.risks.values()][0];
    expect(risk).toMatchObject({organizationId:'tenant-a',status:'risk_identified',initialSeverity:'very_high'});
    expect(risk.documentation[0].evidenceId).toBe(result.evidenceId);
    const report=JSON.parse([...f.objects.values()][0].toString());
    expect(report.scan.findings).toHaveLength(2);
    expect(f.tx.$executeRaw).toHaveBeenCalled();
    expect(f.cache.del).toHaveBeenCalledWith('dashboard:full:tenant-a');
  });

  it('repeated imports preserve native review/treatment and do not duplicate evidence, risks, history or files', async () => {
    const f=fixture();
    const first=await f.service.importLatest('tenant-a','actor-a',26);
    const risk=[...f.risks.values()][0];
    Object.assign(risk,{status:'risk_analyzed',treatmentPlan:'mitigate',riskOwnerId:'owner-a'});
    f.evidence.get(first.evidenceId).status='approved';
    const second=await f.service.importLatest('tenant-a','actor-a',26);
    expect(second).toMatchObject({evidenceCreated:false,createdRisks:0,existingRisks:1,newObservations:0});
    expect(f.risks.size).toBe(1);expect(f.evidence.size).toBe(1);expect(f.history).toHaveLength(1);expect(f.objects.size).toBe(1);
    expect(risk).toMatchObject({status:'risk_analyzed',treatmentPlan:'mitigate',riskOwnerId:'owner-a'});
    expect(f.evidence.get(first.evidenceId).status).toBe('approved');
    expect(f.audit.log).toHaveBeenCalledTimes(1);
  });

  it('does not restore a deleted risk', async () => {
    const f=fixture();await f.service.importLatest('tenant-a','actor-a',26);
    [...f.risks.values()][0].deletedAt=new Date();
    const result=await f.service.importLatest('tenant-a','actor-a',26);
    expect(result.deletedRisksSkipped).toBe(1);expect(result.createdRisks).toBe(0);
  });

  it('deduplicates the same resource/issue across later scans', async () => {
    const f=fixture();await f.service.importLatest('tenant-a','actor-a',26);
    f.scan.id=27;f.scan.findings[0].id=201;
    const result=await f.service.importLatest('tenant-a','actor-a',27);
    expect(result.createdRisks).toBe(0);expect(result.existingRisks).toBe(1);
    expect(f.evidence.size).toBe(2);expect(f.history).toHaveLength(2);
  });

  it('rejects another organization and a changed latest scan before any write', async () => {
    const f=fixture();
    await expect(f.service.importLatest('tenant-a','actor-a',25)).rejects.toBeInstanceOf(ConflictException);
    await expect(f.service.importLatest('tenant-b','actor-b',26)).rejects.toBeInstanceOf(BadGatewayException);
    expect(f.storage.upload).not.toHaveBeenCalled();expect(f.tx.evidence.create).not.toHaveBeenCalled();
    expect(scanEvidenceId('tenant-a',26)).not.toBe(scanEvidenceId('tenant-b',26));
  });
});
