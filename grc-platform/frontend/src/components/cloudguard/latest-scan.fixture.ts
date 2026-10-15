import type { CloudGuardScanSnapshot } from '@/lib/api/cloudguard.api';

export const scanFixture: CloudGuardScanSnapshot = {
  id: 26, provider: 'kubernetes', account_id: 'cluster', started_at: null,
  finding_count: 2, resource_count: 93,
  severity_counts: {critical:1, high:0, medium:0, low:0, info:1},
  findings: [
    {id:101,control_id:'CIS Kubernetes',severity:'critical',title:'Privileged container',description:'Privileged container',resource:'pod-a',resource_type:'Pod',provider:'kubernetes',tool:'kubernetes',timestamp:null},
    {id:102,control_id:'CIS Kubernetes',severity:'info',title:'No IaC baseline',description:'No IaC baseline',resource:'cluster',resource_type:'Cluster',provider:'kubernetes',tool:'kubernetes',timestamp:null},
  ],
};
