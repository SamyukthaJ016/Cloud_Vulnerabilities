import { api } from './client';

export type CloudGuardSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface CloudGuardFinding {
  control_id: string;
  severity: CloudGuardSeverity;
  title: string;
  recommendation?: string | null;
  resource?: string | null;
}

export interface CloudGuardControl {
  control_id: string;
  control_name: string;
  framework: string;
  status: 'compliant' | 'partial' | 'non_compliant' | 'no_evidence';
  evidence_count: number;
  finding_count: number;
  severity_counts: Record<CloudGuardSeverity, number>;
  sources: string[];
  latest_evidence_at?: string | null;
  sample_findings: CloudGuardFinding[];
}

export interface CloudGuardWorker {
  worker_id: string;
  worker_type: string;
  status: string;
  online: boolean;
  age_seconds: number;
  last_seen_at?: string | null;
  metadata?: Record<string, unknown>;
}

export interface CloudGuardDashboardResponse {
  status: string;
  generated_at: string;
  compliance: {
    status: string;
    generated_at: string;
    framework: string;
    score: number;
    counts: {
      total_controls: number;
      compliant: number;
      partial: number;
      non_compliant: number;
      no_evidence: number;
      evidence_artifacts: number;
      findings: number;
    };
    source_counts: Record<string, number>;
    severity_by_source: Record<string, Record<CloudGuardSeverity, number>>;
    evidence_review_counts: {
      system_generated: number;
      manual_uploaded: number;
      pending_review: number;
      approved: number;
    };
    controls: CloudGuardControl[];
  };
  evidence: Array<{
    evidence_id: string;
    job_id?: string | null;
    source_system: string;
    scanner_type: string;
    created_at?: string | null;
  }>;
  workers: {
    status: string;
    scan_workers_online: boolean;
    worker_counts: Record<string, number>;
    online_counts: Record<string, number>;
    workers: CloudGuardWorker[];
  };
}

export const cloudGuardApi = {
  dashboard: async () => {
    const response = await api.get<CloudGuardDashboardResponse>('/api/cloudguard/dashboard');
    return response.data;
  },
};
