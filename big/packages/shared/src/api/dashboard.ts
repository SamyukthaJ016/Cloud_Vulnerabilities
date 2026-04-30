import type { PermissionKey } from '../enums';
import type { OrganizationDto } from './organizations';
import type { RoleDto } from './rbac';
import type { SubscriptionDto } from './subscriptions';
import type { ScannerDto } from './scanners';
import type { SecretMetadataDto } from './secrets';
import type { ScanJobDto } from './scans';
import type { FindingDto } from './findings';

/**
 * Response from GET /dashboard/bootstrap — flow nodes R → X5.
 * Single query that powers every tile on the dashboard shell.
 */
export interface DashboardBootstrapDto {
  organization: OrganizationDto;
  role: Pick<RoleDto, 'key' | 'name'>;
  permissions: PermissionKey[];
  subscription: SubscriptionDto | null;
  scanners: ScannerDto[];
  secrets: SecretMetadataDto[];
  metrics: {
    scansLast30Days: number;
    openFindings: number;
    activeScanners: number;
    totalFindings: number;
  };
  recent: {
    scans: Pick<
      ScanJobDto,
      'id' | 'scannerKey' | 'status' | 'completedAt' | 'summary'
    >[];
    findings: Pick<
      FindingDto,
      'id' | 'title' | 'severity' | 'scannerKey' | 'createdAt'
    >[];
  };
}
