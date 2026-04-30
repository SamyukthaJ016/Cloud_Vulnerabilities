/**
 * System Health & Resilience DTOs
 * 
 * These DTOs define the structure of system health checks
 * that help administrators ensure their deployment is production-ready.
 */

export enum HealthStatus {
  HEALTHY = 'healthy',
  WARNING = 'warning',
  CRITICAL = 'critical',
  UNKNOWN = 'unknown',
}

export enum CheckCategory {
  SECURITY = 'security',
  BACKUP = 'backup',
  DATABASE = 'database',
  STORAGE = 'storage',
  AUTHENTICATION = 'authentication',
  CONFIGURATION = 'configuration',
  PERFORMANCE = 'performance',
}

export interface HealthCheckResult {
  id: string;
  name: string;
  category: CheckCategory;
  status: HealthStatus;
  message: string;
  details?: Record<string, unknown>;
  recommendation?: string;
  documentationUrl?: string;
}

export interface SystemHealthResponse {
  overallStatus: HealthStatus;
  timestamp: string;
  environment: string;
  version: string;
  checks: HealthCheckResult[];
  summary: {
    total: number;
    healthy: number;
    warnings: number;
    critical: number;
  };
}

export interface BackupStatusResponse {
  configured: boolean;
  lastBackup?: string;
  lastBackupStatus?: 'success' | 'failed' | 'unknown';
  backupDestinations: {
    local: boolean;
    remote: boolean;
    remoteProvider?: string;
  };
  retentionDays: number;
  nextScheduledBackup?: string;
}

export interface SetupStatusResponse {
  isFirstRun: boolean;
  completedSteps: string[];
  pendingSteps: string[];
  setupProgress: number; // 0-100
}

export interface ProductionReadinessResponse {
  ready: boolean;
  score: number; // 0-100
  blockers: string[];
  warnings: string[];
  recommendations: string[];
}

