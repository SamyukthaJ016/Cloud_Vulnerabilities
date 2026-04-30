import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../infra/prisma/prisma.service';

/**
 * Plan-level entitlements (quota, feature flags by plan).
 * Distinct from RBAC (role permissions).
 *
 * Flow nodes CG, CH: "Check subscription / entitlement / quota / concurrency limit"
 * and "Scanner included in active plan and within limits?"
 */
@Injectable()
export class EntitlementsService {
  constructor(private readonly prisma: PrismaService) {}

  /**
   * Returns the numeric/bool entitlement value for an org.
   * Resolves via: org → Subscription → Plan → PlanEntitlement.
   */
  async get(_orgId: string, _key: string): Promise<EntitlementValue | null> {
    // TODO
    return null;
  }

  /**
   * Check if a scanner is enabled for the org's current plan.
   * Key convention: `scanner.${scannerKey}.enabled`
   */
  async isScannerEnabled(_orgId: string, _scannerKey: string): Promise<boolean> {
    // TODO
    return false;
  }

  /**
   * Returns remaining quota for `max_scans_per_month` after counting
   * completed scans in the current billing period.
   */
  async remainingScanQuota(_orgId: string): Promise<number> {
    // TODO
    return 0;
  }

  /**
   * Current in-flight scans vs `max_concurrent_scans` entitlement.
   */
  async hasConcurrencyHeadroom(_orgId: string): Promise<boolean> {
    // TODO
    return true;
  }
}

export type EntitlementValue =
  | { type: 'int'; value: number }
  | { type: 'bool'; value: boolean }
  | { type: 'string'; value: string };
