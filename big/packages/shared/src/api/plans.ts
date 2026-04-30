import type { BillingInterval } from '../enums';

export interface PlanEntitlementDto {
  key: string; // e.g. 'max_scans_per_month', 'scanner.scanner_1.enabled'
  valueInt?: number;
  valueBool?: boolean;
  valueString?: string;
}

export interface PlanDto {
  id: string;
  key: string;
  name: string;
  description: string | null;
  priceInPaise: number;
  currency: string;
  billingInterval: BillingInterval;
  isActive: boolean;
  entitlements: PlanEntitlementDto[];
}
