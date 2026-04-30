import type { SubscriptionStatus } from '../enums';
import type { PlanDto } from './plans';

export interface SubscriptionDto {
  id: string;
  status: SubscriptionStatus;
  startedAt: string;
  currentPeriodEnd: string | null;
  canceledAt: string | null;
  plan: PlanDto;
}
