import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../infra/prisma/prisma.service';

@Injectable()
export class SubscriptionsService {
  constructor(private readonly prisma: PrismaService) {}

  async getForOrg(_orgId: string) {
    // TODO: return Subscription + Plan join
  }

  /**
   * Flow node BJ. Called by billing-webhooks after a successful payment.
   */
  async upsertFromPayment(_input: {
    orgId: string;
    planId: string;
    razorpaySubscriptionId?: string | null;
    currentPeriodEnd?: Date | null;
  }) {
    // TODO: upsert; if plan changed, log audit event
  }

  async cancel(_orgId: string) {
    // TODO
  }
}
