import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../infra/prisma/prisma.service';
import { RazorpayService } from './razorpay/razorpay.service';
import { PlansService } from '../plans/plans.service';

@Injectable()
export class BillingService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly razorpay: RazorpayService,
    private readonly plans: PlansService,
  ) {}

  /**
   * Flow node BA → BC. Creates a Razorpay order and persists a PaymentOrder
   * row for correlation when the webhook comes back.
   */
  async createCheckoutOrder(_input: { orgId: string; userId: string; planKey: string }): Promise<{
    orderId: string;
    amountInPaise: number;
    currency: string;
    keyId: string;
    planKey: string;
  }> {
    // TODO:
    //   1. plans.getByKey(planKey) → get amount
    //   2. razorpay.createOrder({ amount, currency, receipt: `org:${orgId}:${uuid}` })
    //   3. prisma.paymentOrder.create({ orgId, planId, razorpayOrderId, amount, status: CREATED })
    //   4. return order + public key id for frontend checkout SDK
    throw new Error('BillingService.createCheckoutOrder not implemented');
  }

  async listOrders(_orgId: string) {
    // TODO
  }
}
