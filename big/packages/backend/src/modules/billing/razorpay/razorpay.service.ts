import { Injectable } from '@nestjs/common';
import { RazorpayClient } from './razorpay.client';

/**
 * Razorpay API wrapper. Wraps only the calls we actually use.
 * Do not leak Razorpay SDK types to other modules — translate to our own shapes.
 */
@Injectable()
export class RazorpayService {
  constructor(private readonly client: RazorpayClient) {}

  /** Flow node BC: create a payment order. */
  async createOrder(_input: {
    amountInPaise: number;
    currency: string;
    receipt: string;
    notes?: Record<string, string>;
  }): Promise<{ id: string; amount: number; currency: string; receipt: string }> {
    // TODO: client.rp.orders.create({...})
    throw new Error('RazorpayService.createOrder not implemented');
  }

  /** Used when subscription-based billing is enabled. */
  async createSubscription(_input: {
    planRazorpayId: string;
    totalCount: number;
    notes?: Record<string, string>;
  }): Promise<{ id: string; status: string }> {
    // TODO
    throw new Error('RazorpayService.createSubscription not implemented');
  }
}
