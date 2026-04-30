import type { PaymentStatus } from '../enums';

export interface CreateCheckoutDto {
  planKey: string;
}

/**
 * Response from POST /billing/checkout.
 * Frontend passes these to Razorpay Checkout SDK.
 */
export interface CheckoutResponseDto {
  orderId: string;
  amountInPaise: number;
  currency: string;
  keyId: string;
  planKey: string;
}

export interface PaymentOrderDto {
  id: string;
  razorpayOrderId: string;
  razorpayPaymentId: string | null;
  amountInPaise: number;
  currency: string;
  status: PaymentStatus;
  createdAt: string;
  updatedAt: string;
}
