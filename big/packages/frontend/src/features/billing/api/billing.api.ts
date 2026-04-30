import { useMutation } from '@tanstack/react-query';
import { http } from '@/api/http';
import type { CheckoutResponseDto, CreateCheckoutDto } from '@cloudguard/shared';
import { openRazorpayCheckout } from './razorpay';

/**
 * End-to-end checkout flow.
 *   1. POST /billing/checkout → order
 *   2. Load Razorpay Checkout SDK if needed
 *   3. Open modal with order id
 *   4. On modal success: backend webhook updates subscription; we wait for
 *      `billing.updated` WS event + invalidate queries.
 */
export function useCheckout() {
  return useMutation({
    mutationFn: async (dto: CreateCheckoutDto): Promise<CheckoutResponseDto> => {
      const { data } = await http.post<CheckoutResponseDto>('/billing/checkout', dto);
      await openRazorpayCheckout(data);
      return data;
    },
  });
}
