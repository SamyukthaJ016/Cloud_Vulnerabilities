import { ComingSoon } from '@/components/ComingSoon';

export function BillingPage() {
  return (
    <ComingSoon
      title="Billing"
      description="Current subscription, payment history, and Razorpay checkout."
      flowNodes="X2, BA → BD"
    />
  );
}
