import type { CheckoutResponseDto } from '@cloudguard/shared';

const CHECKOUT_SRC = 'https://checkout.razorpay.com/v1/checkout.js';

/**
 * Lazy-load Razorpay Checkout SDK and open the modal.
 * SDK attaches `window.Razorpay`.
 */
export async function openRazorpayCheckout(order: CheckoutResponseDto): Promise<void> {
  await loadScript(CHECKOUT_SRC);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const Razorpay = (window as unknown as { Razorpay: new (opts: unknown) => { open(): void } }).Razorpay;
  if (!Razorpay) throw new Error('Razorpay SDK failed to load');

  const rp = new Razorpay({
    key: order.keyId,
    order_id: order.orderId,
    amount: order.amountInPaise,
    currency: order.currency,
    name: 'CloudGuard',
    description: `Plan: ${order.planKey}`,
    // On modal success, Razorpay POSTs a webhook to backend.
    // Frontend does NOT verify here — truth comes from the webhook.
    handler: () => {
      // no-op; subscription refresh happens via WS event
    },
    modal: {
      ondismiss: () => {
        /* user closed modal — nothing to do */
      },
    },
    prefill: {},
    theme: { color: '#000000' },
  });
  rp.open();
}

function loadScript(src: string): Promise<void> {
  return new Promise((resolve, reject) => {
    if (document.querySelector(`script[src="${src}"]`)) return resolve();
    const s = document.createElement('script');
    s.src = src;
    s.async = true;
    s.onload = () => resolve();
    s.onerror = () => reject(new Error(`Failed to load ${src}`));
    document.head.appendChild(s);
  });
}
