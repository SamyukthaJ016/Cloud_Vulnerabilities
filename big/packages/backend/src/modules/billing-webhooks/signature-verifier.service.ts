import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createHmac, timingSafeEqual } from 'crypto';

/**
 * Verifies inbound Razorpay webhook signatures. Flow node BG.
 *
 * Razorpay docs: HMAC SHA256 of the raw body keyed by RAZORPAY_WEBHOOK_SECRET,
 * compared against the `X-Razorpay-Signature` header.
 */
@Injectable()
export class SignatureVerifierService {
  constructor(private readonly config: ConfigService) {}

  verify(rawBody: Buffer | string, signatureHeader: string): boolean {
    const secret = this.config.get<string>('razorpay.webhookSecret')!;
    const expected = createHmac('sha256', secret).update(rawBody).digest('hex');
    const provided = Buffer.from(signatureHeader, 'utf8');
    const computed = Buffer.from(expected, 'utf8');
    if (provided.length !== computed.length) return false;
    return timingSafeEqual(provided, computed);
  }
}
