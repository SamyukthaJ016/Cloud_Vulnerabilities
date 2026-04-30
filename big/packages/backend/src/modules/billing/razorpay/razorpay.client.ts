import { Injectable, ServiceUnavailableException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Razorpay from 'razorpay';

/**
 * Lazy-instantiated Razorpay SDK wrapper.
 *
 * The Razorpay constructor throws when key_id is missing, so we defer
 * instantiation to first use. Lets the app boot even before billing
 * credentials are configured (e.g. while only auth/dashboard are wired).
 */
@Injectable()
export class RazorpayClient {
  private instance?: Razorpay;

  constructor(private readonly config: ConfigService) {}

  get rp(): Razorpay {
    if (!this.instance) {
      const keyId = this.config.get<string>('razorpay.keyId');
      const keySecret = this.config.get<string>('razorpay.keySecret');
      if (!keyId || !keySecret) {
        throw new ServiceUnavailableException(
          'Billing is not configured: RAZORPAY_KEY_ID / RAZORPAY_KEY_SECRET missing',
        );
      }
      this.instance = new Razorpay({ key_id: keyId, key_secret: keySecret });
    }
    return this.instance;
  }
}
