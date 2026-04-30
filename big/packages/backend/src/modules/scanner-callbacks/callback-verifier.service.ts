import { Injectable } from '@nestjs/common';
import { createHmac, timingSafeEqual } from 'crypto';
import { resolveSlotByEnvKey } from '../scanners/scanner-env';

/**
 * Verifies inbound scanner-service callback signatures.
 * Caller looks up the scanner's shared secret by Scanner.baseUrlEnvKey and
 * passes it in. Format: HMAC-SHA256(rawBody || '.' || nonce) hex.
 */
@Injectable()
export class CallbackVerifierService {
  resolveSharedSecret(baseUrlEnvKey: string): string | undefined {
    const slot = resolveSlotByEnvKey(baseUrlEnvKey);
    return slot?.sharedSecret || undefined;
  }

  verify(rawBody: Buffer, nonce: string, signatureHeader: string, secret: string): boolean {
    const data = Buffer.concat([rawBody, Buffer.from('.' + nonce, 'utf8')]);
    const expected = createHmac('sha256', secret).update(data).digest('hex');
    const provided = Buffer.from(signatureHeader, 'utf8');
    const computed = Buffer.from(expected, 'utf8');
    if (provided.length !== computed.length) return false;
    return timingSafeEqual(provided, computed);
  }
}
