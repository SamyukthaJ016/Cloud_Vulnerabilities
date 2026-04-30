import { Injectable, Logger } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { createHmac, randomBytes } from 'crypto';
import { firstValueFrom } from 'rxjs';
import type { ScannerManifest } from '@cloudguard/shared';
import {
  ScannerRunAck,
  ScannerRunRequest,
  ScannerViewTokenResponse,
} from './base/scanner.interface';

const MANIFEST_TIMEOUT_MS = 5_000;
const SCAN_TIMEOUT_MS = 10_000;

/**
 * Stateless HTTP client for any scanner that implements the manifest contract.
 * The caller supplies baseUrl + sharedSecret per-call (looked up from env).
 */
@Injectable()
export class DynamicScannerClient {
  private readonly logger = new Logger(DynamicScannerClient.name);

  constructor(private readonly http: HttpService) {}

  async fetchManifest(baseUrl: string): Promise<ScannerManifest> {
    const response = await firstValueFrom(
      this.http.get<ScannerManifest>(`${baseUrl}/api/manifest`, {
        timeout: MANIFEST_TIMEOUT_MS,
      }),
    );
    return response.data;
  }

  async run(
    baseUrl: string,
    sharedSecret: string,
    request: ScannerRunRequest,
  ): Promise<ScannerRunAck> {
    const rawBody = Buffer.from(JSON.stringify(request), 'utf8');
    const signature = sign(rawBody, request.nonce, sharedSecret);

    const response = await firstValueFrom(
      this.http.post<ScannerRunAck>(`${baseUrl}/api/scan`, request, {
        headers: {
          'Content-Type': 'application/json',
          'X-Scanner-Nonce': request.nonce,
          'X-Scanner-Signature': signature,
        },
        timeout: SCAN_TIMEOUT_MS,
      }),
    );
    return response.data;
  }

  async fetchViewToken(
    baseUrl: string,
    sharedSecret: string,
    externalScanId: string,
  ): Promise<ScannerViewTokenResponse> {
    const nonce = randomBytes(16).toString('hex');
    const body = { scanId: externalScanId };
    const rawBody = Buffer.from(JSON.stringify(body), 'utf8');
    const signature = sign(rawBody, nonce, sharedSecret);

    const response = await firstValueFrom(
      this.http.post<ScannerViewTokenResponse>(
        `${baseUrl}/api/scans/${externalScanId}/view-token`,
        body,
        {
          headers: {
            'Content-Type': 'application/json',
            'X-Scanner-Nonce': nonce,
            'X-Scanner-Signature': signature,
          },
          timeout: SCAN_TIMEOUT_MS,
        },
      ),
    );
    return response.data;
  }
}

function sign(rawBody: Buffer, nonce: string, secret: string): string {
  const toSign = Buffer.concat([rawBody, Buffer.from('.' + nonce, 'utf8')]);
  return createHmac('sha256', secret).update(toSign).digest('hex');
}
