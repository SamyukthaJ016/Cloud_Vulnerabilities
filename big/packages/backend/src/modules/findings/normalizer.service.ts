import { Injectable } from '@nestjs/common';
import { Severity } from '@prisma/client';

/**
 * Flow node K1: normalize scanner-specific findings into the shared schema.
 *
 * Every scanner POSTs results in its own shape. This service converts them into
 * the canonical `NormalizedFinding` shape that we persist to the `Finding` table.
 */
@Injectable()
export class NormalizerService {
  /**
   * Dispatch on `scannerKey`. Each scanner has its own mapping function.
   * Unknown scanners raise — we do NOT silently drop findings.
   */
  normalize(scannerKey: string, _raw: unknown): NormalizedFinding[] {
    switch (scannerKey) {
      case 'scanner_1': // TODO
      case 'scanner_2': // TODO
      case 'scanner_3': // TODO
      case 'scanner_4': // TODO
      default:
        throw new Error(`No normalizer for scanner '${scannerKey}'`);
    }
  }
}

export interface NormalizedFinding {
  externalId?: string;
  title: string;
  description?: string;
  severity: Severity;
  resource?: string;
  evidence?: Record<string, unknown>;
  recommendation?: string;
  tags: string[];
}
