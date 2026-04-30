import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ScannerAvailability } from '@prisma/client';
import type { RefreshScannerResultDto } from '@cloudguard/shared';
import { PrismaService } from '../../infra/prisma/prisma.service';
import { DynamicScannerClient } from '../scanner-clients/dynamic-scanner.client';
import { discoverScannerSlots, ScannerEnvSlot } from './scanner-env';

/**
 * Populates the Scanner catalog from each configured scanner's /api/manifest.
 * Runs at boot (OnModuleInit) and via POST /admin/scanners/refresh. Resilient:
 * one bad scanner does not fail the whole sync.
 */
@Injectable()
export class ScannerSyncService implements OnModuleInit {
  private readonly logger = new Logger(ScannerSyncService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly client: DynamicScannerClient,
  ) {}

  async onModuleInit() {
    try {
      await this.refreshAll();
    } catch (err) {
      this.logger.error('Scanner manifest sync failed at boot', err as Error);
    }
  }

  async refreshAll(): Promise<RefreshScannerResultDto[]> {
    const slots = discoverScannerSlots();
    if (slots.length === 0) {
      this.logger.log('No SCANNER_<N>_BASE_URL env vars set — skipping manifest sync');
      return [];
    }
    const results: RefreshScannerResultDto[] = [];
    for (const slot of slots) {
      results.push(await this.refreshOne(slot));
    }
    return results;
  }

  private async refreshOne(slot: ScannerEnvSlot): Promise<RefreshScannerResultDto> {
    try {
      const manifest = await this.client.fetchManifest(slot.baseUrl);
      await this.prisma.scanner.upsert({
        where: { key: manifest.key },
        create: {
          key: manifest.key,
          name: manifest.name,
          description: manifest.description ?? null,
          version: manifest.version,
          category: manifest.category ?? null,
          baseUrlEnvKey: slot.baseUrlEnvKey,
          credentialSchema: manifest.credentialSchema as object,
          dashboardBaseUrl: manifest.dashboardBaseUrl,
          iconUrl: manifest.iconUrl ?? null,
          availability: ScannerAvailability.AVAILABLE,
          lastError: null,
          manifestFetchedAt: new Date(),
        },
        update: {
          name: manifest.name,
          description: manifest.description ?? null,
          version: manifest.version,
          category: manifest.category ?? null,
          baseUrlEnvKey: slot.baseUrlEnvKey,
          credentialSchema: manifest.credentialSchema as object,
          dashboardBaseUrl: manifest.dashboardBaseUrl,
          iconUrl: manifest.iconUrl ?? null,
          availability: ScannerAvailability.AVAILABLE,
          lastError: null,
          manifestFetchedAt: new Date(),
        },
      });
      this.logger.log(`Synced manifest for ${manifest.key} (${slot.baseUrlEnvKey})`);
      return { key: manifest.key, availability: 'AVAILABLE', error: null };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      this.logger.warn(`Manifest fetch failed for ${slot.baseUrlEnvKey}: ${message}`);
      // We can't upsert by manifest.key — we don't have it. Mark any existing
      // rows that point at this env slot as UNAVAILABLE instead.
      await this.prisma.scanner.updateMany({
        where: { baseUrlEnvKey: slot.baseUrlEnvKey },
        data: {
          availability: ScannerAvailability.UNAVAILABLE,
          lastError: message,
        },
      });
      return { key: slot.baseUrlEnvKey, availability: 'UNAVAILABLE', error: message };
    }
  }
}
