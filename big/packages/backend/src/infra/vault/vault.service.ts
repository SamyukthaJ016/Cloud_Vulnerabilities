import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

/**
 * HashiCorp Vault KV v2 client wrapper.
 *
 * Path convention:   `{mount}/data/{orgPathPrefix}/{orgId}/{scannerKey?}/{key}`
 * e.g.               `secret/data/orgs/abc123/scanner_1/aws_access_key`
 *
 * Used by `secrets` module for writes (flow AD). Scanner v1 does NOT use Vault —
 * credentials are entered per-scan in the modal, forwarded once to the scanner,
 * and never persisted.
 *
 * TODO (secrets module owner):
 *   - wire actual node-vault client (or a small axios wrapper) in onModuleInit
 *   - implement write/read/delete/listVersions
 *   - never log secret values; use vaultPath + version only
 */
@Injectable()
export class VaultService {
  private readonly logger = new Logger(VaultService.name);

  constructor(private readonly config: ConfigService) {}

  /** Build the canonical vault path for a secret. */
  buildPath(orgId: string, key: string, scannerKey?: string | null): string {
    const mount = this.config.get<string>('vault.kvMount');
    const prefix = this.config.get<string>('vault.orgPathPrefix');
    const segments = [mount, 'data', prefix, orgId, scannerKey, key].filter(Boolean);
    return segments.join('/');
  }

  async write(_path: string, _value: Record<string, unknown>): Promise<{ version: number }> {
    throw new Error('VaultService.write not implemented');
  }

  async read(_path: string, _version?: number): Promise<Record<string, unknown>> {
    throw new Error('VaultService.read not implemented');
  }

  async revoke(_path: string): Promise<void> {
    throw new Error('VaultService.revoke not implemented');
  }
}
