import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../infra/prisma/prisma.service';
import { VaultService } from '../../infra/vault/vault.service';

@Injectable()
export class SecretsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly vault: VaultService,
  ) {}

  /**
   * Flow nodes AC → AE. Transactional:
   *   1. encrypt-in-transit / avoid logging plaintext
   *   2. write to Vault
   *   3. persist metadata row
   *   4. caller writes audit log (via @AuditAction on the controller)
   */
  async createOrUpdate(_input: {
    orgId: string;
    userId: string;
    scannerKey?: string;
    key: string;
    value: string; // plaintext; must NEVER be logged or stored in DB
  }) {
    // TODO: implement
    //   - build vaultPath via vault.buildPath
    //   - vault.write(path, { value }) → version
    //   - prisma.secret.upsert({ ..., vaultPath, vaultVersion: version })
    throw new Error('SecretsService.createOrUpdate not implemented');
  }

  /**
   * Flow node CK. Returns metadata rows for scanner dispatch.
   * Never returns the secret value — call `readValue` separately.
   */
  async listMetadataForOrg(_orgId: string) {
    // TODO
  }

  async listForScanner(_orgId: string, _scannerKey: string) {
    // TODO
  }

  /**
   * Reserved for v2 (when scanner credentials are persisted). Service-to-service only.
   * Controllers MUST NOT expose this.
   */
  async readValue(_orgId: string, _secretId: string): Promise<string> {
    // TODO: verify Secret.orgId matches, then vault.read(secret.vaultPath, secret.vaultVersion)
    throw new Error('SecretsService.readValue not implemented');
  }

  async revoke(_orgId: string, _secretId: string) {
    // TODO
  }
}
