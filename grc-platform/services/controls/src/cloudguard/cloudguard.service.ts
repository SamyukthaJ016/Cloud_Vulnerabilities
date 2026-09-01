import {
  BadGatewayException,
  GatewayTimeoutException,
  Injectable,
  Logger,
  ServiceUnavailableException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class CloudGuardService {
  private readonly logger = new Logger(CloudGuardService.name);

  constructor(private readonly configService: ConfigService) {}

  async getDashboard(organizationId: string): Promise<Record<string, unknown>> {
    const baseUrl = this.configService.get<string>('CLOUDGUARD_API_URL')?.trim();
    const connector = this.resolveTenantConnector(organizationId);

    if (!baseUrl) {
      throw new ServiceUnavailableException(
        'CloudGuard connector is not configured. Set CLOUDGUARD_API_URL and CLOUDGUARD_CONNECTOR_CREDENTIALS_JSON.',
      );
    }

    let endpoint: URL;
    try {
      endpoint = new URL('/api/connectors/grc/dashboard', baseUrl);
    } catch {
      throw new ServiceUnavailableException('CLOUDGUARD_API_URL is not a valid URL.');
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15_000);

    try {
      const response = await fetch(endpoint, {
        method: 'GET',
        headers: {
          Accept: 'application/json',
          Authorization: `Bearer ${connector.token}`,
          'X-Connector-ID': connector.connectorId,
        },
        signal: controller.signal,
      });

      if (!response.ok) {
        this.logger.warn(`CloudGuard connector returned HTTP ${response.status}`);
        throw new BadGatewayException(`CloudGuard connector returned HTTP ${response.status}.`);
      }

      return (await response.json()) as Record<string, unknown>;
    } catch (error) {
      if (error instanceof BadGatewayException) {
        throw error;
      }
      if (error instanceof Error && error.name === 'AbortError') {
        throw new GatewayTimeoutException('CloudGuard connector timed out.');
      }

      this.logger.warn(
        `CloudGuard connector request failed: ${error instanceof Error ? error.message : 'unknown error'}`,
      );
      throw new BadGatewayException('CloudGuard connector is currently unavailable.');
    } finally {
      clearTimeout(timeout);
    }
  }

  private resolveTenantConnector(organizationId: string): { connectorId: string; token: string } {
    const rawCredentials = this.configService.get<string>('CLOUDGUARD_CONNECTOR_CREDENTIALS_JSON')?.trim();
    if (!rawCredentials) {
      throw new ServiceUnavailableException('CloudGuard tenant connector credentials are not configured.');
    }

    try {
      const credentials = JSON.parse(rawCredentials) as Record<string, unknown>;
      const entry = credentials[organizationId];
      if (!entry || typeof entry !== 'object') {
        throw new Error('missing tenant credential');
      }
      const { connector_id: connectorId, token, tenant_id: tenantId, scopes } = entry as Record<string, unknown>;
      if (
        typeof connectorId !== 'string' ||
        !connectorId ||
        typeof token !== 'string' ||
        token.length < 32 ||
        tenantId !== organizationId ||
        !Array.isArray(scopes) ||
        !scopes.includes('grc:read')
      ) {
        throw new Error('invalid tenant credential');
      }
      return { connectorId, token };
    } catch {
      throw new ServiceUnavailableException(
        `CloudGuard connector credentials are missing or invalid for tenant ${organizationId}.`,
      );
    }
  }
}
