import { ServiceUnavailableException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { CloudGuardService } from './cloudguard.service';

describe('CloudGuardService tenant connector isolation', () => {
  const tenantCredentials = JSON.stringify({
    'tenant-a': {
      connector_id: 'grc-tenant-a',
      token: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      tenant_id: 'tenant-a',
      user_id: 'cloudguard-user-a',
      scopes: ['grc:read'],
    },
    'tenant-b': {
      connector_id: 'grc-tenant-b',
      token: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      tenant_id: 'tenant-b',
      user_id: 'cloudguard-user-b',
      scopes: ['grc:read'],
    },
  });

  let fetchMock: jest.Mock;

  beforeEach(() => {
    fetchMock = jest.fn().mockResolvedValue({
      ok: true,
      json: jest.fn().mockResolvedValue({ status: 'ok' }),
    });
    global.fetch = fetchMock as unknown as typeof fetch;
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  function createService(credentials = tenantCredentials) {
    const values: Record<string, string> = {
      CLOUDGUARD_API_URL: 'https://cloudguard.internal',
      CLOUDGUARD_CONNECTOR_CREDENTIALS_JSON: credentials,
    };
    const config = {
      get: jest.fn((name: string) => values[name]),
    } as unknown as ConfigService;
    return new CloudGuardService(config);
  }

  it('uses only the connector configured for the authenticated GRC organization', async () => {
    await createService().getDashboard('tenant-a');

    const [, init] = fetchMock.mock.calls[0] as [URL, RequestInit];
    expect(init.headers).toEqual({
      Accept: 'application/json',
      Authorization: 'Bearer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      'X-Connector-ID': 'grc-tenant-a',
    });
  });

  it('refuses a tenant that has no connector credential instead of using a fallback account', async () => {
    await expect(createService().getDashboard('tenant-c')).rejects.toBeInstanceOf(ServiceUnavailableException);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('refuses a connector whose tenant_id does not match the requested organization', async () => {
    const mismatched = JSON.stringify({
      'tenant-a': {
        connector_id: 'grc-tenant-a',
        token: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        tenant_id: 'tenant-b',
        user_id: 'cloudguard-user-b',
        scopes: ['grc:read'],
      },
    });

    await expect(createService(mismatched).getDashboard('tenant-a')).rejects.toBeInstanceOf(
      ServiceUnavailableException,
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
