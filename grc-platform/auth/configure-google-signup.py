#!/usr/bin/env python3
"""Configure Google brokering and registration using a short-lived admin token.

Reads secrets from environment; never writes them to files or prints responses.
Run against the intended realm after creating Google OAuth credentials.
"""
import json
import os
from pathlib import Path
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError


def configure():
    base = os.environ['KEYCLOAK_URL'].rstrip('/')
    if urlparse(base).scheme != 'https' and urlparse(base).hostname not in {'localhost', '127.0.0.1', 'keycloak'}:
        raise ValueError('Use HTTPS for the Keycloak URL')
    realm = quote(os.getenv('KEYCLOAK_REALM', 'gigachad-grc'), safe='')
    token = os.environ['KEYCLOAK_ADMIN_TOKEN']
    client_id = os.environ['GOOGLE_OAUTH_CLIENT_ID']
    secret = os.environ['GOOGLE_OAUTH_CLIENT_SECRET']
    if not all((token, client_id, secret)):
        raise ValueError('Admin token and Google OAuth credentials must be nonempty')

    def request(method, path, payload=None):
        body = json.dumps(payload).encode() if payload is not None else None
        req = Request(f'{base}/admin/realms/{realm}{path}', data=body, method=method,
                      headers={'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'})
        with urlopen(req, timeout=30) as response:
            data = response.read()
            return json.loads(data) if data else None

    # Protect tenant assignment before opening registration. Preserve unrelated
    # existing profile attributes, while making organization_id admin-editable.
    profile = request('GET', '/users/profile')
    template = json.loads(Path(__file__).with_name('user-profile.json').read_text())
    organization = next(attr for attr in template['attributes'] if attr['name'] == 'organization_id')
    profile['attributes'] = [attr for attr in profile['attributes'] if attr['name'] != 'organization_id'] + [organization]
    profile['unmanagedAttributePolicy'] = 'ADMIN_EDIT'
    request('PUT', '/users/profile', profile)

    providers = request('GET', '/identity-provider/instances')
    provider = next((item for item in providers if item['alias'] == 'google'), None)
    if provider and provider['providerId'] != 'google':
        raise ValueError('The google alias is already used by a different provider')
    payload = dict(provider or {})
    payload.update(alias='google', providerId='google', enabled=True, trustEmail=False,
                   storeToken=False, firstBrokerLoginFlowAlias='first broker login')
    payload['config'] = {**payload.get('config', {}), 'clientId': client_id, 'clientSecret': secret,
                         'defaultScope': 'openid profile email', 'syncMode': 'IMPORT'}
    request('PUT' if provider else 'POST', '/identity-provider/instances/google' if provider else '/identity-provider/instances', payload)
    request('PUT', '', {'registrationAllowed': True, 'registrationEmailAsUsername': True,
                        'verifyEmail': True, 'duplicateEmailsAllowed': False})
    print('Google sign-in and verified email registration configured.')
    print(f'Google authorized redirect URI: {base}/realms/{realm}/broker/google/endpoint')


if __name__ == '__main__':
    try:
        configure()
    except HTTPError as exc:
        raise SystemExit(f'Keycloak configuration failed (HTTP {exc.code}); response omitted to protect secrets.')
    except (KeyError, ValueError) as exc:
        raise SystemExit(f'Configuration error: {exc}')
