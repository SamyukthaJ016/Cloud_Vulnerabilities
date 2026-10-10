"""Regression coverage for the September project review (no cloud API calls)."""
import asyncio
import json
import os
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
import yaml
from fastapi import HTTPException

from backend.kubeconfig_security import validate_kubeconfig
from backend.mcp_runtime import isolated_mcp_runtime, bind_mcp_owner
from backend.mcp_servers.base_server import mcp_server_manager
from backend.mcp.mcp_base import mcp_registry, ScanResult
from backend.tenant_security import cloudguard_auth_required, validate_auth_configuration


def kubeconfig():
    return {'clusters': [{'name': 'test', 'cluster': {'server': 'https://127.0.0.1:1'}}],
            'users': [{'name': 'test', 'user': {'token': 'dummy'}}],
            'contexts': [{'name': 'test', 'context': {'cluster': 'test', 'user': 'test'}}],
            'current-context': 'test'}


@pytest.mark.parametrize('section,key,field', [
    ('users', 'user', 'exec'), ('users', 'user', 'auth-provider'),
    ('users', 'user', 'tokenFile'), ('users', 'user', 'client-key'),
    ('users', 'user', 'client-certificate'), ('clusters', 'cluster', 'certificate-authority'),
])
def test_kubeconfig_rejects_execution_and_local_files(section, key, field):
    config = kubeconfig()
    config[section][0][key][field] = {'command': 'never-execute'} if field == 'exec' else '/private/test-secret'
    with pytest.raises(ValueError, match='forbidden'):
        validate_kubeconfig(yaml.safe_dump(config))


def test_embedded_kubeconfig_loads_without_network():
    from backend.mcp_servers.kubernetes_server import build_kubernetes_api_client
    client = build_kubernetes_api_client(yaml.safe_dump(kubeconfig()))
    assert client.configuration.auth_settings()['BearerToken']['value'] == 'Bearer dummy'
    client.close()


def test_sandbox_rejects_unsafe_stored_kubeconfig(api, monkeypatch):
    config = kubeconfig()
    config['users'][0]['user']['exec'] = {'command': 'never-execute'}
    credential = SimpleNamespace(kubernetes_context=None, kubernetes_kubeconfig=yaml.safe_dump(config))
    monkeypatch.setattr(api, '_credential_for_lab', lambda _: credential)
    with pytest.raises(ValueError, match='forbidden'):
        api._kube_clients_for_lab({}, require_enabled=False)


def test_cleanup_recognizes_deleted_resources_but_preserves_other_errors(api):
    from botocore.exceptions import ClientError
    missing = ClientError({'Error': {'Code': 'NoSuchBucket'}}, 'DeleteBucket')
    denied = ClientError({'Error': {'Code': 'AccessDenied'}}, 'DeleteBucket')
    assert api._cleanup_resource_absent(missing)
    assert not api._cleanup_resource_absent(denied)
    assert not api._cleanup_resource_absent(RuntimeError('unavailable'))


def test_mcp_concurrent_jobs_are_isolated_and_cleaned():
    async def run():
        ready = asyncio.Event()
        count = 0
        async def job(owner):
            nonlocal count
            async with isolated_mcp_runtime():
                bind_mcp_owner(owner)
                server = SimpleNamespace(provider='aws', stop=AsyncMock(), owner=owner)
                mcp_server_manager.register_server(server)
                mcp_registry.register('aws', server)
                count += 1
                if count == 2:
                    ready.set()
                await ready.wait()
                assert mcp_server_manager.get_server('aws').owner == owner
                assert mcp_registry.get_plugin('aws').owner == owner
                with pytest.raises(PermissionError):
                    bind_mcp_owner('someone-else')
            server.stop.assert_awaited_once()
        await asyncio.gather(job('user-a'), job('user-b'))
        async with isolated_mcp_runtime():
            assert mcp_server_manager.get_server('aws') is None
            assert mcp_registry.list_providers() == []
    asyncio.run(run())


@pytest.fixture
def api(monkeypatch):
    monkeypatch.setenv('PYTHON_DOTENV_DISABLED', '1')
    monkeypatch.setenv('DATABASE_URL', 'postgresql://unused@127.0.0.1:1/unused')
    monkeypatch.setenv('ENCRYPTION_KEY', 'review-test-key')
    monkeypatch.setenv('OPENAI_API_KEY', 'review-test-key')
    monkeypatch.setenv('APP_ENV', 'test')
    monkeypatch.setenv('NODE_ENV', 'test')
    monkeypatch.setenv('CLOUDGUARD_AUTH_REQUIRED', 'false')
    import backend.main as module
    return module


def test_ai_enabled_startup(api):
    client = api.create_optional_openai_client()
    assert client is not None
    client.close()


def test_mcp_result_conversion_preserves_findings_and_errors(api):
    payload = {
        'resources': [{'name': 'bucket', 'type': 's3_bucket'}],
        'findings': [
            {'resource': {'name': 'bucket', 'type': 's3_bucket'}, 'severity': 'high', 'issue': 'public'},
            {'resource': {'name': 'unlisted', 'type': 'iam_user'}, 'severity': 'LOW', 'issue': 'unused'},
        ],
        'errors': ['one scanner failed'],
    }
    result = api._mcp_to_scan_result('aws', payload)
    assert len(result.findings) == 2
    assert result.findings[0].severity.value == 'HIGH'
    assert result.findings[1].resource.name == 'unlisted'
    assert result.errors == ['one scanner failed']
    assert payload['findings'][0]['severity'] == 'high'  # Conversion does not mutate provider data.
    assert api._mcp_to_scan_result('aws', result) is result


def test_production_cannot_disable_auth(monkeypatch):
    monkeypatch.setenv('APP_ENV', 'production')
    monkeypatch.setenv('CLOUDGUARD_AUTH_REQUIRED', 'false')
    assert cloudguard_auth_required()
    with pytest.raises(RuntimeError, match='cannot be disabled'):
        validate_auth_configuration()


def test_production_requires_verifier_settings(monkeypatch):
    monkeypatch.setenv('APP_ENV', 'production')
    monkeypatch.setenv('CLOUDGUARD_AUTH_REQUIRED', 'true')
    for key in ('KEYCLOAK_ISSUER', 'KEYCLOAK_AUDIENCE', 'KEYCLOAK_JWKS_URL'):
        monkeypatch.delenv(key, raising=False)
    with pytest.raises(RuntimeError, match='KEYCLOAK'):
        validate_auth_configuration()


def test_worker_encryption_handoff_and_failure(api, monkeypatch):
    from backend.credentials.manager import CredentialManager, CredentialDecryptionError
    saved = CredentialManager().encrypt('dummy-cloud-credential')
    assert CredentialManager().decrypt(saved) == 'dummy-cloud-credential'
    monkeypatch.setenv('ENCRYPTION_KEY', 'wrong-key')
    with pytest.raises(CredentialDecryptionError):
        CredentialManager().decrypt(saved)
    monkeypatch.delenv('ENCRYPTION_KEY')
    monkeypatch.setenv('CREDENTIAL_ENCRYPTION_REQUIRED', 'true')
    with pytest.raises(ValueError, match='ENCRYPTION_KEY'):
        CredentialManager()


@pytest.mark.parametrize('provider', ['aws', 'gcp', 'kubernetes'])
def test_selected_credential_is_never_replaced_by_default(api, monkeypatch, provider):
    from backend.credentials.manager import CredentialManager, CloudCredential
    manager = CredentialManager()
    selected = CloudCredential(id=42, user_id='user-a', cloud_provider=provider, credential_name='selected')
    monkeypatch.setattr(manager, 'get_credential_by_id', MagicMock(return_value=selected))
    default = MagicMock(side_effect=AssertionError('Default must not be used'))
    monkeypatch.setattr(manager, 'get_default_credential', default)
    assert manager.resolve_scan_credential('user-a', provider, 42) is selected
    with pytest.raises(ValueError):
        manager.resolve_scan_credential('user-b', provider, 42)
    with pytest.raises(ValueError):
        manager.resolve_scan_credential('user-a', 'wrong-provider', 42)
    default.assert_not_called()


def test_html_navigation_bootstraps_but_data_requires_auth(api, monkeypatch):
    monkeypatch.setenv('CLOUDGUARD_AUTH_REQUIRED', 'true')
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=api.app), base_url='http://test') as client:
            for path in ['/history', '/scheduled_scans', '/schedules', '/login', '/signup']:
                response = await client.get(path)
                assert response.status_code == 200, (path, response.text)
                assert 'text/html' in response.headers['content-type']
            for path in ['/api/memory/dashboard', '/api/scan-jobs', '/providers', '/scan/multi-cloud']:
                assert (await client.get(path)).status_code == 401
    asyncio.run(run())


def test_signup_requires_verified_identity(api, monkeypatch):
    monkeypatch.setenv('CLOUDGUARD_AUTH_REQUIRED', 'true')
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=api.app), base_url='http://test') as client:
            assert (await client.post('/api/auth/onboard')).status_code == 401
            assert (await client.post('/api/auth/onboard', headers={'Authorization': 'Bearer forged'})).status_code == 401
    asyncio.run(run())


def test_raw_mcp_dispatch_is_retired(api):
    with pytest.raises(HTTPException) as error:
        asyncio.run(api.send_mcp_request('aws', {'method': 'tools/list'}))
    assert error.value.status_code == 410


@pytest.mark.parametrize('attempts,expected', [(1, 'queued'), (3, 'dead_letter')])
def test_provider_errors_enter_retry_policy(api, monkeypatch, attempts, expected):
    job = dict(job_id='job-test', providers=['aws'], account_ids={}, deep_scan=False,
               user_id='user-a', tenant_id='tenant-a', credential_id=1, offensive_scan=False,
               attempts=attempts, max_attempts=3)
    monkeypatch.setattr(api, 'start_scan_job', lambda _: job)
    result = ScanResult('aws', 'test', [], [], errors=['provider offline'])
    monkeypatch.setattr(api, 'run_multi_cloud_scan_internal', AsyncMock(return_value={'scan_ids': [1], 'scan_results': [result]}))
    monkeypatch.setattr(api, '_store_scan_job_evidence', lambda *_: None)
    monkeypatch.setattr(api, 'update_scan_job', lambda job_id, status, **updates: {'status': status, **updates})
    updated = asyncio.run(api.process_scan_job('job-test'))
    assert updated['status'] == expected
    assert 'provider offline' in updated['error']
    assert updated['result']['status'] == 'failed'
    assert updated['scan_ids'] == [1]


def test_mixed_provider_results_are_explicitly_partial(api):
    result = api.format_scan_completion_response([], [ScanResult('aws', 'a', [], []), ScanResult('gcp', 'b', [], [], errors=['offline'])], {})
    assert result['status'] == 'partial'
    assert result['errors'] == {'gcp': ['offline']}


def test_enhanced_scan_does_not_resolve_memory_after_provider_failure(api, monkeypatch):
    from starlette.requests import Request
    from backend.tenant_security import RequestIdentity
    req = Request({'type': 'http', 'method': 'POST', 'path': '/', 'headers': []})
    req.state.identity = RequestIdentity('user-a', 'tenant-a', '')
    monkeypatch.setattr(api, 'initialize_mcp_servers_for_user', AsyncMock())
    monkeypatch.setattr(api.mcp_registry, 'scan', AsyncMock(return_value=ScanResult('gcp', 'test', [], [], errors=['offline'])))
    monkeypatch.setattr(api, 'store_scan_result', AsyncMock(return_value=1))
    memory = MagicMock()
    memory.get_dashboard_summary.return_value = {}
    monkeypatch.setattr(api, 'memory_system', SimpleNamespace(for_owner=lambda *_: memory))
    monkeypatch.setattr(api, 'multi_agent_analyzer', SimpleNamespace(analyze=AsyncMock(return_value={})))
    result = asyncio.run(api.multi_cloud_scan_enhanced(api.MultiCloudScanRequest(providers=['gcp']), req))
    assert result['status'] == 'failed'
    assert result['errors'] == {'gcp': ['offline']}
    memory.process_scan_findings.assert_not_called()


@pytest.mark.parametrize('provider_fails,evidence_fails,expected', [(True, False, 'failed'), (False, True, 'destroyed')])
def test_cleanup_failure_never_strands_lab(api, monkeypatch, provider_fails, evidence_fails, expected):
    from backend import cleanup_lease
    lab = dict(lab_id='lab-test', status='scanning', user_id='user-a', tenant_id='tenant-a', provider='iac')
    @contextmanager
    def lease(_):
        yield True
    monkeypatch.setattr(cleanup_lease, 'sandbox_cleanup_lease', lease)
    monkeypatch.setattr(api, 'get_sandbox_lab_run', lambda *a, **k: dict(lab))
    def update(_, **fields):
        lab.update(fields)
        return dict(lab)
    monkeypatch.setattr(api, 'update_sandbox_lab', update)
    monkeypatch.setattr(api, 'add_sandbox_lab_event', lambda *a: None)
    cleanup = MagicMock(side_effect=RuntimeError('provider offline')) if provider_fails else MagicMock(return_value={'errors': []})
    monkeypatch.setattr(api, '_destroy_sandbox_lab_resources', cleanup)
    monkeypatch.setattr(api, 'store_evidence_artifact', MagicMock(side_effect=RuntimeError('storage offline')) if evidence_fails else MagicMock(return_value={'evidence_id': 'proof'}))
    if provider_fails:
        with pytest.raises(RuntimeError, match='provider offline'):
            asyncio.run(api.destroy_sandbox_lab('lab-test'))
        assert lab['cleanup_payload']['retry_cleanup'] is True
    else:
        asyncio.run(api.destroy_sandbox_lab('lab-test'))
        assert lab['cleanup_payload']['evidence_error'] == 'storage offline'
    assert lab['status'] == expected


def test_unscoped_memory_is_forbidden():
    from backend.ai.persistent_memory import PersistentMemorySystem
    with pytest.raises(ValueError, match='Unscoped'):
        PersistentMemorySystem().get_dashboard_summary()
