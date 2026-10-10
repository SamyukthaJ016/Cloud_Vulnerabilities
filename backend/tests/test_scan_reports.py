"""Report response regressions using mocked, tenant-scoped database results."""

import asyncio
from unittest.mock import MagicMock

import httpx
import pytest

from backend.tenant_security import RequestIdentity


@pytest.fixture
def api(monkeypatch):
    monkeypatch.setenv('PYTHON_DOTENV_DISABLED', '1')
    monkeypatch.setenv('DATABASE_URL', 'postgresql://unused@127.0.0.1:1/unused')
    monkeypatch.setenv('ENCRYPTION_KEY', 'report-test-key')
    monkeypatch.setenv('APP_ENV', 'test')
    monkeypatch.setenv('NODE_ENV', 'test')
    monkeypatch.setenv('CLOUDGUARD_AUTH_REQUIRED', 'false')
    for key in ('OPENAI_API_KEY', 'AI_API_KEY', 'OPENAI_BASE_URL', 'AI_BASE_URL'):
        monkeypatch.delenv(key, raising=False)
    import backend.main as module
    return module


def test_json_and_pdf_reports(api, monkeypatch):
    # A resource with multiple findings counts once; clean resources still count.
    rows = [
        (1, 'bucket', 'AWS', 's3_bucket', True, 'HIGH', 'Public access'),
        (1, 'bucket', 'AWS', 's3_bucket', True, 'MEDIUM', 'Missing logging'),
        (2, 'bucket', 'GCP', 'storage_bucket', False, None, None),
    ]
    query = MagicMock(return_value=rows)
    monkeypatch.setattr(api, 'get_scan_report', query)
    monkeypatch.setattr(api, 'request_identity', lambda _: RequestIdentity('user-a', 'tenant-a', ''))

    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=api.app), base_url='http://test') as client:
            response = await client.get('/report/42')
            assert response.status_code == 200
            report = response.json()
            assert report['scan_id'] == 42
            assert report['providers'] == ['aws', 'gcp']
            assert report['total_resources'] == 2
            assert report['total_findings'] == 2
            assert report['findings'][0] == {
                'resource_id': 1, 'resource_name': 'bucket', 'cloud': 'aws',
                'type': 's3_bucket', 'public': True, 'severity': 'HIGH',
                'description': 'Public access',
            }
            assert len(report['findings']) == 2
            query.assert_called_with(42, 'user-a', 'tenant-a')

            response = await client.get('/report/42/pdf')
            assert response.status_code == 200
            assert response.headers['content-type'] == 'application/pdf'
            assert 'cloudguard_report_42.pdf' in response.headers['content-disposition']
            assert response.content.startswith(b'%PDF-')
            query.assert_called_with(42, 'user-a', 'tenant-a')

    asyncio.run(run())


def test_report_includes_resources_without_findings(api, monkeypatch):
    monkeypatch.setattr(api, 'get_scan_report', lambda *_: [
        (1, 'clean-bucket', 'AWS', 's3_bucket', False, None, None),
    ])
    report = api.build_scan_report(42, 'user-a', 'tenant-a')
    assert report['providers'] == ['aws']
    assert report['total_resources'] == 1
    assert report['total_findings'] == 0
    assert report['findings'] == []


@pytest.mark.parametrize('path', ['/report/42', '/report/42/pdf'])
def test_missing_or_inaccessible_report_returns_404(api, monkeypatch, path):
    monkeypatch.setattr(api, 'get_scan_report', lambda *_: [])

    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=api.app), base_url='http://test') as client:
            response = await client.get(path)
            assert response.status_code == 404
            assert response.json()['detail'] == 'Scan 42 not found'

    asyncio.run(run())
