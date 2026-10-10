"""Real PostgreSQL regressions. Set CLOUDGUARD_TEST_DATABASE_URL to a disposable *_regression DB."""
import asyncio
import os
import uuid
from datetime import datetime, timedelta
from urllib.parse import urlparse

import psycopg2
import pytest
from fastapi import HTTPException
from starlette.requests import Request

from backend.tests.test_review_regressions import api
from backend.tenant_security import RequestIdentity


@pytest.fixture
def db(api, monkeypatch):
    url = os.getenv('CLOUDGUARD_TEST_DATABASE_URL')
    if not url:
        pytest.skip('CLOUDGUARD_TEST_DATABASE_URL is not configured')
    parsed = urlparse(url)
    assert parsed.hostname in {'127.0.0.1', 'localhost'} and parsed.path.endswith('_regression')
    monkeypatch.setenv('DATABASE_URL', url)
    conn = psycopg2.connect(url)
    conn.autocommit = True
    from backend import database
    from backend.ai import persistent_memory
    monkeypatch.setattr(api, 'get_conn', lambda: conn)
    monkeypatch.setattr(database, 'get_conn', lambda: conn)
    monkeypatch.setattr(persistent_memory, 'get_conn', lambda: conn)
    monkeypatch.delenv('OBJECT_STORAGE_BUCKET', raising=False)
    monkeypatch.delenv('EVIDENCE_S3_BUCKET', raising=False)
    yield conn
    conn.close()


def identity_request(user, tenant):
    req = Request({'type': 'http', 'method': 'POST', 'path': '/', 'headers': []})
    req.state.identity = RequestIdentity(user, tenant, '')
    return req


def test_evidence_collision_and_foreign_job_are_rejected(api, db):
    evidence_id = 'review-' + uuid.uuid4().hex
    request = api.EvidenceIngestionRequest(evidence_id=evidence_id, source_system='test', payload={'owner': 'a'})
    api.store_evidence_artifact('user-a', 'tenant-a', request)
    with pytest.raises(HTTPException) as exc:
        api.store_evidence_artifact('user-b', 'tenant-b', request.model_copy(update={'payload': {'owner': 'b'}}))
    assert exc.value.status_code == 409
    with db.cursor() as cur:
        cur.execute('SELECT payload, user_id, tenant_id FROM evidence_artifacts WHERE evidence_id = %s', (evidence_id,))
        assert cur.fetchone() == ({'owner': 'a'}, 'user-a', 'tenant-a')
        job_id = 'review-' + uuid.uuid4().hex
        cur.execute("INSERT INTO scan_jobs(job_id,user_id,tenant_id,providers) VALUES (%s,'user-a','tenant-a','[\"aws\"]')", (job_id,))
    with pytest.raises(HTTPException) as exc:
        api.store_evidence_artifact('user-b', 'tenant-b', request.model_copy(update={'evidence_id': None, 'job_id': job_id}))
    assert exc.value.status_code == 404
    api.store_evidence_artifact('user-a', 'tenant-a', request.model_copy(update={'job_id': job_id, 'payload': {'updated': True}}))


def test_upsert_race_cannot_change_foreign_owner(api, db, monkeypatch):
    """Insert a foreign row after the preflight read, before the upsert."""
    evidence_id = 'review-' + uuid.uuid4().hex
    original_cursor = db.cursor
    class Connection:
        def cursor(self):
            return Cursor()
        def commit(self):
            db.commit()
    class Cursor:
        def __enter__(self):
            self.cur = original_cursor()
            return self
        def __exit__(self, *args):
            self.cur.close()
        def execute(self, sql, params):
            if 'INSERT INTO evidence_artifacts' in sql:
                with original_cursor() as other:
                    other.execute("INSERT INTO evidence_artifacts(evidence_id,user_id,tenant_id,source_system,scanner_type,artifact_type,storage_type,uri,checksum_sha256) VALUES (%s,'user-b','tenant-b','test','test','json','database','original','original')", (evidence_id,))
            self.cur.execute(sql, params)
        def fetchone(self):
            return self.cur.fetchone()
    monkeypatch.setattr(api, 'get_conn', lambda: Connection())
    with pytest.raises(HTTPException) as exc:
        api.store_evidence_artifact('user-a', 'tenant-a', api.EvidenceIngestionRequest(evidence_id=evidence_id, source_system='test'))
    assert exc.value.status_code == 409
    with db.cursor() as cur:
        cur.execute('SELECT uri FROM evidence_artifacts WHERE evidence_id = %s', (evidence_id,))
        assert cur.fetchone()[0] == 'original'


def test_memory_isolated_by_tenant_user_and_account(api, db):
    from backend.ai.persistent_memory import PersistentMemorySystem
    suffix = uuid.uuid4().hex
    tenant_a, tenant_b = 'ta-' + suffix, 'tb-' + suffix
    memory_a = PersistentMemorySystem().for_owner(tenant_a, 'user-a')
    memory_b = PersistentMemorySystem().for_owner(tenant_b, 'user-b')
    def scan(tenant, user, account, findings):
        with db.cursor() as cur:
            cur.execute("INSERT INTO scans(user_id,tenant_id,account_id,cloud,status) VALUES (%s,%s,%s,'aws','completed') RETURNING id", (user, tenant, account))
            scan_id = cur.fetchone()[0]
        return PersistentMemorySystem().for_owner(tenant, user).process_scan_findings(scan_id, findings)
    finding = dict(provider='aws', resource_name='same-resource', issue='same-issue', severity='HIGH', description='test', recommendation='fix')
    scan(tenant_a, 'user-a', 'account-1', [finding])
    scan(tenant_b, 'user-b', 'account-1', [finding])
    scan(tenant_a, 'user-a', 'account-2', [finding])
    tasks_a, tasks_b = memory_a.get_open_tasks(), memory_b.get_open_tasks()
    assert len(tasks_a) == 2 and len(tasks_b) == 1
    assert tasks_a[0]['finding_hash'] != tasks_b[0]['finding_hash']
    assert memory_b.get_finding_history(tasks_a[0]['finding_hash']) == {}
    with pytest.raises(ValueError, match='Finding not found'):
        memory_b._add_note(tasks_a[0]['finding_hash'], 'test', 'foreign note')
    with pytest.raises(HTTPException) as exc:
        asyncio.run(api.update_task_status(identity_request('user-b', tenant_b), tasks_a[0]['id'], 'resolved'))
    assert exc.value.status_code == 404
    assert memory_a.get_dashboard_summary()['open_tasks']['total'] == 2
    scan(tenant_a, 'user-a', 'account-1', [])
    assert len(memory_a.get_open_tasks()) == 1  # account-2 is still open
    assert len(memory_b.get_open_tasks()) == 1
    task = memory_a.get_open_tasks()[0]
    asyncio.run(api.update_task_status(identity_request('user-a', tenant_a), task['id'], 'resolved', 'fixed'))
    assert memory_a.get_finding_history(task['finding_hash'])['notes'][0]['content'] == 'fixed'


def test_cleanup_lease_releases_and_reconciler_recovers_crashed_work(api, db, monkeypatch):
    from backend.cleanup_lease import sandbox_cleanup_lease
    lab_id = 'review-' + uuid.uuid4().hex
    with sandbox_cleanup_lease(lab_id) as acquired:
        assert acquired
        with sandbox_cleanup_lease(lab_id) as other:
            assert not other
    with sandbox_cleanup_lease(lab_id) as acquired:
        assert acquired
    with db.cursor() as cur:
        cur.execute("""INSERT INTO sandbox_lab_runs(lab_id,user_id,tenant_id,provider,status,resource_prefix,expires_at,auto_destroy)
                       VALUES (%s,'user-a','tenant-a','iac','destroying','review',%s,false)""", (lab_id, datetime.utcnow() + timedelta(hours=1)))
    monkeypatch.setattr(api, '_destroy_sandbox_lab_resources', lambda _: {'deleted': [], 'errors': []})
    result = asyncio.run(api.reconcile_sandbox_labs())
    assert lab_id in result['destroyed']
    assert api.get_sandbox_lab_run(lab_id)['status'] == 'destroyed'
