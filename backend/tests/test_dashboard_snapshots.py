"""Dashboard snapshot regressions; optional real SQL uses a disposable local DB."""

import asyncio
import os
from datetime import datetime
from unittest.mock import Mock
from urllib.parse import urlparse

import psycopg2
import pytest

from backend import database
from backend.tests.test_dashboard_scope import route


def test_scope_uses_authenticated_owner_and_returns_snapshot_ids():
    lookup = Mock(return_value=[(22, 'aws', 'account-a', datetime(2026, 10, 14))])
    get = route('get_dashboard_scope', get_user_id=lambda _: 'user-a',
                _request_tenant_id=lambda *args, **kwargs: 'tenant-a',
                get_latest_dashboard_scans=lookup)
    result = asyncio.run(get(object()))
    lookup.assert_called_once_with('user-a', 'tenant-a')
    assert result['scan_ids'] == [22]
    assert result['scans'][0]['started_at'] == '2026-10-14T00:00:00'


@pytest.fixture
def snapshot_db(monkeypatch):
    url = os.getenv('CLOUDGUARD_TEST_DATABASE_URL')
    if not url:
        pytest.skip('Set CLOUDGUARD_TEST_DATABASE_URL to a disposable local *_regression DB')
    parsed = urlparse(url)
    assert parsed.hostname in {'localhost', '127.0.0.1'} and parsed.path.endswith('_regression')
    conn = psycopg2.connect(url)
    conn.autocommit = True
    monkeypatch.setattr(database, 'ensure_connection', lambda: conn)
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TEMP TABLE scans (
                id INT PRIMARY KEY, cloud TEXT, account_id TEXT, user_id TEXT,
                tenant_id TEXT, status TEXT, started_at TIMESTAMP
            );
            CREATE TEMP TABLE resources (id INT PRIMARY KEY, scan_id INT, cloud TEXT, public BOOL);
            CREATE TEMP TABLE findings (id INT PRIMARY KEY, scan_id INT, resource_id INT);
        """)
        scans = [
            (1, 'aws', 'a', 'u', 't', 'completed', '2026-10-12'),
            (2, 'aws', 'a', 'u', 't', 'completed', '2026-10-13'),
            (3, 'kubernetes', 'cluster', 'u', 't', 'completed', '2026-10-12'),
            (4, 'kubernetes', 'cluster', 'u', 't', 'completed', '2026-10-13'),
            (5, 'aws', 'a', 'u', 't', 'failed', '2026-10-14'),
            (6, 'aws', 'a', 'u', 'foreign', 'completed', '2026-10-14'),
            (7, 'aws', 'a', 'u', 't', 'running', '2026-10-14'),
            (8, 'aws', 'a', 'foreign', 't', 'completed', '2026-10-14'),
        ]
        cur.executemany('INSERT INTO scans VALUES (%s,%s,%s,%s,%s,%s,%s)', scans)
        cur.executemany('INSERT INTO resources VALUES (%s,%s,%s,false)', [(s[0], s[0], s[1]) for s in scans])
        finding_id = 0
        for scan_id, count in [(1, 3), (2, 0), (3, 2), (4, 1), (5, 4), (6, 10), (7, 2), (8, 10)]:
            for _ in range(count):
                finding_id += 1
                cur.execute('INSERT INTO findings VALUES (%s,%s,%s)', (finding_id, scan_id, scan_id))
    yield conn
    conn.close()


def test_completed_clean_scans_replace_old_findings_and_exclude_other_owners(snapshot_db):
    snapshots = database.get_latest_dashboard_scans('u', 't')
    assert [row[0] for row in snapshots] == [2, 4]
    current = database.get_multi_cloud_summary('u', 't', scan_ids='2,4')
    assert sum(row[2] for row in current) == 1
    assert sum(row[1] for row in current) == 2
    history = database.get_multi_cloud_summary('u', 't')
    assert sum(row[2] for row in history) == 12
    assert database.get_latest_dashboard_scans('missing', 't') == []
    assert database.get_multi_cloud_summary('u', 't', scan_ids='0') == []


def test_timestamp_ties_choose_the_newer_id(snapshot_db):
    with snapshot_db.cursor() as cur:
        cur.execute("INSERT INTO scans VALUES (9,'aws','a','u','t','completed','2026-10-13')")
    assert [row[0] for row in database.get_latest_dashboard_scans('u', 't')] == [9, 4]
