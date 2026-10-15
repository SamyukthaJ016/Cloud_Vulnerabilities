from unittest.mock import Mock
import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace

from backend import grc_snapshot
from backend.tests.test_dashboard_scope import route


def test_latest_scan_findings_are_complete_scoped_and_not_control_fanout(monkeypatch):
    lookup = Mock(return_value=[(26, 'kubernetes', 'cluster', None)])
    cur = Mock()
    cur.__enter__ = Mock(return_value=cur)
    cur.__exit__ = Mock(return_value=False)
    cur.fetchone.return_value = (93,)
    cur.fetchall.return_value = [
        (101, 'CRITICAL', '[K8S-SCANNER] [K8S-SCANNER] Privileged container', 'kubernetes', None, 'pod-a', 'Pod', 'kubernetes'),
        (102, 'INFO', 'No IaC baseline', 'kubernetes', None, 'cluster', 'Cluster', 'kubernetes'),
    ]
    conn = Mock()
    conn.cursor.return_value = cur
    monkeypatch.setattr(grc_snapshot, 'get_latest_dashboard_scans', lookup)
    monkeypatch.setattr(grc_snapshot, 'get_conn', lambda: conn)
    result = grc_snapshot.latest_scan_snapshot('user-a', 'tenant-a')
    lookup.assert_called_once_with('user-a', 'tenant-a')
    for call in cur.execute.call_args_list:
        assert call.args[1] == (26, 'user-a', 'tenant-a')
    assert result['finding_count'] == 2
    assert result['severity_counts']['critical'] == 1
    assert result['severity_counts']['info'] == 1
    assert result['findings'][0]['id'] == 101
    assert result['findings'][0]['title'] == 'Privileged container'
    assert result['resource_count'] == 93
    assert 'config' not in result['findings'][0]


def test_no_completed_scan_never_falls_back_to_history(monkeypatch):
    monkeypatch.setattr(grc_snapshot, 'get_latest_dashboard_scans', lambda *_: [])
    conn = Mock(side_effect=AssertionError('Must not query historical findings'))
    monkeypatch.setattr(grc_snapshot, 'get_conn', conn)
    assert grc_snapshot.latest_scan_snapshot('user-a', 'tenant-a') is None
    conn.assert_not_called()


def test_grc_snapshot_uses_the_verified_connector_owner():
    identity = Mock(return_value=SimpleNamespace(user_id='scanner-user', tenant_id='tenant-a'))
    snapshot = Mock(return_value={'id': 26, 'finding_count': 47})
    get = route('get_grc_connector_dashboard', require_connector_identity=identity,
                latest_scan_snapshot=snapshot, build_compliance_summary=Mock(return_value={}),
                list_evidence_artifacts=Mock(return_value=[]), list_scanner_worker_statuses=lambda: {},
                datetime=datetime, timezone=timezone)
    request = object()
    result = asyncio.run(get(request))
    identity.assert_called_once_with(request, 'grc:read')
    snapshot.assert_called_once_with('scanner-user', 'tenant-a')
    assert result['tenant_id'] == 'tenant-a'
    assert result['latest_scan']['finding_count'] == 47
