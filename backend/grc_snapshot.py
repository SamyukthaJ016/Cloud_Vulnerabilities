"""Tenant-scoped findings from the last completed scan for the GRC connector."""

import re

from backend.database import get_conn, get_latest_dashboard_scans
from backend.evidence_payloads import stored_finding_control


def latest_scan_snapshot(user_id, tenant_id):
    scans = get_latest_dashboard_scans(user_id, tenant_id)
    if not scans:
        return None
    scan_id, provider, account_id, started_at = scans[0]
    params = (scan_id, user_id, tenant_id)
    with get_conn().cursor() as cur:
        cur.execute("""
            SELECT COUNT(*) FROM resources r JOIN scans s ON s.id = r.scan_id
            WHERE s.id = %s AND s.user_id = %s AND s.tenant_id = %s
        """, params)
        resource_count = cur.fetchone()[0]
        cur.execute("""
            SELECT f.id, f.severity, f.description, f.validated_by, f.created_at,
                   r.name, r.type, r.cloud
            FROM findings f
            JOIN resources r ON r.id = f.resource_id AND r.scan_id = f.scan_id
            JOIN scans s ON s.id = f.scan_id
            WHERE s.id = %s AND s.user_id = %s AND s.tenant_id = %s
            ORDER BY f.id
        """, params)
        rows = cur.fetchall()
    severity_counts = dict.fromkeys(['critical', 'high', 'medium', 'low', 'info'], 0)
    findings = []
    for finding_id, severity, description, tool, created_at, name, resource_type, cloud in rows:
        severity = str(severity or 'info').lower()
        if severity not in severity_counts:
            severity = 'info'
        severity_counts[severity] += 1
        description = str(description or 'Scanner finding')
        findings.append({
            'id': finding_id,
            'control_id': stored_finding_control(cloud, resource_type, description),
            'severity': severity,
            'title': re.sub(r'^(?:\[[^\]]+\]\s*)+', '', description)[:240],
            'description': description,
            'resource': name,
            'resource_type': resource_type,
            'provider': cloud,
            'tool': tool,
            'timestamp': created_at.isoformat() if created_at else None,
            'recommendation': 'Review the affected resource in CloudGuard and apply the scanner remediation guidance.',
        })
    return {
        'id': scan_id, 'provider': provider, 'account_id': account_id,
        'started_at': started_at.isoformat() if started_at else None,
        'resource_count': resource_count, 'finding_count': len(findings),
        'severity_counts': severity_counts, 'findings': findings,
    }
