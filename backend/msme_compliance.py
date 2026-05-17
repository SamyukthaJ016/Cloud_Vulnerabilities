import re
from datetime import date, datetime
from typing import Any

from psycopg2.extras import Json

from backend.database import get_conn


FRAMEWORK_CODE = "CERTIN_MSME_2025_V1"
FRAMEWORK_NAME = "CERT-In Elemental Cyber Defense Controls for MSMEs"
FRAMEWORK_VERSION = "1.0"
FRAMEWORK_DATE = "2025-09-01"
FRAMEWORK_SOURCE = "https://cert-in.org.in/PDF/Elemental_Cyber_Defense_Controls_for_MSME.pdf"

STATUS_LABELS = {
    "not_started": "Not Started",
    "in_progress": "In Progress",
    "implemented": "Implemented",
    "evidence_uploaded": "Evidence Uploaded",
    "verified": "Verified",
    "exception_approved": "Exception Approved",
    "not_applicable": "Not Applicable",
}

STATUS_SCORES = {
    "not_started": 0,
    "in_progress": 35,
    "implemented": 70,
    "evidence_uploaded": 82,
    "verified": 100,
    "exception_approved": 90,
    "not_applicable": 100,
}

TECHNICAL_BLOCKERS = {"NES", "SC", "PM", "LM", "DPBP", "RPP", "ACIM", "VAA"}

MSME_CONTROLS: list[dict[str, Any]] = [
    {
        "code": "EAM",
        "number": 1,
        "title": "Effective Asset Management",
        "plain_language": "Know every device, account, system, cloud asset, and business-critical service before trying to protect it.",
        "evidence_required": ["Asset inventory", "Asset owner list", "Periodic inventory review record"],
        "recommendations": [
            {"code": "EAM.1", "title": "Maintain an inventory of hardware, software, cloud services, and business data assets."},
            {"code": "EAM.2", "title": "Review ownership, classification, and lifecycle status of assets at planned intervals."},
        ],
    },
    {
        "code": "NES",
        "number": 2,
        "title": "Network and Email Security",
        "plain_language": "Reduce exposure from insecure networks, email abuse, and internet-facing services.",
        "evidence_required": ["Firewall/security group review", "Email security settings", "Network diagram", "Remote access procedure"],
        "recommendations": [
            {"code": "NES.1", "title": "Use firewalls or equivalent controls to restrict inbound and outbound access."},
            {"code": "NES.2", "title": "Secure remote access with strong authentication and approved channels."},
            {"code": "NES.3", "title": "Enable anti-spoofing and anti-phishing protections for email."},
            {"code": "NES.4", "title": "Review exposed ports, services, and risky network paths regularly."},
        ],
    },
    {
        "code": "EMS",
        "number": 3,
        "title": "Endpoint and Mobile Security",
        "plain_language": "Protect laptops, desktops, servers, and mobile devices used for business work.",
        "evidence_required": ["Endpoint protection dashboard", "Mobile/device policy", "Device encryption record", "Lost device procedure"],
        "recommendations": [
            {"code": "EMS.1", "title": "Use endpoint protection on employee and server devices."},
            {"code": "EMS.2", "title": "Apply device encryption and screen lock policies."},
            {"code": "EMS.3", "title": "Restrict installation of untrusted software and apps."},
            {"code": "EMS.4", "title": "Keep mobile and endpoint operating systems updated."},
        ],
    },
    {
        "code": "SC",
        "number": 4,
        "title": "Secure Configurations",
        "plain_language": "Harden systems so default passwords, open access, and weak settings do not become easy attack paths.",
        "evidence_required": ["Configuration baseline", "Hardening checklist", "Cloud/IaC scan report"],
        "recommendations": [
            {"code": "SC.1", "title": "Remove or change insecure default settings before systems go live."},
            {"code": "SC.2", "title": "Use approved secure baselines for servers, cloud, network, and applications."},
            {"code": "SC.3", "title": "Review configuration drift and misconfigurations through checks or scans."},
        ],
    },
    {
        "code": "PM",
        "number": 5,
        "title": "Patch Management",
        "plain_language": "Track and fix known vulnerabilities in operating systems, applications, packages, and infrastructure.",
        "evidence_required": ["Patch register", "Vulnerability scan report", "Exception record"],
        "recommendations": [
            {"code": "PM.1", "title": "Maintain a patching process for critical software and infrastructure."},
            {"code": "PM.2", "title": "Prioritize security updates based on severity and exposure."},
        ],
    },
    {
        "code": "IM",
        "number": 6,
        "title": "Incident Management",
        "plain_language": "Be ready to detect, respond, escalate, and report cyber incidents quickly.",
        "evidence_required": ["Incident response plan", "Incident contact list", "Drill or tabletop record"],
        "recommendations": [
            {"code": "IM.1", "title": "Document incident response roles, contacts, and escalation paths."},
            {"code": "IM.2", "title": "Maintain a process for timely incident reporting and preservation of evidence."},
            {"code": "IM.3", "title": "Run drills or reviews to test incident readiness."},
        ],
    },
    {
        "code": "LM",
        "number": 7,
        "title": "Logging and Monitoring",
        "plain_language": "Collect useful logs and monitor them so suspicious activity is noticed in time.",
        "evidence_required": ["Logging policy", "Cloud audit logging screenshot", "Alert configuration", "Retention setting"],
        "recommendations": [
            {"code": "LM.1", "title": "Enable logs for critical systems, identity events, and cloud activity."},
            {"code": "LM.2", "title": "Monitor important alerts and suspicious activity."},
            {"code": "LM.3", "title": "Retain logs for an appropriate period and protect them from tampering."},
        ],
    },
    {
        "code": "AT",
        "number": 8,
        "title": "Awareness and Training",
        "plain_language": "Train employees and contractors to avoid common cyber risks like phishing, weak passwords, and unsafe data handling.",
        "evidence_required": ["Training calendar", "Attendance record", "Awareness material"],
        "recommendations": [
            {"code": "AT.1", "title": "Conduct cybersecurity awareness training at planned intervals."},
            {"code": "AT.2", "title": "Include phishing, password hygiene, safe browsing, and incident reporting topics."},
        ],
    },
    {
        "code": "TPRM",
        "number": 9,
        "title": "Third Party Risk Management",
        "plain_language": "Track vendors and service providers that can affect the organization's data, systems, or operations.",
        "evidence_required": ["Vendor inventory", "Vendor security questionnaire", "Contract/security clause record"],
        "recommendations": [
            {"code": "TPRM.1", "title": "Maintain an inventory of important vendors and service providers."},
            {"code": "TPRM.2", "title": "Review vendor security expectations, access, and data handling responsibilities."},
        ],
    },
    {
        "code": "DPBP",
        "number": 10,
        "title": "Data Protection, Backup and Recovery",
        "plain_language": "Protect important data, back it up, and prove it can be restored when needed.",
        "evidence_required": ["Backup policy", "Restore test record", "Data classification record", "Encryption settings"],
        "recommendations": [
            {"code": "DPBP.1", "title": "Classify and protect sensitive business and customer data."},
            {"code": "DPBP.2", "title": "Encrypt sensitive data where practical in storage and transmission."},
            {"code": "DPBP.3", "title": "Maintain regular backups for important systems and data."},
            {"code": "DPBP.4", "title": "Test restoration to confirm backups are usable."},
        ],
    },
    {
        "code": "GC",
        "number": 11,
        "title": "Governance and Compliance",
        "plain_language": "Assign accountability for cyber security and keep basic policies, reviews, and records in place.",
        "evidence_required": ["Security policy", "Management review minutes", "Compliance responsibility matrix"],
        "recommendations": [
            {"code": "GC.1", "title": "Assign responsibility for cybersecurity and compliance activities."},
            {"code": "GC.2", "title": "Maintain core security policies and review them periodically."},
            {"code": "GC.3", "title": "Track compliance obligations, exceptions, and management approvals."},
            {"code": "GC.4", "title": "Keep evidence of periodic reviews and corrective actions."},
        ],
    },
    {
        "code": "RPP",
        "number": 12,
        "title": "Robust Password Policy",
        "plain_language": "Prevent weak, shared, and reused credentials from becoming the easiest path into the business.",
        "evidence_required": ["Password policy", "MFA configuration screenshot", "Account lockout setting", "Credential rotation record"],
        "recommendations": [
            {"code": "RPP.1", "title": "Require strong passwords or passphrases for business accounts."},
            {"code": "RPP.2", "title": "Use multi-factor authentication for important systems and remote access."},
            {"code": "RPP.3", "title": "Prevent shared credentials and rotate privileged credentials when needed."},
            {"code": "RPP.4", "title": "Lock or throttle repeated failed login attempts."},
        ],
    },
    {
        "code": "ACIM",
        "number": 13,
        "title": "Access Control and Identity Management",
        "plain_language": "Give users only the access they need and remove access quickly when roles change.",
        "evidence_required": ["User access review", "Joiner/mover/leaver process", "Privileged access list", "MFA evidence"],
        "recommendations": [
            {"code": "ACIM.1", "title": "Use unique user accounts and avoid unnecessary shared access."},
            {"code": "ACIM.2", "title": "Apply least privilege for employees, admins, vendors, and service accounts."},
            {"code": "ACIM.3", "title": "Review user and privileged access periodically."},
            {"code": "ACIM.4", "title": "Remove or change access promptly during exits and role changes."},
        ],
    },
    {
        "code": "PS",
        "number": 14,
        "title": "Physical Security",
        "plain_language": "Protect offices, devices, records, and server/network equipment from unauthorized physical access.",
        "evidence_required": ["Access control procedure", "Visitor log sample", "Device storage/disposal record"],
        "recommendations": [
            {"code": "PS.1", "title": "Restrict physical access to important systems, records, and network equipment."},
            {"code": "PS.2", "title": "Track visitors, secure unattended devices, and dispose of assets safely."},
        ],
    },
    {
        "code": "VAA",
        "number": 15,
        "title": "Vulnerability Audits and Assessments",
        "plain_language": "Assess vulnerabilities at least annually and after meaningful technology changes.",
        "evidence_required": ["Vulnerability assessment report", "Remediation tracker", "Retest evidence"],
        "recommendations": [
            {"code": "VAA.1", "title": "Run vulnerability assessment or audit for important systems at least annually."},
            {"code": "VAA.2", "title": "Track remediation and verify closure of important findings."},
        ],
    },
]

CONTROL_BY_CODE = {control["code"]: control for control in MSME_CONTROLS}

FINDING_KEYWORD_MAP: list[tuple[str, tuple[str, ...]]] = [
    ("EAM", ("inventory", "unknown asset", "unmanaged", "orphan")),
    ("NES", ("public", "open port", "0.0.0.0/0", "internet", "ingress", "security group", "firewall", "exposed")),
    ("EMS", ("endpoint", "mobile", "device", "antivirus", "malware")),
    ("SC", ("misconfiguration", "default", "unencrypted", "insecure", "hardening", "configuration", "public bucket")),
    ("PM", ("cve", "vulnerab", "patch", "outdated", "fixed version", "package")),
    ("IM", ("incident", "response", "forensic", "breach")),
    ("LM", ("logging", "log", "monitor", "audit trail", "cloudtrail", "alert")),
    ("AT", ("training", "awareness", "phishing")),
    ("TPRM", ("vendor", "third party", "supplier", "service provider")),
    ("DPBP", ("backup", "recovery", "restore", "encrypt", "data protection", "storage", "snapshot")),
    ("GC", ("policy", "compliance", "governance", "approval", "exception")),
    ("RPP", ("password", "credential", "secret", "mfa", "multi-factor", "login")),
    ("ACIM", ("iam", "access", "admin", "privilege", "rbac", "cluster-admin", "root", "role")),
    ("PS", ("physical", "visitor", "premise", "office")),
    ("VAA", ("scan", "vulnerability", "assessment", "audit", "finding")),
]


def _safe_date(value: Any) -> str | None:
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    return value


def _status_payload(row: tuple[Any, ...] | None) -> dict[str, Any]:
    if not row:
        return {
            "status": "not_started",
            "status_label": STATUS_LABELS["not_started"],
            "owner": None,
            "due_date": None,
            "notes": None,
            "score_override": None,
            "updated_at": None,
        }
    status = row[0] or "not_started"
    return {
        "status": status,
        "status_label": STATUS_LABELS.get(status, status.replace("_", " ").title()),
        "owner": row[1],
        "due_date": _safe_date(row[2]),
        "notes": row[3],
        "score_override": row[4],
        "updated_at": _safe_date(row[5]),
    }


def _control_score(status_payload: dict[str, Any], evidence_count: int, open_tasks: int, scanner_gaps: int) -> int:
    override = status_payload.get("score_override")
    if override is not None:
        try:
            return max(0, min(100, int(override)))
        except (TypeError, ValueError):
            pass

    score = STATUS_SCORES.get(status_payload["status"], 0)
    if evidence_count and score < 82:
        score = max(score, 82)
    if open_tasks:
        score -= min(30, open_tasks * 8)
    if scanner_gaps:
        score -= min(25, scanner_gaps * 5)
    return max(0, min(100, score))


def _ensure_control_rows(user_id: str) -> None:
    conn = get_conn()
    with conn.cursor() as cur:
        for control in MSME_CONTROLS:
            cur.execute(
                """
                INSERT INTO msme_control_status (user_id, framework_code, control_code)
                VALUES (%s, %s, %s)
                ON CONFLICT (user_id, framework_code, control_code) DO NOTHING
                """,
                (user_id, FRAMEWORK_CODE, control["code"]),
            )
    conn.commit()


def _load_status_rows(user_id: str) -> dict[str, dict[str, Any]]:
    _ensure_control_rows(user_id)
    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT control_code, status, owner, due_date, notes, score_override, updated_at
            FROM msme_control_status
            WHERE user_id = %s AND framework_code = %s
            """,
            (user_id, FRAMEWORK_CODE),
        )
        rows = cur.fetchall()
    return {
        row[0]: _status_payload((row[1], row[2], row[3], row[4], row[5], row[6]))
        for row in rows
    }


def _load_counts(user_id: str, table: str, status_filter: str | None = None) -> dict[str, int]:
    conn = get_conn()
    with conn.cursor() as cur:
        query = f"""
            SELECT control_code, COUNT(*)
            FROM {table}
            WHERE user_id = %s AND framework_code = %s
        """
        params: list[Any] = [user_id, FRAMEWORK_CODE]
        if status_filter:
            query += " AND status = %s"
            params.append(status_filter)
        query += " GROUP BY control_code"
        cur.execute(query, tuple(params))
        return {row[0]: int(row[1] or 0) for row in cur.fetchall()}


def map_finding_to_controls(description: str, cloud: str | None = None) -> list[str]:
    haystack = f"{cloud or ''} {description or ''}".lower()
    matches: list[str] = []
    for control_code, keywords in FINDING_KEYWORD_MAP:
        if any(keyword in haystack for keyword in keywords):
            matches.append(control_code)
    if not matches and re.search(r"critical|high|risk|exposed", haystack):
        matches.append("VAA")
    return matches[:4]


def get_scanner_control_gaps(user_id: str, limit: int = 200) -> dict[str, list[dict[str, Any]]]:
    conn = get_conn()
    gaps: dict[str, list[dict[str, Any]]] = {control["code"]: [] for control in MSME_CONTROLS}
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                f.id,
                f.scan_id,
                f.severity,
                f.description,
                f.created_at,
                r.cloud,
                r.name
            FROM findings f
            JOIN scans s ON s.id = f.scan_id
            JOIN resources r ON r.id = f.resource_id
            WHERE s.user_id = %s
            ORDER BY f.created_at DESC
            LIMIT %s
            """,
            (user_id, limit),
        )
        rows = cur.fetchall()

    for finding_id, scan_id, severity, description, created_at, cloud, resource_name in rows:
        mapped_controls = map_finding_to_controls(description or "", cloud)
        for control_code in mapped_controls:
            gaps.setdefault(control_code, []).append(
                {
                    "finding_id": finding_id,
                    "scan_id": scan_id,
                    "severity": severity,
                    "description": description,
                    "cloud": cloud,
                    "resource_name": resource_name,
                    "created_at": _safe_date(created_at),
                }
            )
    return gaps


def _build_control_payload(
    control: dict[str, Any],
    status_rows: dict[str, dict[str, Any]],
    evidence_counts: dict[str, int],
    open_task_counts: dict[str, int],
    scanner_gaps: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    code = control["code"]
    status = status_rows.get(code) or _status_payload(None)
    evidence_count = evidence_counts.get(code, 0)
    open_tasks = open_task_counts.get(code, 0)
    gaps = scanner_gaps.get(code, [])
    return {
        **control,
        "framework_code": FRAMEWORK_CODE,
        "status": status,
        "evidence_count": evidence_count,
        "open_task_count": open_tasks,
        "scanner_gap_count": len(gaps),
        "scanner_gaps": gaps[:8],
        "score": _control_score(status, evidence_count, open_tasks, len(gaps)),
    }


def get_framework() -> dict[str, Any]:
    return {
        "code": FRAMEWORK_CODE,
        "name": FRAMEWORK_NAME,
        "version": FRAMEWORK_VERSION,
        "released_on": FRAMEWORK_DATE,
        "source": FRAMEWORK_SOURCE,
        "control_count": len(MSME_CONTROLS),
        "recommendation_count": sum(len(control["recommendations"]) for control in MSME_CONTROLS),
        "status_labels": STATUS_LABELS,
    }


def list_controls(user_id: str) -> list[dict[str, Any]]:
    status_rows = _load_status_rows(user_id)
    evidence_counts = _load_counts(user_id, "msme_evidence")
    open_task_counts = _load_counts(user_id, "msme_tasks", status_filter="open")
    scanner_gaps = get_scanner_control_gaps(user_id)
    return [
        _build_control_payload(control, status_rows, evidence_counts, open_task_counts, scanner_gaps)
        for control in MSME_CONTROLS
    ]


def get_dashboard(user_id: str) -> dict[str, Any]:
    controls = list_controls(user_id)
    total_score = round(sum(control["score"] for control in controls) / len(controls), 1)
    status_counts: dict[str, int] = {key: 0 for key in STATUS_LABELS}
    for control in controls:
        status_counts[control["status"]["status"]] = status_counts.get(control["status"]["status"], 0) + 1

    open_gaps = sum(control["scanner_gap_count"] for control in controls)
    open_tasks = sum(control["open_task_count"] for control in controls)
    evidence_total = sum(control["evidence_count"] for control in controls)
    blockers = [
        control
        for control in controls
        if control["code"] in TECHNICAL_BLOCKERS and (control["score"] < 70 or control["scanner_gap_count"] > 0)
    ]

    return {
        "framework": get_framework(),
        "readiness_score": total_score,
        "controls_total": len(controls),
        "controls_verified": status_counts.get("verified", 0),
        "controls_evidence_uploaded": status_counts.get("evidence_uploaded", 0),
        "open_scanner_gaps": open_gaps,
        "open_tasks": open_tasks,
        "evidence_total": evidence_total,
        "status_counts": status_counts,
        "priority_controls": [
            {
                "code": control["code"],
                "title": control["title"],
                "score": control["score"],
                "scanner_gap_count": control["scanner_gap_count"],
                "open_task_count": control["open_task_count"],
            }
            for control in sorted(blockers, key=lambda item: (item["score"], -item["scanner_gap_count"]))[:5]
        ],
        "controls": controls,
    }


def get_control(user_id: str, control_code: str) -> dict[str, Any] | None:
    controls = list_controls(user_id)
    normalized = control_code.strip().upper()
    return next((control for control in controls if control["code"] == normalized), None)


def update_control_status(user_id: str, control_code: str, payload: dict[str, Any]) -> dict[str, Any]:
    normalized = control_code.strip().upper()
    if normalized not in CONTROL_BY_CODE:
        raise ValueError("Unknown MSME control")

    allowed_statuses = set(STATUS_LABELS)
    status = payload.get("status")
    if status is not None and status not in allowed_statuses:
        raise ValueError("Invalid status")

    conn = get_conn()
    status_value = status
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO msme_control_status (
                user_id, framework_code, control_code, status, owner, due_date, notes, score_override
            )
            VALUES (%s, %s, %s, COALESCE(%s, 'not_started'), %s, %s, %s, %s)
            ON CONFLICT (user_id, framework_code, control_code)
            DO UPDATE SET
                status = CASE
                    WHEN %s IS NULL THEN msme_control_status.status
                    ELSE EXCLUDED.status
                END,
                owner = COALESCE(EXCLUDED.owner, msme_control_status.owner),
                due_date = COALESCE(EXCLUDED.due_date, msme_control_status.due_date),
                notes = COALESCE(EXCLUDED.notes, msme_control_status.notes),
                score_override = COALESCE(EXCLUDED.score_override, msme_control_status.score_override),
                updated_at = NOW()
            """,
            (
                user_id,
                FRAMEWORK_CODE,
                normalized,
                status_value,
                payload.get("owner"),
                payload.get("due_date"),
                payload.get("notes"),
                payload.get("score_override"),
                status_value,
            ),
        )
    conn.commit()
    return get_control(user_id, normalized) or {}


def list_evidence(user_id: str, control_code: str | None = None) -> list[dict[str, Any]]:
    conn = get_conn()
    with conn.cursor() as cur:
        query = """
            SELECT id, control_code, recommendation_code, title, evidence_type, file_name,
                   file_url, notes, review_status, evidence_date, expires_at, created_at
            FROM msme_evidence
            WHERE user_id = %s AND framework_code = %s
        """
        params: list[Any] = [user_id, FRAMEWORK_CODE]
        if control_code:
            query += " AND control_code = %s"
            params.append(control_code.strip().upper())
        query += " ORDER BY created_at DESC"
        cur.execute(query, tuple(params))
        rows = cur.fetchall()

    return [
        {
            "id": row[0],
            "control_code": row[1],
            "recommendation_code": row[2],
            "title": row[3],
            "evidence_type": row[4],
            "file_name": row[5],
            "file_url": row[6],
            "notes": row[7],
            "review_status": row[8],
            "evidence_date": _safe_date(row[9]),
            "expires_at": _safe_date(row[10]),
            "created_at": _safe_date(row[11]),
        }
        for row in rows
    ]


def create_evidence(user_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    control_code = str(payload.get("control_code") or "").strip().upper()
    if control_code not in CONTROL_BY_CODE:
        raise ValueError("Unknown MSME control")

    title = str(payload.get("title") or "").strip()
    if not title:
        raise ValueError("Evidence title is required")

    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO msme_evidence (
                user_id, framework_code, control_code, recommendation_code, title,
                evidence_type, file_name, file_url, notes, evidence_date, expires_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                user_id,
                FRAMEWORK_CODE,
                control_code,
                payload.get("recommendation_code"),
                title,
                payload.get("evidence_type") or "document",
                payload.get("file_name"),
                payload.get("file_url"),
                payload.get("notes"),
                payload.get("evidence_date"),
                payload.get("expires_at"),
            ),
        )
        evidence_id = cur.fetchone()[0]
        cur.execute(
            """
            UPDATE msme_control_status
            SET status = CASE
                WHEN status IN ('not_started', 'in_progress', 'implemented') THEN 'evidence_uploaded'
                ELSE status
            END,
            updated_at = NOW()
            WHERE user_id = %s AND framework_code = %s AND control_code = %s
            """,
            (user_id, FRAMEWORK_CODE, control_code),
        )
    conn.commit()
    return next(item for item in list_evidence(user_id, control_code) if item["id"] == evidence_id)


def list_tasks(user_id: str, control_code: str | None = None) -> list[dict[str, Any]]:
    conn = get_conn()
    with conn.cursor() as cur:
        query = """
            SELECT id, control_code, recommendation_code, title, severity, owner,
                   due_date, status, source, linked_scan_id, notes, created_at
            FROM msme_tasks
            WHERE user_id = %s AND framework_code = %s
        """
        params: list[Any] = [user_id, FRAMEWORK_CODE]
        if control_code:
            query += " AND control_code = %s"
            params.append(control_code.strip().upper())
        query += " ORDER BY created_at DESC"
        cur.execute(query, tuple(params))
        rows = cur.fetchall()

    return [
        {
            "id": row[0],
            "control_code": row[1],
            "recommendation_code": row[2],
            "title": row[3],
            "severity": row[4],
            "owner": row[5],
            "due_date": _safe_date(row[6]),
            "status": row[7],
            "source": row[8],
            "linked_scan_id": row[9],
            "notes": row[10],
            "created_at": _safe_date(row[11]),
        }
        for row in rows
    ]


def create_task(user_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    control_code = str(payload.get("control_code") or "").strip().upper()
    if control_code not in CONTROL_BY_CODE:
        raise ValueError("Unknown MSME control")

    title = str(payload.get("title") or "").strip()
    if not title:
        raise ValueError("Task title is required")

    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO msme_tasks (
                user_id, framework_code, control_code, recommendation_code, title,
                severity, owner, due_date, source, linked_scan_id, notes
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                user_id,
                FRAMEWORK_CODE,
                control_code,
                payload.get("recommendation_code"),
                title,
                payload.get("severity") or "medium",
                payload.get("owner"),
                payload.get("due_date"),
                payload.get("source") or "manual",
                payload.get("linked_scan_id"),
                payload.get("notes"),
            ),
        )
        task_id = cur.fetchone()[0]
    conn.commit()
    return next(item for item in list_tasks(user_id, control_code) if item["id"] == task_id)


def update_task(user_id: str, task_id: int, payload: dict[str, Any]) -> dict[str, Any] | None:
    allowed = {"title", "severity", "owner", "due_date", "status", "notes"}
    updates = {key: value for key, value in payload.items() if key in allowed and value is not None}
    if not updates:
        return next((item for item in list_tasks(user_id) if item["id"] == task_id), None)

    assignments = ", ".join(f"{key} = %s" for key in updates)
    params = [*updates.values(), user_id, task_id]
    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute(
            f"""
            UPDATE msme_tasks
            SET {assignments}, updated_at = NOW()
            WHERE user_id = %s AND id = %s
            """,
            tuple(params),
        )
    conn.commit()
    return next((item for item in list_tasks(user_id) if item["id"] == task_id), None)


def create_scanner_mapping_tasks(user_id: str) -> dict[str, Any]:
    gaps = get_scanner_control_gaps(user_id)
    created = []
    for control_code, findings in gaps.items():
        for finding in findings[:3]:
            title = f"Review scanner gap for {control_code}: {finding['resource_name'] or 'resource'}"
            created.append(
                create_task(
                    user_id,
                    {
                        "control_code": control_code,
                        "title": title,
                        "severity": str(finding.get("severity") or "medium").lower(),
                        "source": "scanner",
                        "linked_scan_id": finding.get("scan_id"),
                        "notes": (finding.get("description") or "")[:1000],
                    },
                )
            )
    return {"created": created, "created_count": len(created)}


def export_readiness_payload(user_id: str) -> dict[str, Any]:
    dashboard = get_dashboard(user_id)
    payload = {
        "generated_at": datetime.utcnow().isoformat(),
        "framework": dashboard["framework"],
        "readiness_score": dashboard["readiness_score"],
        "controls": [
            {
                "code": control["code"],
                "title": control["title"],
                "score": control["score"],
                "status": control["status"]["status_label"],
                "evidence_count": control["evidence_count"],
                "open_task_count": control["open_task_count"],
                "scanner_gap_count": control["scanner_gap_count"],
            }
            for control in dashboard["controls"]
        ],
    }

    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO msme_audit_exports (user_id, framework_code, export_type, export_payload)
            VALUES (%s, %s, 'readiness_summary', %s)
            RETURNING id
            """,
            (user_id, FRAMEWORK_CODE, Json(payload)),
        )
        export_id = cur.fetchone()[0]
    conn.commit()
    return {"export_id": export_id, **payload}
