from __future__ import annotations

from datetime import datetime
from typing import Any

from backend.msme_compliance import (
    FRAMEWORK_CODE,
    FRAMEWORK_NAME,
    export_readiness_payload,
    get_dashboard as get_msme_dashboard,
    list_evidence,
    list_tasks,
)


SEVERITY_WEIGHTS = {
    "CRITICAL": {"likelihood": 5, "impact": 5},
    "HIGH": {"likelihood": 4, "impact": 4},
    "MEDIUM": {"likelihood": 3, "impact": 3},
    "LOW": {"likelihood": 2, "impact": 2},
    "INFO": {"likelihood": 1, "impact": 1},
}

GOVERNANCE_CONTROLS = {"GC", "IM", "TPRM", "AT"}
RISK_CONTROLS = {"VAA", "SC", "ACIM", "NES", "PM", "LM"}
COMPLIANCE_CONTROLS = {
    "EAM",
    "EMS",
    "DPBP",
    "RPP",
    "PS",
}


def _normalize_severity(value: Any) -> str:
    severity = str(value or "MEDIUM").strip().upper()
    if severity in {"INFORMATIONAL", "UNKNOWN"}:
        return "INFO"
    return severity if severity in SEVERITY_WEIGHTS else "MEDIUM"


def _risk_rating(score: int) -> str:
    if score >= 20:
        return "Critical"
    if score >= 13:
        return "High"
    if score >= 7:
        return "Medium"
    return "Low"


def _average_score(controls: list[dict[str, Any]], control_codes: set[str]) -> float:
    scoped = [control for control in controls if control["code"] in control_codes]
    if not scoped:
        return 0.0
    return round(sum(control["score"] for control in scoped) / len(scoped), 1)


def _control_risk_reduction(control_score: int) -> float:
    """A simple residual-risk reduction model for executive reporting."""
    return min(max(control_score, 0), 95) / 125


def _control_status_label(control: dict[str, Any]) -> str:
    return control.get("status", {}).get("status_label") or "Not Started"


def _risk_from_scanner_gap(control: dict[str, Any], gap: dict[str, Any]) -> dict[str, Any]:
    severity = _normalize_severity(gap.get("severity"))
    weights = SEVERITY_WEIGHTS[severity]
    inherent_score = weights["likelihood"] * weights["impact"]
    residual_score = max(1, round(inherent_score * (1 - _control_risk_reduction(control["score"]))))

    return {
        "id": f"SCAN-{gap.get('finding_id')}",
        "title": (gap.get("description") or "Scanner finding requires review")[:140],
        "source": "CloudGuard Scanner",
        "category": "Technical Risk",
        "linked_control": control["code"],
        "linked_control_title": control["title"],
        "asset": gap.get("resource_name") or "Unknown resource",
        "cloud": gap.get("cloud") or "unknown",
        "severity": severity,
        "likelihood": weights["likelihood"],
        "impact": weights["impact"],
        "inherent_score": inherent_score,
        "residual_score": residual_score,
        "rating": _risk_rating(residual_score),
        "status": "Open" if control["score"] < 70 else "Treatment in Progress",
        "owner": control.get("status", {}).get("owner") or "Unassigned",
        "treatment": "Remediate scanner finding and attach closure evidence.",
        "evidence_count": control.get("evidence_count", 0),
        "linked_scan_id": gap.get("scan_id"),
        "created_at": gap.get("created_at"),
    }


def _risk_from_control_gap(control: dict[str, Any]) -> dict[str, Any]:
    score = int(control.get("score") or 0)
    severity = "HIGH" if score < 35 else "MEDIUM"
    weights = SEVERITY_WEIGHTS[severity]
    inherent_score = weights["likelihood"] * weights["impact"]
    residual_score = max(1, round(inherent_score * (1 - _control_risk_reduction(score))))

    return {
        "id": f"CTRL-{control['code']}",
        "title": f"{control['title']} is below the target maturity threshold",
        "source": "Control Assessment",
        "category": "Control Gap",
        "linked_control": control["code"],
        "linked_control_title": control["title"],
        "asset": "Compliance workspace",
        "cloud": "all",
        "severity": severity,
        "likelihood": weights["likelihood"],
        "impact": weights["impact"],
        "inherent_score": inherent_score,
        "residual_score": residual_score,
        "rating": _risk_rating(residual_score),
        "status": "Open" if score < 55 else "Treatment in Progress",
        "owner": control.get("status", {}).get("owner") or "Unassigned",
        "treatment": "Assign an owner, implement checklist items, and upload audit evidence.",
        "evidence_count": control.get("evidence_count", 0),
        "linked_scan_id": None,
        "created_at": control.get("status", {}).get("updated_at"),
    }


def build_risk_register(controls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    risks: list[dict[str, Any]] = []
    for control in controls:
        for gap in control.get("scanner_gaps", []):
            risks.append(_risk_from_scanner_gap(control, gap))

        if control.get("score", 0) < 55:
            risks.append(_risk_from_control_gap(control))

    return sorted(
        risks,
        key=lambda item: (item["residual_score"], item["inherent_score"], item["id"]),
        reverse=True,
    )


def _risk_summary(risks: list[dict[str, Any]]) -> dict[str, Any]:
    by_rating = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    by_status: dict[str, int] = {}
    residual_total = 0
    for risk in risks:
        by_rating[risk["rating"]] = by_rating.get(risk["rating"], 0) + 1
        by_status[risk["status"]] = by_status.get(risk["status"], 0) + 1
        residual_total += int(risk["residual_score"])

    average_residual = round(residual_total / len(risks), 1) if risks else 0
    risk_score = max(0, round(100 - (average_residual * 4), 1))
    return {
        "total": len(risks),
        "critical": by_rating.get("Critical", 0),
        "high": by_rating.get("High", 0),
        "medium": by_rating.get("Medium", 0),
        "low": by_rating.get("Low", 0),
        "by_rating": by_rating,
        "by_status": by_status,
        "average_residual": average_residual,
        "risk_score": risk_score,
    }


def _task_summary(tasks: list[dict[str, Any]]) -> dict[str, Any]:
    by_status: dict[str, int] = {}
    by_source: dict[str, int] = {}
    for task in tasks:
        by_status[task["status"]] = by_status.get(task["status"], 0) + 1
        by_source[task["source"]] = by_source.get(task["source"], 0) + 1
    return {
        "total": len(tasks),
        "open": by_status.get("open", 0),
        "closed": by_status.get("closed", 0),
        "by_status": by_status,
        "by_source": by_source,
    }


def _evidence_summary(evidence: list[dict[str, Any]]) -> dict[str, Any]:
    by_review_status: dict[str, int] = {}
    by_type: dict[str, int] = {}
    for item in evidence:
        by_review_status[item["review_status"]] = by_review_status.get(item["review_status"], 0) + 1
        by_type[item["evidence_type"]] = by_type.get(item["evidence_type"], 0) + 1
    return {
        "total": len(evidence),
        "pending_review": by_review_status.get("pending_review", 0),
        "approved": by_review_status.get("approved", 0),
        "by_review_status": by_review_status,
        "by_type": by_type,
    }


def _policy_register(controls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    policies = [
        ("Cybersecurity Governance Policy", ["GC", "IM"], "Owner, annual review cycle, incident escalation"),
        ("Access Control and Password Policy", ["ACIM", "RPP"], "MFA, least privilege, account lifecycle"),
        ("Asset and Configuration Management Policy", ["EAM", "SC"], "Asset inventory, baseline hardening, change review"),
        ("Logging and Monitoring Procedure", ["LM"], "Audit logs, alert triage, retention"),
        ("Backup and Recovery Procedure", ["DPBP"], "Backup scope, restore tests, recovery ownership"),
        ("Third Party Risk Procedure", ["TPRM"], "Vendor inventory, onboarding review, contractual controls"),
        ("Vulnerability Assessment Procedure", ["VAA", "PM"], "Scan cadence, remediation SLA, exception handling"),
    ]
    control_lookup = {control["code"]: control for control in controls}
    rows = []
    for name, mapped_controls, requirement in policies:
        scores = [control_lookup[code]["score"] for code in mapped_controls if code in control_lookup]
        evidence = sum(control_lookup[code]["evidence_count"] for code in mapped_controls if code in control_lookup)
        maturity = round(sum(scores) / len(scores), 1) if scores else 0
        rows.append(
            {
                "name": name,
                "mapped_controls": mapped_controls,
                "requirement": requirement,
                "maturity": maturity,
                "evidence_count": evidence,
                "status": "Ready" if maturity >= 85 and evidence else "Needs Evidence" if maturity >= 65 else "Draft Needed",
            }
        )
    return rows


def get_grc_dashboard(user_id: str) -> dict[str, Any]:
    compliance = get_msme_dashboard(user_id)
    controls = compliance["controls"]
    risks = build_risk_register(controls)
    tasks = list_tasks(user_id)
    evidence = list_evidence(user_id)
    risk_summary = _risk_summary(risks)

    governance_score = _average_score(controls, GOVERNANCE_CONTROLS)
    risk_management_score = round(
        (_average_score(controls, RISK_CONTROLS) * 0.6) + (risk_summary["risk_score"] * 0.4),
        1,
    )
    compliance_score = round(
        (
            compliance["readiness_score"] * 0.7
            + _average_score(controls, COMPLIANCE_CONTROLS) * 0.3
        ),
        1,
    )

    return {
        "generated_at": datetime.utcnow().isoformat(),
        "platform": {
            "name": "CloudGuard GRC",
            "description": "Governance, risk, and compliance cockpit powered by CloudGuard scans and CERT-In MSME controls.",
            "primary_framework": FRAMEWORK_CODE,
            "framework_name": FRAMEWORK_NAME,
        },
        "metrics": {
            "overall_grc_score": round((governance_score + risk_management_score + compliance_score) / 3, 1),
            "governance_score": governance_score,
            "risk_management_score": risk_management_score,
            "compliance_score": compliance_score,
            "open_risks": risk_summary["total"],
            "critical_risks": risk_summary["critical"],
            "high_risks": risk_summary["high"],
            "open_tasks": _task_summary(tasks)["open"],
            "evidence_total": len(evidence),
        },
        "pillars": [
            {
                "key": "governance",
                "title": "Governance",
                "score": governance_score,
                "description": "Ownership, policies, third-party oversight, incident accountability, and management review.",
                "controls": sorted(GOVERNANCE_CONTROLS),
            },
            {
                "key": "risk",
                "title": "Risk Management",
                "score": risk_management_score,
                "description": "Scanner-driven risk register, residual scoring, treatment tasks, and vulnerability governance.",
                "controls": sorted(RISK_CONTROLS),
            },
            {
                "key": "compliance",
                "title": "Compliance",
                "score": compliance_score,
                "description": "CERT-In MSME control readiness, evidence, audit exports, and closure tracking.",
                "controls": sorted(COMPLIANCE_CONTROLS),
            },
        ],
        "framework": compliance["framework"],
        "controls": controls,
        "risk_register": risks[:75],
        "risk_summary": risk_summary,
        "task_summary": _task_summary(tasks),
        "evidence_summary": _evidence_summary(evidence),
        "policy_register": _policy_register(controls),
        "priority_actions": [
            {
                "title": risk["title"],
                "linked_control": risk["linked_control"],
                "rating": risk["rating"],
                "owner": risk["owner"],
                "treatment": risk["treatment"],
            }
            for risk in risks[:6]
        ],
        "msme_compliance": {
            key: value
            for key, value in compliance.items()
            if key not in {"controls"}
        },
    }


def list_grc_risks(user_id: str) -> dict[str, Any]:
    dashboard = get_grc_dashboard(user_id)
    return {
        "status": "success",
        "risk_summary": dashboard["risk_summary"],
        "risks": dashboard["risk_register"],
    }


def export_grc_audit_pack(user_id: str) -> dict[str, Any]:
    grc_dashboard = get_grc_dashboard(user_id)
    readiness = export_readiness_payload(user_id)
    return {
        "status": "success",
        "export_type": "grc_audit_pack",
        "generated_at": datetime.utcnow().isoformat(),
        "readiness_export_id": readiness["export_id"],
        "grc": {
            "platform": grc_dashboard["platform"],
            "metrics": grc_dashboard["metrics"],
            "pillars": grc_dashboard["pillars"],
            "risk_summary": grc_dashboard["risk_summary"],
            "policy_register": grc_dashboard["policy_register"],
            "priority_actions": grc_dashboard["priority_actions"],
        },
        "compliance": readiness,
    }
