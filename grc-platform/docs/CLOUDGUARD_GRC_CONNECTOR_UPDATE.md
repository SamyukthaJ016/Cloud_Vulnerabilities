# CloudGuard GRC Connector Update

CloudGuard is kept as a standalone scanner and cloud security dashboard. The GRC platform now treats CloudGuard as an evidence connector.

## What Was Added

- New GRC page: `/cloudguard-grc`
- Sidebar entry under Compliance: `CloudGuard GRC`
- CloudGuard integration type on the Integrations page
- MCP evidence tool: `normalize_cloudguard_evidence`
- CERT-In MSME control-family mapping view
- Connector health view for CloudGuard, AWS, GCP, Kubernetes, IaC, MCP tools, and manual evidence
- Risk heatmap by evidence source and severity
- Evidence approval split: system generated, manual uploaded, pending review, approved
- What to fix first table with remediation and audit status

## Model

Scanner output stays outside GRC. GRC receives normalized evidence from CloudGuard or MCP tools, maps it to MSME control families, calculates risk priority, and tracks audit review status.

```text
CloudGuard / Local MCP Scanner / Manual Upload
        ↓
GRC Connector
        ↓
Evidence Normalization
        ↓
MSME Control Mapping
        ↓
Risk Prioritization
        ↓
Audit Review / Report
```

## Demo Line

CloudGuard can still be sold and used independently, but in the GRC platform it acts as a connector. GRC does not need to run every scanner directly. It consumes CloudGuard and MCP scanner outputs as evidence, maps them to CERT-In MSME controls, and shows what needs to be fixed first.
