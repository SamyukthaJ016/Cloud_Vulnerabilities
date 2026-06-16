---
marp: true
theme: cloudguard
paginate: true
title: Presentation Title
description: Reusable CloudGuard Marp presentation template.
---

<!-- _class: lead -->

# Presentation Title

## Short subtitle or purpose

One-line context for the audience.

---

# Executive Summary

- Key point one
- Key point two
- Key point three
- Decision or outcome needed

---

# Current Architecture

![Architecture diagram](images/grc-evidence-flow.png)

---

# Component Breakdown

| Component | Purpose |
|---|---|
| Dashboard | User-facing portal, reports, compliance views |
| API | Authentication, jobs, evidence ingestion, scanner endpoints |
| Workers | Long-running scans and scheduled jobs |
| Database | Jobs, findings, evidence metadata, users |
| Object storage | Raw evidence artifacts and reports |

---

# Workflow

```text
Input source
        |
        v
Connector / API
        |
        v
Queue / Worker
        |
        v
Evidence + Dashboard
```

---

# Technical Details

| Area | Details |
|---|---|
| Backend | FastAPI / Python |
| Database | PostgreSQL |
| Deployment | Docker Compose / Dokploy |
| Storage | S3-compatible object storage |
| Security | Tokens, credentials, evidence checksums |

---

# Risks And Mitigation

| Risk | Mitigation |
|---|---|
| Long-running scans affect UI | Keep scanner workers separate from portal |
| Evidence format mismatch | Use common connector schema |
| Deployment drift | Use Docker Compose and documented env files |
| Production monitoring gaps | Add uptime, logs, metrics, and alerts |

---

# Next Steps

1. Step one
2. Step two
3. Step three
4. Owner and timeline

---

<!-- _class: closing -->

# Recommendation

State the recommended action clearly.

Keep the final sentence crisp for the audience.
